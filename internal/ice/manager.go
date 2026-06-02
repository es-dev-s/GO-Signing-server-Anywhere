package ice

import (
	"context"
	"sync"
	"time"

	"github.com/anywhere/signing-server-go/internal/config"
)

// Manager builds and caches ICE / transport plans (STUN → TURN → optional SFU).
type Manager struct {
	cfg  config.Config
	pool *ProviderPool

	mu       sync.RWMutex
	full     []ServerEntry
	stunOnly []ServerEntry
	cfAt     time.Time
}

func NewManager(cfg config.Config) *Manager {
	m := &Manager{cfg: cfg, pool: NewProviderPool(cfg)}
	m.refresh(context.Background())
	go m.loop()
	go m.probeLoop()
	return m
}

func (m *Manager) ProviderPool() *ProviderPool {
	return m.pool
}

func (m *Manager) loop() {
	t := time.NewTicker(45 * time.Minute)
	defer t.Stop()
	for range t.C {
		m.refresh(context.Background())
	}
}

func (m *Manager) probeLoop() {
	interval := time.Duration(m.cfg.MediaProviderProbeIntervalMs) * time.Millisecond
	if interval < 30*time.Second {
		interval = 90 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if m.pool != nil && m.cfg.EnableCloudflareSFU {
			m.pool.ProbeRealtime(context.Background())
		}
	}
}

func (m *Manager) refresh(ctx context.Context) {
	stun := baseStunServers()
	user, cred := MintTurnCredentials(m.cfg.TurnSecret, 86400)
	home := BuildHomeIceServers(m.cfg, user, cred)
	cf := FetchAllCloudflareIceServers(ctx, m.pool)
	full := mergeIceLists(stun, home, cf)
	stunOnly := mergeIceLists(stun, nil, nil)

	m.mu.Lock()
	m.full = full
	m.stunOnly = stunOnly
	m.cfAt = time.Now()
	m.mu.Unlock()
}

func (m *Manager) WelcomePlan() TransportPlan {
	m.mu.RLock()
	full := append([]ServerEntry(nil), m.full...)
	stun := append([]ServerEntry(nil), m.stunOnly...)
	m.mu.RUnlock()
	if len(full) == 0 {
		full = baseStunServers()
		stun = full
	}
	return TransportPlan{
		Version:        1,
		Mode:           ModeP2PPreferred,
		Reason:         "default_welcome",
		PhaseOneMs:     m.cfg.IcePhaseOneMs,
		IceServers:     full,
		IceServersStun: stun,
		IceServersFull: full,
	}
}

func (m *Manager) SessionPlan(ctx context.Context, in SessionInput) TransportPlan {
	m.mu.RLock()
	full := append([]ServerEntry(nil), m.full...)
	stun := append([]ServerEntry(nil), m.stunOnly...)
	m.mu.RUnlock()
	if len(full) == 0 {
		full = baseStunServers()
		stun = full
	}

	mode, reason := m.chooseMode(in)
	plan := TransportPlan{
		Version:          1,
		Mode:             mode,
		Reason:           reason,
		PhaseOneMs:       m.cfg.IcePhaseOneMs,
		IceServers:       pickIceList(mode, stun, full),
		IceServersStun:   stun,
		IceServersFull:   full,
		ViewerCount:      in.ClientViewerCount,
		AdminTargetCount: in.AdminViewerTargetCount,
	}

	if mode == ModeSFU {
		if m.pool == nil || !m.pool.AnyRealtimeHealthy() {
			plan.Mode = ModeTurnRelay
			plan.Reason = "sfu_lanes_down_turn_fallback"
			plan.IceServers = full
		} else {
			lanes := m.pool.AvailableRealtimeLanes()
			plan.SFU = &SFUHint{
				Enabled:       true,
				StunURL:       "stun:stun.cloudflare.com:3478",
				ProviderLane:  int(m.pool.PreferredLane()),
				ProviderLanes: lanes,
				FallbackModes: []string{string(ModeTurnRelay), string(ModeP2PPreferred)},
			}
		}
	}
	return plan
}

func (m *Manager) chooseMode(in SessionInput) (StreamMode, string) {
	if in.ForceTurn || in.HasStreamRelayGrant {
		return ModeTurnRelay, "relay_grant_or_forced"
	}
	vc := in.ClientViewerCount
	at := in.AdminViewerTargetCount
	sfuConfigured := m.cfg.EnableCloudflareSFU && m.pool != nil && len(m.pool.Lanes()) > 0
	if sfuConfigured {
		if vc >= m.cfg.StreamSFUViewerThreshold || at >= m.cfg.StreamSFUAdminTargetsThreshold {
			return ModeSFU, "multi_viewer_sfu"
		}
	}
	if vc >= m.cfg.StreamTurnViewerThreshold || at >= m.cfg.StreamTurnAdminTargetsThreshold {
		return ModeTurnRelay, "multi_viewer_turn"
	}
	return ModeP2PPreferred, "single_viewer_p2p_first"
}

func pickIceList(mode StreamMode, stun, full []ServerEntry) []ServerEntry {
	if mode == ModeP2PPreferred {
		return stun
	}
	return full
}

func baseStunServers() []ServerEntry {
	return []ServerEntry{
		{URLs: "stun:stun.l.google.com:19302"},
		{URLs: "stun:stun.cloudflare.com:3478"},
	}
}

func mergeIceLists(parts ...[]ServerEntry) []ServerEntry {
	var out []ServerEntry
	seen := map[string]struct{}{}
	for _, p := range parts {
		for _, e := range p {
			key := serverKey(e)
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, e)
		}
	}
	return out
}

func serverKey(e ServerEntry) string {
	switch u := e.URLs.(type) {
	case string:
		return u + "|" + e.Username
	case []any:
		var s string
		for _, x := range u {
			s += stringOf(x) + ","
		}
		return s + "|" + e.Username
	case []string:
		var s string
		for _, x := range u {
			s += x + ","
		}
		return s + "|" + e.Username
	default:
		return ""
	}
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ToMap serializes the plan for WebSocket JSON (streamTransport field).
func (p TransportPlan) ToMap() map[string]any {
	m := map[string]any{
		"version":          p.Version,
		"mode":             string(p.Mode),
		"reason":           p.Reason,
		"phaseOneMs":       p.PhaseOneMs,
		"iceServers":       p.IceServers,
		"iceServersStunOnly": p.IceServersStun,
		"iceServersFull":   p.IceServersFull,
	}
	if p.ViewerCount > 0 {
		m["viewerCount"] = p.ViewerCount
	}
	if p.AdminTargetCount > 0 {
		m["adminTargetCount"] = p.AdminTargetCount
	}
	if p.SFU != nil {
		m["sfu"] = p.SFU
	}
	return m
}
