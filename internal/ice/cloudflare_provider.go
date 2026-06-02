package ice

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/anywhere/signing-server-go/internal/config"
)

// ProviderLane identifies primary (1) or secondary (2) Cloudflare Realtime/TURN credentials.
type ProviderLane int

const (
	LanePrimary   ProviderLane = 1
	LaneSecondary ProviderLane = 2
)

// CloudflareLane holds one Cloudflare TURN key + Realtime SFU app.
type CloudflareLane struct {
	Lane            ProviderLane
	TurnKeyID       string
	TurnKeyToken    string
	RealtimeAppID   string
	RealtimeToken   string
}

func LoadCloudflareLanes(cfg config.Config) []CloudflareLane {
	var lanes []CloudflareLane
	if strings.TrimSpace(cfg.CloudflareTurnKeyID) != "" || strings.TrimSpace(cfg.CloudflareRealtimeAppID) != "" {
		lanes = append(lanes, CloudflareLane{
			Lane:          LanePrimary,
			TurnKeyID:     cfg.CloudflareTurnKeyID,
			TurnKeyToken:  cfg.CloudflareTurnKeyAPIToken,
			RealtimeAppID: cfg.CloudflareRealtimeAppID,
			RealtimeToken: cfg.CloudflareRealtimeAPIToken,
		})
	}
	if strings.TrimSpace(cfg.CloudflareTurnKeyID2) != "" || strings.TrimSpace(cfg.CloudflareRealtimeAppID2) != "" {
		lanes = append(lanes, CloudflareLane{
			Lane:          LaneSecondary,
			TurnKeyID:     cfg.CloudflareTurnKeyID2,
			TurnKeyToken:  cfg.CloudflareTurnKeyAPIToken2,
			RealtimeAppID: cfg.CloudflareRealtimeAppID2,
			RealtimeToken: cfg.CloudflareRealtimeAPIToken2,
		})
	}
	return lanes
}

type laneHealth struct {
	healthy      bool
	lastFail     time.Time
	lastOK       time.Time
	failStreak   int
	cooldown     time.Duration
}

// ProviderPool tracks Cloudflare lane health and preferred order (1↔2 failover).
type ProviderPool struct {
	lanes    []CloudflareLane
	health   map[ProviderLane]*laneHealth
	mu       sync.RWMutex
	prefer   ProviderLane
	cooldown time.Duration
}

func NewProviderPool(cfg config.Config) *ProviderPool {
	lanes := LoadCloudflareLanes(cfg)
	cool := time.Duration(cfg.MediaProviderCooldownMs) * time.Millisecond
	if cool < 15*time.Second {
		cool = 45 * time.Second
	}
	p := &ProviderPool{
		lanes:    lanes,
		health:   make(map[ProviderLane]*laneHealth),
		prefer:   LanePrimary,
		cooldown: cool,
	}
	for _, l := range lanes {
		p.health[l.Lane] = &laneHealth{healthy: true, cooldown: cool}
	}
	return p
}

func (p *ProviderPool) Lanes() []CloudflareLane {
	return append([]CloudflareLane(nil), p.lanes...)
}

func (p *ProviderPool) LaneOrder(preferred ProviderLane) []ProviderLane {
	p.mu.RLock()
	pref := p.prefer
	p.mu.RUnlock()
	var out []ProviderLane
	add := func(lane ProviderLane) {
		if !p.laneConfigured(lane) {
			return
		}
		for _, x := range out {
			if x == lane {
				return
			}
		}
		out = append(out, lane)
	}
	if preferred != 0 {
		add(preferred)
	}
	if pref != 0 {
		add(pref)
	}
	for _, l := range p.lanes {
		add(l.Lane)
	}
	return out
}

func (p *ProviderPool) laneConfigured(lane ProviderLane) bool {
	for _, l := range p.lanes {
		if l.Lane == lane {
			return true
		}
	}
	return false
}

func (p *ProviderPool) laneByID(lane ProviderLane) *CloudflareLane {
	for i := range p.lanes {
		if p.lanes[i].Lane == lane {
			return &p.lanes[i]
		}
	}
	return nil
}

func (p *ProviderPool) isUsable(lane ProviderLane) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	h := p.health[lane]
	if h == nil {
		return false
	}
	if h.healthy {
		return true
	}
	return time.Since(h.lastFail) >= h.cooldown
}

func (p *ProviderPool) MarkSuccess(lane ProviderLane) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[lane]
	if h == nil {
		return
	}
	h.healthy = true
	h.failStreak = 0
	h.lastOK = time.Now()
	p.prefer = lane
}

func (p *ProviderPool) MarkFailure(lane ProviderLane, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[lane]
	if h == nil {
		return
	}
	h.failStreak++
	h.lastFail = time.Now()
	if h.failStreak >= 2 {
		h.healthy = false
	}
	// Flip preferred to the other lane when available.
	for _, l := range p.lanes {
		if l.Lane != lane {
			p.prefer = l.Lane
			break
		}
	}
	if reason != "" {
		log.Printf("[media][lane-%d] degraded: %s", lane, reason)
	}
}

func (p *ProviderPool) PreferredLane() ProviderLane {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.prefer
}

func (p *ProviderPool) AnyRealtimeHealthy() bool {
	for _, l := range p.lanes {
		if strings.TrimSpace(l.RealtimeAppID) == "" || strings.TrimSpace(l.RealtimeToken) == "" {
			continue
		}
		if p.isUsable(l.Lane) {
			return true
		}
	}
	return false
}

func (p *ProviderPool) AvailableRealtimeLanes() []int {
	var out []int
	for _, l := range p.lanes {
		if strings.TrimSpace(l.RealtimeAppID) == "" || strings.TrimSpace(l.RealtimeToken) == "" {
			continue
		}
		if p.isUsable(l.Lane) {
			out = append(out, int(l.Lane))
		}
	}
	return out
}

func (p *ProviderPool) RealtimeClient(lane ProviderLane) *RealtimeClient {
	l := p.laneByID(lane)
	if l == nil {
		return nil
	}
	return NewRealtimeClient(l.RealtimeAppID, l.RealtimeToken)
}

// ProbeRealtime pings sessions/new on each configured lane (background health).
func (p *ProviderPool) ProbeRealtime(ctx context.Context) {
	for _, l := range p.lanes {
		if strings.TrimSpace(l.RealtimeAppID) == "" || strings.TrimSpace(l.RealtimeToken) == "" {
			continue
		}
		rt := NewRealtimeClient(l.RealtimeAppID, l.RealtimeToken)
		probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		_, err := rt.NewSession(probeCtx)
		cancel()
		if err != nil {
			p.MarkFailure(l.Lane, err.Error())
		} else {
			p.MarkSuccess(l.Lane)
		}
	}
}
