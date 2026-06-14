package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/anywhere/signing-server-go/internal/auditproxy"
	"github.com/anywhere/signing-server-go/internal/config"
	"github.com/anywhere/signing-server-go/internal/db"
	"github.com/anywhere/signing-server-go/internal/ice"
	"github.com/anywhere/signing-server-go/internal/iputil"
	"github.com/anywhere/signing-server-go/internal/ratelimit"
	"github.com/gorilla/websocket"
)

type ConnKind string

const (
	KindUnknown    ConnKind = ""
	KindClient     ConnKind = "client"
	KindAdmin      ConnKind = "admin"
	KindLegacyAgent ConnKind = "legacy_agent"
)

type ClientIdentity struct {
	ID       int64  `json:"id"`
	OrgID    int64  `json:"orgId"`
	FullName string `json:"fullName"`
	DeviceID string `json:"deviceId,omitempty"`
}

type AdminIdentity struct {
	AdminID  int64  `json:"adminId"`
	OrgID    int64  `json:"orgId"`
	Username string `json:"username"`
	FullName string `json:"fullName"`
	Role     string `json:"role"`
	Token    string `json:"-"`
}

type ScreenSource struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Index *int   `json:"index"`
}

const wsSendQueueSize = 512

type Conn struct {
	ws                    *websocket.Conn
	writeMu               sync.Mutex
	sendCh                chan []byte
	sendDone              chan struct{}
	kind                  ConnKind
	client                *ClientIdentity
	admin                 *AdminIdentity
	bucket                *ratelimit.TokenBucket
	ip                    string
	ipStatusSent          bool
	workstationIPs        []string
	pendingDeviceID       string
	screenSources         []ScreenSource
	screenSourcesSig      string
	appVersion            string
	signalSeq             int64
	isAlive               bool
}

type Hub struct {
	cfg    config.Config
	db     *db.Store
	ice    *ice.Manager
	audit  auditproxy.Env
	upgrader websocket.Upgrader

	mu                    sync.RWMutex
	conns                 map[string]*Conn
	ipCount               map[string]int
	lastDeviceTakeover    map[string]int64
	adminViewerLinks      map[string]map[string]struct{}
	clientViewerLinks     map[string]map[string]struct{}
	sfu                   *sfuRegistry
}

func New(cfg config.Config, store *db.Store) *Hub {
	iceMgr := ice.NewManager(cfg)
	return &Hub{
		cfg:   cfg,
		db:    store,
		ice:   iceMgr,
		audit: auditproxy.FromConfig(cfg),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		conns:             make(map[string]*Conn),
		ipCount:           make(map[string]int),
		lastDeviceTakeover: make(map[string]int64),
		adminViewerLinks:  make(map[string]map[string]struct{}),
		clientViewerLinks: make(map[string]map[string]struct{}),
		sfu:               newSfuRegistry(),
	}
}

func (h *Hub) Run(ctx context.Context) error {
	if h.cfg.WipeDBOnStart {
		if err := h.db.ResetAllOnStartup(ctx); err != nil {
			return fmt.Errorf("resetAllOnStartup: %w", err)
		}
		log.Printf("[startup] SIGNALING_WIPE_DB=1 — all clients marked offline, sessions ended")
	} else {
		if err := h.db.SoftReconcileOnStartup(ctx); err != nil {
			return fmt.Errorf("softReconcileOnStartup: %w", err)
		}
		log.Printf("[startup] soft reconcile — ended active sessions, cleared stale socket_id (roster preserved)")
	}
	if h.cfg.SeedSuperAdmin && h.cfg.BootstrapPassword != "" {
		if err := h.db.SeedDefaultSuperAdmin(ctx, h.cfg.BootstrapOrg, h.cfg.BootstrapUsername, h.cfg.BootstrapFullName, h.cfg.BootstrapPassword); err != nil {
			log.Printf("[seed] warning: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.serveHTTP)
	mux.HandleFunc("/health", h.serveHTTP)

	addr := fmt.Sprintf("%s:%d", h.cfg.Host, h.cfg.Port)
	srv := &http.Server{Addr: addr, Handler: mux}

	go h.pingLoop(ctx)
	go h.heartbeatLoop(ctx)
	go h.viewerLinksCleanupLoop(ctx)
	go h.sessionCleanupLoop(ctx)
	go h.relayExpiryLoop(ctx)

	welcome := h.ice.WelcomePlan()
	ice.LogIceConfig(h.cfg, welcome)
	log.Printf("✅ Go signaling server on %s (stream: p2p→turn→sfu, no browser-tab telemetry)", addr)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		_ = srv.Shutdown(context.Background())
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (h *Hub) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		h.serveWS(w, r)
		return
	}
	if !h.originAllowed(r.Header.Get("Origin")) {
		writeJSON(w, 403, map[string]any{"error": "FORBIDDEN_ORIGIN", "message": "Origin not allowed"})
		return
	}
	path := r.URL.Path
	if path == "/" || path == "/health" {
		if r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]any{"ok": true, "service": "anywhere-signaling-go"})
			return
		}
	}
	switch {
	case path == "/api/call-events":
		h.httpCallEvents(w, r)
		return
	case path == "/api/taskbar-events":
		h.httpTaskbarEvents(w, r)
		return
	default:
	}
	writeJSON(w, 404, map[string]any{"error": "NOT_FOUND"})
}

func (h *Hub) serveWS(w http.ResponseWriter, r *http.Request) {
	if !h.wsTokenOK(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.originAllowed(r.Header.Get("Origin")) {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}
	if h.cfg.EnforceTLS && !isLocalHost(r.Host) {
		proto := strings.ToLower(r.Header.Get("X-Forwarded-Proto"))
		if proto != "https" && proto != "wss" {
			http.Error(w, "TLS required", http.StatusBadRequest)
			return
		}
	}

	h.mu.Lock()
	if len(h.conns) >= h.cfg.MaxConnections {
		h.mu.Unlock()
		http.Error(w, "Server at capacity", http.StatusServiceUnavailable)
		return
	}
	ip := clientIP(r)
	if h.ipCount[ip] >= h.cfg.MaxPerIP {
		h.mu.Unlock()
		http.Error(w, "Too many connections from this IP", http.StatusServiceUnavailable)
		return
	}
	h.ipCount[ip]++
	h.mu.Unlock()

	ws, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.mu.Lock()
		h.ipCount[ip]--
		h.mu.Unlock()
		return
	}

	socketID := genSocketID()
	conn := &Conn{
		ws:      ws,
		sendCh:  make(chan []byte, wsSendQueueSize),
		sendDone: make(chan struct{}),
		bucket:  ratelimit.New(h.cfg.RateCapacity, h.cfg.RateRefillPerSec),
		ip:      ip,
		isAlive: true,
	}

	h.mu.Lock()
	h.conns[socketID] = conn
	h.mu.Unlock()

	go conn.writePump()

	log.Printf("🔌 New connection: %s (%s)", socketID, ip)

	ws.SetPongHandler(func(string) error {
		conn.isAlive = true
		if conn.kind == KindClient {
			_ = h.db.UpdateClientHeartbeat(context.Background(), socketID)
		}
		return nil
	})

	go h.sendWelcome(socketID, conn)
	go h.readLoop(socketID, conn)
}

func (h *Hub) readLoop(socketID string, conn *Conn) {
	defer h.disconnect(socketID)
	for {
		_, raw, err := conn.ws.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("🔌 read ended %s (%s): %v", socketID, conn.ip, err)
			}
			return
		}
		conn.isAlive = true
		if len(raw) > maxMessageBytes {
			h.sendConn(conn, map[string]any{"type": "error", "error": "MESSAGE_TOO_LARGE"})
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal(raw, &msg); err != nil {
			h.sendConn(conn, map[string]any{"type": "error", "error": "INVALID_MESSAGE"})
			continue
		}
		h.handleMessage(socketID, conn, msg)
	}
}

func (h *Hub) pingLoop(ctx context.Context) {
	t := time.NewTicker(time.Duration(h.cfg.WsPingIntervalMs) * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.mu.RLock()
			var connsToPing []*Conn
			var connsToClose []*Conn
			for _, c := range h.conns {
				if !c.isAlive {
					connsToClose = append(connsToClose, c)
					continue
				}
				connsToPing = append(connsToPing, c)
			}
			h.mu.RUnlock()

			for _, c := range connsToClose {
				log.Printf("💀 ping timeout %s", c.ip)
				_ = c.ws.Close()
			}

			for _, c := range connsToPing {
				c.isAlive = false
				if err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					log.Printf("💀 ping write failed: %v", err)
					_ = c.ws.Close()
				}
			}
		}
	}
}

func (h *Hub) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(time.Duration(h.cfg.HeartbeatCheckMs) * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			stale, err := h.db.CleanupStaleClients(ctx, h.cfg.ClientHeartbeatTimeoutMs)
			if err != nil {
				log.Printf("[heartbeat] %v", err)
				continue
			}
			for _, c := range stale {
				var toClose *websocket.Conn
				h.mu.Lock()
				if c.SocketID != nil {
					if conn, ok := h.conns[*c.SocketID]; ok {
						toClose = conn.ws
						delete(h.conns, *c.SocketID)
					}
				}
				h.mu.Unlock()
				if toClose != nil {
					_ = toClose.Close()
				}
				_ = h.broadcastClientsListToAdmins(ctx, c.OrgID)
			}
		}
	}
}

func (h *Hub) sessionCleanupLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = h.db.PurgeExpiredSessions(ctx)
		}
	}
}

func (h *Hub) relayExpiryLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = h.db.ExpireRemoteAccessRequests(ctx)
			_ = h.db.ExpireStreamRelayRequests(ctx)
		}
	}
}

func (c *Conn) writePump() {
	defer close(c.sendDone)
	for payload := range c.sendCh {
		c.writeMu.Lock()
		err := c.ws.WriteMessage(websocket.TextMessage, payload)
		c.writeMu.Unlock()
		if err != nil {
			return
		}
	}
}

func (h *Hub) sendConn(c *Conn, data map[string]any) {
	if c == nil || c.sendCh == nil {
		return
	}
	select {
	case <-c.sendDone:
		return
	default:
	}
	payload := mustJSON(data)
	select {
	case c.sendCh <- payload:
	default:
		// Queue full (burst ICE) — block briefly rather than drop signaling.
		select {
		case c.sendCh <- payload:
		case <-time.After(3 * time.Second):
			log.Printf("[ws] outbound queue saturated (dropped one message)")
		}
	}
}

func (c *Conn) closeSendLoop() {
	if c.sendCh == nil {
		return
	}
	select {
	case <-c.sendDone:
	default:
		close(c.sendCh)
		<-c.sendDone
	}
}

func (h *Hub) getConn(socketID string) *Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.conns[socketID]
}

func (h *Hub) linkViewer(adminSID, clientSID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.adminViewerLinks[adminSID] == nil {
		h.adminViewerLinks[adminSID] = make(map[string]struct{})
	}
	h.adminViewerLinks[adminSID][clientSID] = struct{}{}
	if h.clientViewerLinks[clientSID] == nil {
		h.clientViewerLinks[clientSID] = make(map[string]struct{})
	}
	h.clientViewerLinks[clientSID][adminSID] = struct{}{}
}

func (h *Hub) unlinkViewer(adminSID, clientSID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.adminViewerLinks[adminSID]; s != nil {
		delete(s, clientSID)
		if len(s) == 0 {
			delete(h.adminViewerLinks, adminSID)
		}
	}
	if s := h.clientViewerLinks[clientSID]; s != nil {
		delete(s, adminSID)
		if len(s) == 0 {
			delete(h.clientViewerLinks, clientSID)
		}
	}
}

func (h *Hub) countAdminTargets(adminSID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.adminViewerLinks[adminSID])
}

func (h *Hub) countClientViewers(clientSID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clientViewerLinks[clientSID])
}

func (h *Hub) adminAlreadyViewing(adminSID, clientSID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.adminViewerLinks[adminSID][clientSID]
	return ok
}

func (h *Hub) sensitiveAccessAllowed() (bool, string) {
	return true, ""
}

func (h *Hub) maybeSendAdminIPStatus(socketID string, admin *db.AdminRow, conn *Conn) {
	if conn.ipStatusSent {
		return
	}
	conn.ipStatusSent = true
	grant, _ := h.db.GetActiveRemoteAccess(context.Background(), admin.AdminID)
	var grantObj any
	if grant != nil {
		grantObj = map[string]any{
			"expiresAt":       grant["expires_at"],
			"durationHours":   grant["duration_hours"],
			"grantId":         grant["id"],
		}
	}
	h.sendConn(conn, map[string]any{
		"type":       "admin-ip-status",
		"isOffice":   iputil.IsOnOfficeNetwork(conn.ip, conn.workstationIPs),
		"officeName": iputil.OfficeNetworkLabel(conn.ip, conn.workstationIPs),
		"adminIp":    conn.ip,
		"role":       admin.Role,
		"activeRemoteGrant": grantObj,
	})
}

func legacyPseudoDevice(name, socketID string) string {
	sum := sha256.Sum256([]byte(name + ":" + socketID))
	return "legacy-" + hex.EncodeToString(sum[:16])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(mustJSON(v))
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isLocalHost(host string) bool {
	h := strings.Split(host, ":")[0]
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (h *Hub) originAllowed(origin string) bool {
	if len(h.cfg.AllowedOrigins) == 0 {
		return true
	}
	if origin == "" {
		return true
	}
	_, ok := h.cfg.AllowedOrigins[origin]
	return ok
}

func (h *Hub) wsTokenOK(r *http.Request) bool {
	expected := strings.TrimSpace(h.cfg.WsConnectToken)
	if expected == "" {
		return true
	}
	provided := r.URL.Query().Get("token")
	if provided == "" {
		provided = r.Header.Get("X-Ws-Token")
	}
	return strings.TrimSpace(provided) == expected
}
