package hub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/anywhere/signing-server-go/internal/auth"
)

func (h *Hub) httpCallEvents(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	switch r.Method {
	case http.MethodPost:
		h.postCallEvents(ctx, w, r)
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"success": true, "events": []any{}, "page": 1, "limit": 0, "hasMore": false})
	default:
		writeJSON(w, 405, map[string]any{"error": "METHOD_NOT_ALLOWED"})
	}
}

func (h *Hub) httpTaskbarEvents(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.EnableTaskbarTelemetry {
		writeJSON(w, 200, map[string]any{"success": true, "events": []any{}, "disabled": true})
		return
	}
	switch r.Method {
	case http.MethodPost:
		body, err := readBody(r, maxHTTPBodyBytes)
		if err != nil {
			writeJSON(w, 413, map[string]any{"error": "PAYLOAD_TOO_LARGE"})
			return
		}
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		// Broadcast-only fast path (no DB); mirrors Node when taskbar ingest is enabled.
		h.broadcastTaskbarToAdmins(payload)
		writeJSON(w, 200, map[string]any{"ok": true, "accepted": 1, "persisted": false})
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"success": true, "events": []any{}, "page": 1, "limit": 0, "hasMore": false})
	default:
		writeJSON(w, 405, map[string]any{"error": "METHOD_NOT_ALLOWED"})
	}
}

func (h *Hub) postCallEvents(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	authHdr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	authHdr = strings.TrimSpace(authHdr)
	body, err := readBody(r, maxHTTPBodyBytes)
	if err != nil {
		writeJSON(w, 413, map[string]any{"error": "PAYLOAD_TOO_LARGE"})
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, 400, map[string]any{"error": "INVALID_JSON"})
		return
	}
	var clientID int64
	if ingest, err := auth.VerifyIngestToken(h.cfg.IngestTokenSecret, authHdr); err == nil {
		row, _ := h.db.GetClientByID(ctx, ingest.ClientID)
		if row == nil || row.Disabled == 1 || row.OrgID != ingest.OrgID {
			writeJSON(w, 403, map[string]any{"error": "FORBIDDEN"})
			return
		}
		clientID = ingest.ClientID
	} else if h.cfg.AllowCallNoToken {
		dev := asNonEmptyString(payload["deviceId"], 200)
		if dev == "" {
			writeJSON(w, 401, map[string]any{"error": "UNAUTHORIZED"})
			return
		}
		cid, _ := h.db.GetClientIDByDeviceID(ctx, dev)
		if cid == 0 {
			writeJSON(w, 403, map[string]any{"error": "FORBIDDEN"})
			return
		}
		clientID = cid
	} else {
		writeJSON(w, 401, map[string]any{"error": "UNAUTHORIZED"})
		return
	}
	events, _ := payload["events"].([]any)
	if len(events) == 0 {
		writeJSON(w, 400, map[string]any{"error": "INVALID_INPUT"})
		return
	}
	for _, e := range events {
		ev, _ := e.(map[string]any)
		typ := asNonEmptyString(ev["type"], 32)
		platform := asNonEmptyString(ev["platform"], 120)
		ts := asNonEmptyString(ev["timestamp"], 80)
		if typ == "" || platform == "" || ts == "" {
			writeJSON(w, 400, map[string]any{"error": "VALIDATION_ERROR"})
			return
		}
		var dur *int64
		if ev["duration_ms"] != nil {
			if d, ok := toInt64(ev["duration_ms"]); ok {
				dur = &d
			}
		}
		_ = h.db.InsertCallEvent(ctx, clientID, typ, platform, ts, dur)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "accepted": len(events)})
}

func (h *Hub) broadcastTaskbarToAdmins(payload map[string]any) {
	clientID, _ := toInt64(payload["clientId"])
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, conn := range h.conns {
		if conn.kind != KindAdmin || conn.admin == nil {
			continue
		}
		if conn.admin.Role == "org_admin" {
			// org scoping would need client org lookup; skip if unknown
			_ = clientID
		}
		h.sendConn(conn, map[string]any{
			"type": "taskbar-events-update",
			"clientId": clientID,
			"payload":  payload,
		})
	}
}

func readBody(r *http.Request, limit int64) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(io.LimitReader(r.Body, limit))
}

func init() {
	_ = time.Now
}
