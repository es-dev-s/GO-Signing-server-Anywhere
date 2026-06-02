package hub

import (
	"context"
	"fmt"

	"github.com/anywhere/signing-server-go/internal/ice"
)

func (h *Hub) mediaPool() *ice.ProviderPool {
	if h.ice == nil {
		return nil
	}
	return h.ice.ProviderPool()
}

func parseProviderLane(msg map[string]any) ice.ProviderLane {
	if n, ok := toInt64(msg["providerLane"]); ok && (n == 1 || n == 2) {
		return ice.ProviderLane(n)
	}
	return 0
}

func (h *Hub) handleSfuAPI(ctx context.Context, conn *Conn, msg map[string]any) {
	reqID := asNonEmptyString(msg["requestId"], 128)
	if reqID == "" {
		h.sendConn(conn, map[string]any{"type": "sfu-api-response", "success": false, "error": "MISSING_REQUEST_ID"})
		return
	}
	if !h.cfg.EnableCloudflareSFU {
		h.sendConn(conn, map[string]any{"type": "sfu-api-response", "success": false, "requestId": reqID, "error": "SFU_DISABLED"})
		return
	}
	pool := h.mediaPool()
	if pool == nil {
		h.sendConn(conn, map[string]any{"type": "sfu-api-response", "success": false, "requestId": reqID, "error": "SFU_NOT_CONFIGURED"})
		return
	}
	preferred := parseProviderLane(msg)
	op := asNonEmptyString(msg["op"], 64)
	resp := map[string]any{"type": "sfu-api-response", "requestId": reqID, "op": op}

	switch op {
	case "sessions-new":
		sid, lane, err := pool.NewSessionFailover(ctx, preferred)
		if err != nil {
			resp["success"] = false
			resp["error"] = err.Error()
			resp["fallbackModes"] = []string{"turn-relay", "p2p-preferred"}
		} else {
			resp["success"] = true
			resp["sessionId"] = sid
			resp["providerLane"] = int(lane)
		}
	case "tracks-new":
		sid := asNonEmptyString(msg["sessionId"], 128)
		body, _ := msg["body"].(map[string]any)
		if sid == "" || body == nil {
			resp["success"] = false
			resp["error"] = "INVALID_TRACKS_NEW"
			break
		}
		out, lane, err := pool.RunRealtime(ctx, preferred, func(ctx context.Context, rt *ice.RealtimeClient) (map[string]any, error) {
			return rt.TracksNew(ctx, sid, body)
		})
		if err != nil {
			resp["success"] = false
			resp["error"] = err.Error()
			if out != nil {
				resp["data"] = out
			}
			resp["fallbackModes"] = []string{"turn-relay", "p2p-preferred"}
		} else {
			resp["success"] = true
			resp["data"] = out
			resp["providerLane"] = int(lane)
		}
	case "renegotiate":
		sid := asNonEmptyString(msg["sessionId"], 128)
		body, _ := msg["body"].(map[string]any)
		if sid == "" || body == nil {
			resp["success"] = false
			resp["error"] = "INVALID_RENEGOTIATE"
			break
		}
		out, lane, err := pool.RunRealtime(ctx, preferred, func(ctx context.Context, rt *ice.RealtimeClient) (map[string]any, error) {
			return rt.Renegotiate(ctx, sid, body)
		})
		if err != nil {
			resp["success"] = false
			resp["error"] = err.Error()
			if out != nil {
				resp["data"] = out
			}
		} else {
			resp["success"] = true
			resp["data"] = out
			resp["providerLane"] = int(lane)
		}
	case "tracks-close":
		sid := asNonEmptyString(msg["sessionId"], 128)
		body, _ := msg["body"].(map[string]any)
		if sid == "" || body == nil {
			resp["success"] = false
			resp["error"] = "INVALID_TRACKS_CLOSE"
			break
		}
		out, lane, err := pool.RunRealtime(ctx, preferred, func(ctx context.Context, rt *ice.RealtimeClient) (map[string]any, error) {
			return rt.TracksClose(ctx, sid, body)
		})
		if err != nil {
			resp["success"] = false
			resp["error"] = err.Error()
			if out != nil {
				resp["data"] = out
			}
		} else {
			resp["success"] = true
			resp["data"] = out
			resp["providerLane"] = int(lane)
		}
	case "publisher-info":
		cid, ok := toInt64(msg["clientId"])
		if !ok || cid <= 0 {
			if conn.client != nil {
				cid = conn.client.ID
			}
		}
		pub := h.sfu.getPublisher(cid)
		if pub == nil {
			resp["success"] = false
			resp["error"] = "NO_PUBLISHER"
		} else {
			resp["success"] = true
			resp["clientId"] = cid
			resp["publisherSessionId"] = pub.SessionID
			resp["trackName"] = pub.TrackName
			resp["providerLane"] = pub.ProviderLane
		}
	default:
		resp["success"] = false
		resp["error"] = fmt.Sprintf("UNKNOWN_SFU_OP:%s", op)
	}
	h.sendConn(conn, resp)
}

func (h *Hub) handleSfuRegisterPublisher(_ string, conn *Conn, msg map[string]any) {
	if conn.kind != KindClient || conn.client == nil {
		h.sendConn(conn, map[string]any{"type": "sfu-register-publisher-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	sessionID := asNonEmptyString(msg["sessionId"], 128)
	trackName := asNonEmptyString(msg["trackName"], 128)
	if trackName == "" {
		trackName = ice.ClientTrackName(conn.client.ID)
	}
	if sessionID == "" {
		h.sendConn(conn, map[string]any{"type": "sfu-register-publisher-response", "success": false, "error": "MISSING_SESSION"})
		return
	}
	lane := 1
	if n, ok := toInt64(msg["providerLane"]); ok && (n == 1 || n == 2) {
		lane = int(n)
	}
	h.sfu.setPublisher(conn.client.ID, sessionID, trackName, lane)
	h.sendConn(conn, map[string]any{
		"type": "sfu-register-publisher-response", "success": true,
		"clientId": conn.client.ID, "sessionId": sessionID, "trackName": trackName, "providerLane": lane,
	})
	h.broadcastSfuPublisherReady(conn.client.ID, sessionID, trackName, lane)
}

func (h *Hub) handleMediaProviderFailed(conn *Conn, msg map[string]any) {
	lane := parseProviderLane(msg)
	if lane == 0 {
		return
	}
	if pool := h.mediaPool(); pool != nil {
		reason := asNonEmptyString(msg["reason"], 200)
		if reason == "" {
			reason = "client_reported_failure"
		}
		pool.MarkFailure(lane, reason)
	}
	// Nudge connected peers to refresh transport (TURN mesh / alternate SFU lane) without alarming UI.
	if conn.kind == KindClient && conn.client != nil {
		h.pushTransportRefreshForClient(conn.client.ID, "media_provider_failed")
	}
}

func (h *Hub) pushTransportRefreshForClient(clientID int64, reason string) {
	ctx := context.Background()
	h.mu.RLock()
	defer h.mu.RUnlock()
	for clientSID, admins := range h.clientViewerLinks {
		c := h.conns[clientSID]
		if c == nil || c.client == nil || c.client.ID != clientID {
			continue
		}
		for adminSID := range admins {
			ac := h.conns[adminSID]
			if ac == nil {
				continue
			}
			plan := h.ice.SessionPlan(ctx, ice.SessionInput{
				ClientViewerCount: h.countClientViewersByClientID(clientID),
			})
			h.sendConn(ac, map[string]any{
				"type": "stream-transport-hint", "clientId": clientID, "reason": reason,
				"streamTransport": plan.ToMap(),
			})
			clientPlan := h.enrichTransportPlan(plan, clientID, "publisher")
			h.sendConn(c, map[string]any{
				"type": "stream-transport-hint", "clientId": clientID, "reason": reason,
				"streamTransport": clientPlan.ToMap(),
			})
		}
	}
}

func (h *Hub) broadcastSfuPublisherReady(clientID int64, sessionID, trackName string, providerLane int) {
	payload := map[string]any{
		"type":               "sfu-publisher-ready",
		"clientId":           clientID,
		"publisherSessionId": sessionID,
		"trackName":          trackName,
		"providerLane":       providerLane,
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for clientSID, admins := range h.clientViewerLinks {
		c := h.conns[clientSID]
		if c == nil || c.client == nil || c.client.ID != clientID {
			continue
		}
		for adminSID := range admins {
			if ac := h.conns[adminSID]; ac != nil {
				h.sendConn(ac, payload)
			}
		}
	}
}

func (h *Hub) enrichTransportPlan(plan ice.TransportPlan, clientID int64, role string) ice.TransportPlan {
	if plan.Mode != ice.ModeSFU || plan.SFU == nil || !plan.SFU.Enabled {
		return plan
	}
	hint := *plan.SFU
	hint.Role = role
	hint.TrackName = ice.ClientTrackName(clientID)
	hint.PublisherClientID = clientID
	if pool := h.mediaPool(); pool != nil {
		hint.ProviderLane = int(pool.PreferredLane())
		hint.ProviderLanes = pool.AvailableRealtimeLanes()
	}
	if role == "subscriber" {
		if pub := h.sfu.getPublisher(clientID); pub != nil {
			hint.PublisherSessionID = pub.SessionID
			if pub.ProviderLane > 0 {
				hint.ProviderLane = pub.ProviderLane
			}
		}
	}
	plan.SFU = &hint
	return plan
}
