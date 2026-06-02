package hub

import (
	"context"

	"github.com/anywhere/signing-server-go/internal/ice"
)

func (h *Hub) sendWelcome(socketID string, conn *Conn) {
	plan := h.ice.WelcomePlan()
	h.sendConn(conn, map[string]any{
		"type":            "welcome",
		"socketId":        socketID,
		"iceServers":      plan.IceServersFull,
		"streamTransport": plan.ToMap(),
	})
}

func (h *Hub) sessionTransportPlan(ctx context.Context, adminSID string, clientID int64, alreadyViewing, hasRelay bool) ice.TransportPlan {
	vc := h.countClientViewersByClientID(clientID)
	at := h.countAdminTargets(adminSID)
	if !alreadyViewing {
		vc++
		at++
	}
	return h.ice.SessionPlan(ctx, ice.SessionInput{
		ClientViewerCount:      vc,
		AdminViewerTargetCount: at,
		HasStreamRelayGrant:    hasRelay,
	})
}

func (h *Hub) countClientViewersByClientID(clientID int64) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for clientSID, admins := range h.clientViewerLinks {
		c := h.conns[clientSID]
		if c == nil || c.client == nil || c.client.ID != clientID {
			continue
		}
		n += len(admins)
	}
	return n
}

func streamTransportFields(plan ice.TransportPlan) map[string]any {
	return map[string]any{"streamTransport": plan.ToMap()}
}
