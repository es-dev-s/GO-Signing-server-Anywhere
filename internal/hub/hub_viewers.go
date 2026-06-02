package hub

import (
	"context"
	"log"
	"time"
)

// viewerLinksCleanupLoop removes admin↔client viewer edges that point at dead sockets.
func (h *Hub) viewerLinksCleanupLoop(ctx context.Context) {
	t := time.NewTicker(12 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n := h.purgeOrphanViewerLinks()
			if n > 0 {
				log.Printf("[viewers] purged %d orphan viewer link(s)", n)
			}
		}
	}
}

func (h *Hub) purgeOrphanViewerLinks() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	removed := 0
	for adminSID, targets := range h.adminViewerLinks {
		for clientSID := range targets {
			if h.isLiveSocketLocked(clientSID) {
				continue
			}
			delete(targets, clientSID)
			removed++
			if cs := h.clientViewerLinks[clientSID]; cs != nil {
				delete(cs, adminSID)
				if len(cs) == 0 {
					delete(h.clientViewerLinks, clientSID)
				}
			}
		}
		if len(targets) == 0 {
			delete(h.adminViewerLinks, adminSID)
		}
	}
	return removed
}

func (h *Hub) isLiveSocketLocked(socketID string) bool {
	c, ok := h.conns[socketID]
	return ok && c != nil
}

// unlinkAdminFromStaleClientSockets drops viewer links for the same client on dead or superseded sockets.
func (h *Hub) unlinkAdminFromStaleClientSockets(adminSID string, clientID int64, liveClientSID string) {
	var notify []string
	h.mu.Lock()
	targets := h.adminViewerLinks[adminSID]
	if targets == nil {
		h.mu.Unlock()
		return
	}
	for oldSID := range targets {
		if oldSID == liveClientSID {
			continue
		}
		cc := h.conns[oldSID]
		if cc != nil && cc.client != nil && cc.client.ID == clientID {
			delete(targets, oldSID)
			if cs := h.clientViewerLinks[oldSID]; cs != nil {
				delete(cs, adminSID)
				if len(cs) == 0 {
					delete(h.clientViewerLinks, oldSID)
				}
			}
			notify = append(notify, oldSID)
			continue
		}
		if cc == nil {
			delete(targets, oldSID)
			if cs := h.clientViewerLinks[oldSID]; cs != nil {
				delete(cs, adminSID)
				if len(cs) == 0 {
					delete(h.clientViewerLinks, oldSID)
				}
			}
		}
	}
	if len(targets) == 0 {
		delete(h.adminViewerLinks, adminSID)
	}
	adminName := "Admin"
	if ac := h.conns[adminSID]; ac != nil && ac.admin != nil {
		adminName = ac.admin.FullName
	}
	h.mu.Unlock()

	for _, oldSID := range notify {
		h.mu.RLock()
		cc := h.conns[oldSID]
		h.mu.RUnlock()
		if cc != nil && cc.kind == KindClient {
			h.sendConn(cc, map[string]any{
				"type": "agent-disconnected", "agentSocketId": adminSID, "agentName": adminName,
			})
		}
	}
}

// unlinkAdminFromClient removes all viewer links between admin and any socket for clientID.
func (h *Hub) unlinkAdminFromClient(adminSID string, clientID int64, adminConn *Conn) int {
	var notify []string
	h.mu.Lock()
	targets := h.adminViewerLinks[adminSID]
	if targets == nil {
		h.mu.Unlock()
		return 0
	}
	for clientSID := range targets {
		cc := h.conns[clientSID]
		if cc != nil && cc.client != nil && cc.client.ID == clientID {
			delete(targets, clientSID)
			if cs := h.clientViewerLinks[clientSID]; cs != nil {
				delete(cs, adminSID)
				if len(cs) == 0 {
					delete(h.clientViewerLinks, clientSID)
				}
			}
			notify = append(notify, clientSID)
		}
	}
	if len(targets) == 0 {
		delete(h.adminViewerLinks, adminSID)
	}
	adminName := "Admin"
	if adminConn != nil && adminConn.admin != nil {
		adminName = adminConn.admin.FullName
	}
	h.mu.Unlock()

	for _, clientSID := range notify {
		h.mu.RLock()
		cc := h.conns[clientSID]
		h.mu.RUnlock()
		if cc != nil && cc.kind == KindClient {
			h.sendConn(cc, map[string]any{
				"type": "agent-disconnected", "agentSocketId": adminSID, "agentName": adminName,
			})
		}
	}
	return len(notify)
}
