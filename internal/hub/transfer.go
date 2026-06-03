package hub

import (
	"context"
	"time"
)

// applyClientOrgTransfer moves a client to toOrgID immediately (DB + live socket identity) and notifies admins.
func (h *Hub) applyClientOrgTransfer(ctx context.Context, clientID, fromOrgID, toOrgID int64, approvedByAdminID int64) error {
	if err := h.db.SetClientOrgNow(ctx, clientID, toOrgID); err != nil {
		return err
	}
	_ = h.db.ReconcileClientOrgsFromApprovedTransfers(ctx)
	if approvedByAdminID > 0 {
		_ = h.db.ResolvePendingTransfersForClient(ctx, clientID, approvedByAdminID)
	}
	h.setClientOrgInMemory(clientID, toOrgID)
	if fromOrgID > 0 && fromOrgID != toOrgID {
		_ = h.broadcastClientsListToAdmins(ctx, fromOrgID)
	}
	_ = h.broadcastClientsListToAdmins(ctx, toOrgID)
	return nil
}

func (h *Hub) setClientOrgInMemory(clientID, toOrgID int64) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, conn := range h.conns {
		if conn.client != nil && conn.client.ID == clientID {
			conn.client.OrgID = toOrgID
		}
	}
}

func (h *Hub) broadcastTransferEvent(event map[string]any) {
	fromOrgID, _ := toInt64(event["fromOrgId"])
	toOrgID, _ := toInt64(event["toOrgId"])
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, conn := range h.conns {
		if conn.kind != KindAdmin || conn.admin == nil {
			continue
		}
		role := conn.admin.Role
		orgID := conn.admin.OrgID
		interested := role == "super_admin" || role == "it_ops" ||
			(orgID == fromOrgID || orgID == toOrgID)
		if !interested {
			continue
		}
		h.sendConn(conn, map[string]any{"type": "transfer-event", "success": true, "event": event})
	}
}

func (h *Hub) transferEventPayload(ctx context.Context, kind string, requestID, clientID int64, clientName string, fromOrgID, toOrgID int64, status string, byAdminID int64, byAdminName string) map[string]any {
	fromName, _ := h.db.GetOrganizationNameByID(ctx, fromOrgID)
	toName, _ := h.db.GetOrganizationNameByID(ctx, toOrgID)
	if fromName == "" {
		fromName = "Org " + itoa(fromOrgID)
	}
	if toName == "" {
		toName = "Org " + itoa(toOrgID)
	}
	ev := map[string]any{
		"kind": kind, "requestId": requestID, "clientId": clientID, "clientName": clientName,
		"fromOrgId": fromOrgID, "fromOrgName": fromName, "toOrgId": toOrgID, "toOrgName": toName,
		"status": status, "at": time.Now().UnixMilli(),
	}
	if byAdminID > 0 {
		ev["byAdminId"] = byAdminID
		ev["byAdminName"] = byAdminName
	}
	return ev
}

func (h *Hub) handleAdminCreateTransferRequest(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	if admin.Role == "it_ops" {
		h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": "FORBIDDEN", "message": "Forbidden"})
		return
	}
	clientID, ok1 := toInt64(msg["clientId"])
	toOrgID, ok2 := toInt64(msg["toOrgId"])
	if !ok1 || !ok2 {
		h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": "INVALID_INPUT", "message": "clientId and toOrgId required"})
		return
	}
	client, err := h.db.GetClientByID(ctx, clientID)
	if err != nil || client == nil || client.Disabled == 1 {
		h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": "NOT_FOUND", "message": "Client not found"})
		return
	}
	if admin.Role == "org_admin" && client.OrgID != admin.OrgID {
		h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": "FORBIDDEN", "message": "Client not in your organization"})
		return
	}
	features, _ := h.db.GetAdminUiFeatures(ctx)
	if admin.Role == "org_admin" {
		if on, _ := features["transfer_tab"].(bool); !on {
			h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": "FORBIDDEN", "message": "Transfer workflow is disabled for team leads"})
			return
		}
	}
	fromOrgID := client.OrgID
	if fromOrgID == toOrgID {
		h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": "INVALID_INPUT", "message": "Client is already in this team"})
		return
	}

	// Super admin: instant transfer (no pending approval).
	if admin.Role == "super_admin" {
		if err := h.applyClientOrgTransfer(ctx, clientID, fromOrgID, toOrgID, admin.AdminID); err != nil {
			h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": "SERVER_ERROR", "message": "Could not transfer client"})
			return
		}
		created, err := h.db.CreateTransferRequestApproved(ctx, clientID, fromOrgID, toOrgID, admin.AdminID, admin.AdminID)
		if err != nil {
			h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": "SERVER_ERROR"})
			return
		}
		h.sendConn(conn, map[string]any{
			"type": "admin-create-transfer-request-response", "success": true,
			"requestId": created.RequestID, "deduped": created.Deduped, "status": "approved", "instant": true,
		})
		h.broadcastTransferEvent(h.transferEventPayload(ctx, "transfer-updated", created.RequestID, clientID, client.FullName,
			fromOrgID, toOrgID, "approved", admin.AdminID, admin.FullName))
		return
	}

	created, err := h.db.CreateTransferRequest(ctx, clientID, fromOrgID, toOrgID, admin.AdminID)
	if err != nil || !created.Success {
		h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": false, "error": created.Error, "message": created.Message})
		return
	}
	h.sendConn(conn, map[string]any{"type": "admin-create-transfer-request-response", "success": true, "requestId": created.RequestID, "deduped": created.Deduped})
	h.broadcastTransferEvent(h.transferEventPayload(ctx, "transfer-requested", created.RequestID, clientID, client.FullName,
		fromOrgID, toOrgID, "pending", admin.AdminID, admin.FullName))
}

func (h *Hub) handleAdminRespondTransferRequest(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	if admin.Role == "it_ops" {
		h.sendConn(conn, map[string]any{"type": "admin-respond-transfer-request-response", "success": false, "error": "FORBIDDEN", "message": "Forbidden"})
		return
	}
	requestID, ok := toInt64(msg["requestId"])
	action := asNonEmptyString(msg["action"], 32)
	if !ok || (action != "approve" && action != "reject") {
		h.sendConn(conn, map[string]any{"type": "admin-respond-transfer-request-response", "success": false, "error": "INVALID_INPUT", "message": "requestId and action required"})
		return
	}
	req, err := h.db.GetTransferRequestByID(ctx, requestID)
	if err != nil || req == nil {
		h.sendConn(conn, map[string]any{"type": "admin-respond-transfer-request-response", "success": false, "error": "NOT_FOUND", "message": "Request not found"})
		return
	}
	if req.Status != "pending" {
		h.sendConn(conn, map[string]any{"type": "admin-respond-transfer-request-response", "success": false, "error": "INVALID_STATE", "message": "Request already resolved"})
		return
	}
	canAct := admin.Role == "super_admin" || (admin.Role == "org_admin" && admin.OrgID == req.ToOrgID)
	if !canAct {
		h.sendConn(conn, map[string]any{"type": "admin-respond-transfer-request-response", "success": false, "error": "FORBIDDEN", "message": "Forbidden"})
		return
	}
	features, _ := h.db.GetAdminUiFeatures(ctx)
	if admin.Role == "org_admin" {
		if on, _ := features["transfer_tab"].(bool); !on {
			h.sendConn(conn, map[string]any{"type": "admin-respond-transfer-request-response", "success": false, "error": "FORBIDDEN", "message": "Transfer workflow is disabled for team leads"})
			return
		}
	}
	nextStatus := "rejected"
	if action == "approve" {
		nextStatus = "approved"
		if err := h.applyClientOrgTransfer(ctx, req.ClientID, req.FromOrgID, req.ToOrgID, admin.AdminID); err != nil {
			h.sendConn(conn, map[string]any{"type": "admin-respond-transfer-request-response", "success": false, "error": "SERVER_ERROR", "message": "Could not transfer client"})
			return
		}
	}
	_ = h.db.UpdateTransferRequestStatus(ctx, requestID, nextStatus, admin.AdminID)
	h.sendConn(conn, map[string]any{"type": "admin-respond-transfer-request-response", "success": true, "requestId": requestID, "status": nextStatus})
	h.broadcastTransferEvent(h.transferEventPayload(ctx, "transfer-updated", requestID, req.ClientID, req.ClientFullName,
		req.FromOrgID, req.ToOrgID, nextStatus, admin.AdminID, admin.FullName))
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
