package hub

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/anywhere/signing-server-go/internal/auditproxy"
)

func (h *Hub) auditProxyReview(ctx context.Context, conn *Conn, msg map[string]any) {
	ipc := asNonEmptyString(msg["ipcCorrId"], 64)
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil || admin.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-audit-org-access-review-response", "success": false, "ipcCorrId": ipc})
		return
	}
	if !h.audit.Configured {
		h.sendConn(conn, map[string]any{"type": "admin-audit-org-access-review-response", "success": false, "error": "AUDIT_PROXY_NOT_CONFIGURED", "ipcCorrId": ipc})
		return
	}
	body, _ := json.Marshal(map[string]any{
		"id": msg["id"], "action": msg["action"], "reviewerUsername": msg["reviewerUsername"],
	})
	ok, _, data, err := auditproxy.FetchJSON(ctx, h.audit, "/api/superadmin/audit-org-access", http.MethodPost, body)
	if err != nil || !ok {
		h.sendConn(conn, map[string]any{"type": "admin-audit-org-access-review-response", "success": false, "ipcCorrId": ipc})
		return
	}
	h.sendConn(conn, map[string]any{"type": "admin-audit-org-access-review-response", "success": data["success"] != false, "status": data["status"], "ipcCorrId": ipc})
}

func (h *Hub) auditProxyGroupsGet(ctx context.Context, conn *Conn, msg map[string]any) {
	ipc := asNonEmptyString(msg["ipcCorrId"], 64)
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil || admin.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-audit-groups-get-response", "success": false, "ipcCorrId": ipc})
		return
	}
	if !h.audit.Configured {
		h.sendConn(conn, map[string]any{"type": "admin-audit-groups-get-response", "success": false, "error": "AUDIT_PROXY_NOT_CONFIGURED", "ipcCorrId": ipc})
		return
	}
	ok, _, data, err := auditproxy.FetchJSON(ctx, h.audit, "/api/superadmin/audit-groups", http.MethodGet, nil)
	if err != nil || !ok {
		h.sendConn(conn, map[string]any{"type": "admin-audit-groups-get-response", "success": false, "ipcCorrId": ipc})
		return
	}
	h.sendConn(conn, map[string]any{
		"type": "admin-audit-groups-get-response", "success": true,
		"groups": data["groups"], "teamLeads": data["teamLeads"], "ipcCorrId": ipc,
	})
}

func (h *Hub) auditProxyGroupsMutate(ctx context.Context, conn *Conn, msg map[string]any) {
	ipc := asNonEmptyString(msg["ipcCorrId"], 64)
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil || admin.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-audit-groups-mutate-response", "success": false, "ipcCorrId": ipc})
		return
	}
	if !h.audit.Configured {
		h.sendConn(conn, map[string]any{"type": "admin-audit-groups-mutate-response", "success": false, "error": "AUDIT_PROXY_NOT_CONFIGURED", "ipcCorrId": ipc})
		return
	}
	body := map[string]any{}
	for k, v := range msg {
		if k == "type" || k == "token" || k == "ipcCorrId" {
			continue
		}
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	ok, _, data, err := auditproxy.FetchJSON(ctx, h.audit, "/api/superadmin/audit-groups", http.MethodPost, raw)
	if err != nil || !ok {
		h.sendConn(conn, map[string]any{"type": "admin-audit-groups-mutate-response", "success": false, "ipcCorrId": ipc})
		return
	}
	resp := map[string]any{"type": "admin-audit-groups-mutate-response", "success": true, "ipcCorrId": ipc}
	for k, v := range data {
		resp[k] = v
	}
	h.sendConn(conn, resp)
}

func (h *Hub) handleRemoteAccess(ctx context.Context, typ string, conn *Conn, msg map[string]any) {
	ipc := asNonEmptyString(msg["ipcCorrId"], 64)
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	switch typ {
	case "remote-access-request":
		if admin.Role == "super_admin" {
			h.sendConn(conn, map[string]any{"type": "remote-access-request-response", "success": false, "reason": "NOT_APPLICABLE", "ipcCorrId": ipc})
			return
		}
		active, _ := h.db.GetActiveRemoteAccess(ctx, admin.AdminID)
		if active != nil {
			h.sendConn(conn, map[string]any{"type": "remote-access-request-response", "success": false, "reason": "ALREADY_ACTIVE", "ipcCorrId": ipc})
			return
		}
		reason := asNonEmptyString(msg["reason"], 500)
		dur := 4
		if d, ok := toInt64(msg["durationHours"]); ok {
			dur = int(d)
		}
		if dur < 1 {
			dur = 1
		}
		if dur > 72 {
			dur = 72
		}
		req, _ := h.db.CreateRemoteAccessRequest(ctx, admin.AdminID, admin.OrgID, conn.ip, reason, dur)
		h.sendConn(conn, map[string]any{"type": "remote-access-request-response", "success": true, "requestId": req["id"], "ipcCorrId": ipc})
	case "approve-remote-access":
		if admin.Role != "super_admin" {
			return
		}
		rid, _ := toInt64(msg["requestId"])
		updated, _ := h.db.ApproveRemoteAccessRequest(ctx, rid, admin.AdminID)
		h.sendConn(conn, map[string]any{"type": "approve-remote-access-response", "success": updated != nil, "ipcCorrId": ipc})
	case "deny-remote-access":
		if admin.Role != "super_admin" {
			return
		}
		rid, _ := toInt64(msg["requestId"])
		_, _ = h.db.DenyRemoteAccessRequest(ctx, rid, admin.AdminID)
		h.sendConn(conn, map[string]any{"type": "deny-remote-access-response", "success": true, "ipcCorrId": ipc})
	case "get-my-remote-access-requests":
		list, _ := h.db.GetMyRemoteAccessRequests(ctx, admin.AdminID)
		h.sendConn(conn, map[string]any{"type": "my-remote-access-requests", "requests": list, "ipcCorrId": ipc})
	case "get-pending-remote-access-requests":
		if admin.Role != "super_admin" {
			return
		}
		list, _ := h.db.GetAllPendingRemoteAccessRequests(ctx)
		h.sendConn(conn, map[string]any{"type": "pending-remote-access-requests", "requests": list, "ipcCorrId": ipc})
	}
}

func (h *Hub) handleStreamRelay(ctx context.Context, typ string, conn *Conn, msg map[string]any) {
	ipc := asNonEmptyString(msg["ipcCorrId"], 64)
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	switch typ {
	case "stream-relay-request":
		if admin.Role != "org_admin" {
			h.sendConn(conn, map[string]any{"type": "stream-relay-request-response", "success": false, "reason": "NOT_APPLICABLE", "ipcCorrId": ipc})
			return
		}
		active, _ := h.db.GetActiveStreamRelay(ctx, admin.AdminID)
		if active != nil {
			h.sendConn(conn, map[string]any{"type": "stream-relay-request-response", "success": false, "reason": "ALREADY_ACTIVE", "ipcCorrId": ipc})
			return
		}
		reason := asNonEmptyString(msg["reason"], 500)
		dur := 4
		if d, ok := toInt64(msg["durationHours"]); ok {
			dur = int(d)
		}
		req, _ := h.db.CreateStreamRelayRequest(ctx, admin.AdminID, admin.OrgID, conn.ip, reason, dur)
		h.sendConn(conn, map[string]any{"type": "stream-relay-request-response", "success": true, "requestId": req["id"], "ipcCorrId": ipc})
	case "approve-stream-relay":
		if admin.Role != "super_admin" {
			return
		}
		rid, _ := toInt64(msg["requestId"])
		updated, _ := h.db.ApproveStreamRelayRequest(ctx, rid, admin.AdminID)
		h.sendConn(conn, map[string]any{"type": "approve-stream-relay-response", "success": updated != nil, "ipcCorrId": ipc})
	case "deny-stream-relay":
		if admin.Role != "super_admin" {
			return
		}
		rid, _ := toInt64(msg["requestId"])
		_, _ = h.db.DenyStreamRelayRequest(ctx, rid, admin.AdminID)
		h.sendConn(conn, map[string]any{"type": "deny-stream-relay-response", "success": true, "ipcCorrId": ipc})
	case "get-my-stream-relay-requests":
		list, _ := h.db.GetMyStreamRelayRequests(ctx, admin.AdminID)
		h.sendConn(conn, map[string]any{"type": "my-stream-relay-requests", "requests": list, "ipcCorrId": ipc})
	case "get-pending-stream-relay-requests":
		if admin.Role != "super_admin" {
			return
		}
		list, _ := h.db.GetAllPendingStreamRelayRequests(ctx)
		h.sendConn(conn, map[string]any{"type": "pending-stream-relay-requests", "requests": list, "ipcCorrId": ipc})
	case "get-active-stream-relay":
		var active any
		if admin.Role == "org_admin" || admin.Role == "it_ops" {
			active, _ = h.db.GetActiveStreamRelay(ctx, admin.AdminID)
		}
		h.sendConn(conn, map[string]any{"type": "active-stream-relay", "active": active, "ipcCorrId": ipc})
	}
}
