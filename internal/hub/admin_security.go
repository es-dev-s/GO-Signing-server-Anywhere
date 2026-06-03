package hub

import (
	"context"
	"time"

	"github.com/anywhere/signing-server-go/internal/streamwindow"
)

func (h *Hub) orgAdminStreamConnectAllowed(ctx context.Context) (bool, string) {
	p, err := h.db.GetOrgAdminStreamWindow(ctx)
	if err != nil {
		return true, ""
	}
	ok, err := p.AllowedNow(time.Now())
	if err != nil {
		return true, ""
	}
	if ok {
		return true, ""
	}
	return false, p.DenyMessage()
}

func (h *Hub) revokeAdminSessionsAndDisconnect(ctx context.Context, adminID int64) {
	_ = h.db.RevokeAllAdminSessions(ctx, adminID)
	payload := map[string]any{
		"type":    "admin-session-revoked",
		"reason":  "password_reset",
		"message": "Your password was reset. Please sign in again.",
	}
	var toClose []string
	h.mu.RLock()
	for sid, c := range h.conns {
		if c.admin != nil && c.admin.AdminID == adminID {
			h.sendConn(c, payload)
			toClose = append(toClose, sid)
		}
	}
	h.mu.RUnlock()
	for _, sid := range toClose {
		h.mu.RLock()
		c := h.conns[sid]
		h.mu.RUnlock()
		if c != nil && c.ws != nil {
			_ = c.ws.Close()
		}
	}
}

func (h *Hub) handleAdminListResettableAdmins(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil || admin.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-list-resettable-admins-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	list, err := h.db.ListResettableAdmins(ctx)
	if err != nil {
		h.sendConn(conn, map[string]any{"type": "admin-list-resettable-admins-response", "success": false, "error": "SERVER_ERROR"})
		return
	}
	h.sendConn(conn, map[string]any{"type": "admin-list-resettable-admins-response", "success": true, "admins": list})
}

func (h *Hub) handleAdminResetPassword(ctx context.Context, conn *Conn, msg map[string]any) {
	actor := h.requireAdmin(ctx, conn, msg)
	if actor == nil || actor.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-reset-password-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	targetID, ok := toInt64(msg["targetAdminId"])
	if !ok {
		h.sendConn(conn, map[string]any{"type": "admin-reset-password-response", "success": false, "error": "INVALID_INPUT"})
		return
	}
	password := asNonEmptyString(msg["newPassword"], 500)
	if len(password) < 8 {
		h.sendConn(conn, map[string]any{
			"type": "admin-reset-password-response", "success": false,
			"error": "INVALID_INPUT", "message": "Password must be at least 8 characters.",
		})
		return
	}
	target, err := h.db.GetAdminByID(ctx, targetID)
	if err != nil || target == nil {
		h.sendConn(conn, map[string]any{"type": "admin-reset-password-response", "success": false, "error": "NOT_FOUND"})
		return
	}
	if target.Role != "org_admin" && target.Role != "super_admin" {
		h.sendConn(conn, map[string]any{
			"type": "admin-reset-password-response", "success": false,
			"error": "FORBIDDEN", "message": "Only org admin and super admin accounts can be reset.",
		})
		return
	}
	if err := h.db.UpdateAdminPassword(ctx, targetID, password); err != nil {
		h.sendConn(conn, map[string]any{"type": "admin-reset-password-response", "success": false, "error": "SERVER_ERROR"})
		return
	}
	h.revokeAdminSessionsAndDisconnect(ctx, targetID)
	h.sendConn(conn, map[string]any{
		"type": "admin-reset-password-response", "success": true,
		"targetAdminId": targetID, "username": target.Username, "fullName": target.FullName,
		"message": "Password updated. The account has been signed out everywhere.",
	})
}

func (h *Hub) handleAdminGetStreamWindow(ctx context.Context, conn *Conn, msg map[string]any) {
	if h.requireAdmin(ctx, conn, msg) == nil {
		return
	}
	p, err := h.db.GetOrgAdminStreamWindow(ctx)
	if err != nil {
		h.sendConn(conn, map[string]any{"type": "admin-get-stream-window-response", "success": false, "error": "SERVER_ERROR"})
		return
	}
	allowed, _ := p.AllowedNow(time.Now())
	h.sendConn(conn, map[string]any{
		"type": "admin-get-stream-window-response", "success": true,
		"streamWindow": streamWindowPayload(p, allowed),
	})
}

func (h *Hub) handleAdminSetStreamWindow(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil || admin.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-set-stream-window-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	cur, _ := h.db.GetOrgAdminStreamWindow(ctx)
	if v, ok := msg["enabled"].(bool); ok {
		cur.Enabled = v
	}
	if v, ok := msg["startHour"].(float64); ok {
		cur.StartHour = int(v)
	}
	if v, ok := msg["endHour"].(float64); ok {
		cur.EndHour = int(v)
	}
	next, err := h.db.SetOrgAdminStreamWindow(ctx, cur)
	if err != nil {
		h.sendConn(conn, map[string]any{"type": "admin-set-stream-window-response", "success": false, "error": "SERVER_ERROR"})
		return
	}
	allowed, _ := next.AllowedNow(time.Now())
	h.sendConn(conn, map[string]any{
		"type": "admin-set-stream-window-response", "success": true,
		"streamWindow": streamWindowPayload(next, allowed),
	})
}

func streamWindowPayload(p streamwindow.Policy, allowedNow bool) map[string]any {
	p = p.Normalize()
	return map[string]any{
		"enabled": p.Enabled, "timezone": p.Timezone,
		"startHour": p.StartHour, "endHour": p.EndHour,
		"windowLabel": p.HumanWindow(), "allowedNow": allowedNow,
	}
}
