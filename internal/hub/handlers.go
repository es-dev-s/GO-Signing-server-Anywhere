package hub

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/anywhere/signing-server-go/internal/auditproxy"
	"github.com/anywhere/signing-server-go/internal/auth"
	"github.com/anywhere/signing-server-go/internal/db"
	"github.com/anywhere/signing-server-go/internal/ice"
)

func (h *Hub) handleMessage(socketID string, conn *Conn, msg map[string]any) {
	ctx := context.Background()
	typ := msgType(msg)
	skipRate := messageSkipsRateLimit(typ)
	if !skipRate && !conn.bucket.Take(1) {
		h.sendConn(conn, map[string]any{"type": "error", "error": "RATE_LIMITED"})
		return
	}
	if typ == "" {
		h.sendConn(conn, map[string]any{"type": "error", "error": "INVALID_TYPE"})
		return
	}

	switch typ {
	case "public-list-orgs":
		orgs, _ := h.db.GetOrganizationsWithAdmins(ctx)
		h.sendConn(conn, map[string]any{"type": "public-list-orgs-response", "success": true, "orgs": orgs})
	case "client-auth":
		h.handleClientAuth(ctx, socketID, conn, msg)
	case "admin-register":
		h.handleAdminRegister(ctx, conn, msg)
	case "admin-login":
		h.handleAdminLogin(ctx, socketID, conn, msg)
	case "admin-logout":
		h.handleAdminLogout(ctx, conn, msg)
	case "admin-get-orgs":
		if a := h.requireAdmin(ctx, conn, msg); a != nil {
			orgs, _ := h.db.GetOrganizations(ctx)
			h.sendConn(conn, map[string]any{"type": "admin-get-orgs-response", "success": true, "orgs": orgs})
		}
	case "admin-get-org-leads":
		h.handleAdminGetOrgLeads(ctx, conn, msg)
	case "admin-get-clients":
		h.handleAdminGetClients(ctx, conn, msg)
	case "admin-get-org-summaries":
		if a := h.requireAdmin(ctx, conn, msg); a != nil {
			orgs, _ := h.db.GetOrganizationSummaries(ctx)
			h.sendConn(conn, map[string]any{"type": "admin-get-org-summaries-response", "success": true, "orgs": orgs})
		}
	case "admin-get-transfer-requests":
		if a := h.requireAdmin(ctx, conn, msg); a != nil {
			list, _ := h.db.ListTransferRequests(ctx, a.Role, a.OrgID)
			h.sendConn(conn, map[string]any{"type": "admin-get-transfer-requests-response", "success": true, "requests": list})
		}
	case "admin-create-transfer-request":
		h.handleAdminCreateTransferRequest(ctx, conn, msg)
	case "admin-respond-transfer-request":
		h.handleAdminRespondTransferRequest(ctx, conn, msg)
	case "admin-get-ui-features":
		h.handleAdminGetUIFeatures(ctx, conn, msg)
	case "admin-set-ui-features":
		h.handleAdminSetUIFeatures(ctx, conn, msg)
	case "admin-list-resettable-admins":
		h.handleAdminListResettableAdmins(ctx, conn, msg)
	case "admin-reset-password":
		h.handleAdminResetPassword(ctx, conn, msg)
	case "admin-get-stream-window":
		h.handleAdminGetStreamWindow(ctx, conn, msg)
	case "admin-set-stream-window":
		h.handleAdminSetStreamWindow(ctx, conn, msg)
	case "admin-update-client-org":
		h.handleAdminUpdateClientOrg(ctx, conn, msg)
	case "admin-remove-client":
		h.handleAdminRemoveClient(ctx, conn, msg)
	case "admin-audit-org-access-list":
		h.auditProxyList(ctx, conn, msg)
	case "admin-audit-org-access-review":
		h.auditProxyReview(ctx, conn, msg)
	case "admin-audit-groups-get":
		h.auditProxyGroupsGet(ctx, conn, msg)
	case "admin-audit-groups-mutate":
		h.auditProxyGroupsMutate(ctx, conn, msg)
	case "offer", "answer", "ice-candidate", "client-ready", "request-offer", "enable-client-media", "client-screen-sources":
		h.relaySignaling(socketID, conn, msg)
	case "ice-path-report":
		h.handleIcePathReport(ctx, socketID, conn, msg)
	case "request-stream-transport-upgrade":
		h.handleStreamTransportUpgrade(ctx, socketID, conn, msg)
	case "sfu-api":
		h.handleSfuAPI(ctx, conn, msg)
	case "sfu-register-publisher":
		h.handleSfuRegisterPublisher(socketID, conn, msg)
	case "media-provider-failed":
		h.handleMediaProviderFailed(conn, msg)
	case "remote-access-request", "approve-remote-access", "deny-remote-access",
		"get-my-remote-access-requests", "get-pending-remote-access-requests":
		h.handleRemoteAccess(ctx, typ, conn, msg)
	case "stream-relay-request", "approve-stream-relay", "deny-stream-relay",
		"get-my-stream-relay-requests", "get-pending-stream-relay-requests", "get-active-stream-relay":
		h.handleStreamRelay(ctx, typ, conn, msg)
	case "heartbeat":
		_ = h.db.UpdateClientHeartbeat(ctx, socketID)
		h.sendConn(conn, map[string]any{"type": "heartbeat-ack"})
	case "register":
		h.handleLegacyRegister(ctx, socketID, conn, msg)
	case "get-clients":
		h.handleLegacyGetClients(ctx, conn)
	case "connect-to-client":
		if asToken(msg["token"]) != "" {
			h.handleAdminConnectToClient(ctx, socketID, conn, msg)
		} else {
			h.handleLegacyConnect(ctx, socketID, conn, msg)
		}
	case "admin-stop-viewing":
		h.handleAdminStopViewing(socketID, conn, msg)
	case "admin-focus-client-app":
		h.handleAdminFocusClientApp(ctx, socketID, conn, msg)
	case "start-sharing", "stop-sharing":
	case "disconnect":
		h.disconnect(socketID)
	default:
		h.sendConn(conn, map[string]any{"type": "error", "error": "UNKNOWN_TYPE", "message": "Unknown message type: " + typ})
	}
}

func (h *Hub) requireAdmin(ctx context.Context, conn *Conn, msg map[string]any) *db.AdminRow {
	token := asToken(msg["token"])
	if token == "" {
		h.sendConn(conn, map[string]any{"type": "error", "error": "UNAUTHORIZED"})
		return nil
	}
	admin, err := h.db.GetAdminBySessionToken(ctx, token)
	if err != nil || admin == nil {
		h.sendConn(conn, map[string]any{"type": "error", "error": "UNAUTHORIZED"})
		return nil
	}
	if conn.kind != KindAdmin {
		conn.kind = KindAdmin
		conn.admin = &AdminIdentity{
			AdminID: admin.AdminID, OrgID: admin.OrgID, Username: admin.Username,
			FullName: admin.FullName, Role: admin.Role, Token: token,
		}
		conn.client = nil
	}
	return admin
}

func (h *Hub) handleClientAuth(ctx context.Context, socketID string, conn *Conn, msg map[string]any) {
	deviceID := asNonEmptyString(msg["deviceId"], 200)
	orgName := asNonEmptyString(msg["orgName"], 200)
	fullName := asNonEmptyString(msg["fullName"], 200)
	if deviceID == "" || orgName == "" || fullName == "" {
		h.sendConn(conn, map[string]any{"type": "client-auth-response", "success": false, "error": "INVALID_INPUT"})
		return
	}
	prev, _ := h.db.GetSocketIDForDevice(ctx, deviceID)
	if prev != nil && *prev != socketID {
		h.mu.RLock()
		prevConn := h.conns[*prev]
		last := h.lastDeviceTakeover[deviceID]
		h.mu.RUnlock()
		// Only throttle when the *previous socket is still connected* (two live clients fighting).
		// After OTA/reconnect the DB may still list a dead socket_id until disconnect runs — do not
		// reject legitimate reconnects with DUPLICATE_DEVICE in that case.
		if prevConn != nil {
			if time.Now().UnixMilli()-last < h.cfg.DeviceTakeoverCooldownMs {
				log.Printf("[client-auth] DUPLICATE_DEVICE device=%s prev=%s new=%s (cooldown)", deviceID, *prev, socketID)
				h.sendConn(conn, map[string]any{"type": "client-auth-response", "success": false, "error": "DUPLICATE_DEVICE"})
				_ = conn.ws.Close()
				return
			}
			h.mu.Lock()
			h.lastDeviceTakeover[deviceID] = time.Now().UnixMilli()
			h.mu.Unlock()
		}
	}
	res, err := h.db.UpsertClientAuth(ctx, deviceID, orgName, fullName, socketID)
	if err != nil || !res.Success {
		h.sendConn(conn, map[string]any{"type": "client-auth-response", "success": false, "error": res.Error, "message": res.Message})
		return
	}
	conn.kind = KindClient
	conn.client = &ClientIdentity{ID: res.Client.ID, OrgID: res.Client.OrgID, FullName: res.Client.FullName, DeviceID: deviceID}
	conn.admin = nil
	ingest, _ := auth.SignIngestToken(h.cfg.IngestTokenSecret, res.Client.ID, res.Client.OrgID, h.cfg.IngestTokenTTLMs)
	h.sendConn(conn, map[string]any{
		"type": "client-auth-response", "success": true,
		"client": map[string]any{"id": res.Client.ID, "orgId": res.Client.OrgID, "fullName": res.Client.FullName, "status": res.Client.Status},
		"ingestToken": ingest,
	})
	if prev != nil && *prev != socketID {
		h.mu.RLock()
		old := h.conns[*prev]
		h.mu.RUnlock()
		if old != nil {
			log.Printf("[client-auth] device takeover %s: closing previous socket %s", deviceID, *prev)
			_ = old.ws.Close()
		}
	}
	_ = h.broadcastClientsListToAdmins(ctx, res.Client.OrgID)
	if res.ExtraBroadcastOrgID != nil {
		_ = h.broadcastClientsListToAdmins(ctx, *res.ExtraBroadcastOrgID)
	}
}

func (h *Hub) handleAdminLogin(ctx context.Context, socketID string, conn *Conn, msg map[string]any) {
	orgName := asNonEmptyString(msg["orgName"], 200)
	username := asNonEmptyString(msg["username"], 200)
	password := asNonEmptyString(msg["password"], 500)
	org, err := h.db.GetOrganizationByName(ctx, orgName)
	if err != nil || org == nil {
		h.sendConn(conn, map[string]any{"type": "admin-login-response", "success": false, "error": "UNKNOWN_ORG"})
		return
	}
	row, err := h.db.GetAdminByOrgAndUsername(ctx, org.ID, username)
	if err != nil || row == nil {
		h.sendConn(conn, map[string]any{"type": "admin-login-response", "success": false, "error": "INVALID_CREDENTIALS"})
		return
	}
	ph, _ := row["password_hash"].(string)
	if !h.db.VerifyAdminPassword(ph, password) {
		h.sendConn(conn, map[string]any{"type": "admin-login-response", "success": false, "error": "INVALID_CREDENTIALS"})
		return
	}
	adminID, _ := toInt64(row["id"])
	sess, err := h.db.CreateAdminSession(ctx, adminID)
	if err != nil {
		h.sendConn(conn, map[string]any{"type": "admin-login-response", "success": false, "error": "SERVER_ERROR"})
		return
	}
	conn.kind = KindAdmin
	conn.workstationIPs = parseWorkstationIPs(msg["workstationIps"])
	conn.admin = &AdminIdentity{
		AdminID: adminID, OrgID: org.ID,
		Username: fmt.Sprint(row["username"]), FullName: fmt.Sprint(row["full_name"]),
		Role: fmt.Sprint(row["role"]), Token: sess.Token,
	}
	conn.client = nil
	conn.ipStatusSent = false
	features, _ := h.db.GetAdminUiFeatures(ctx)
	loginResp := map[string]any{
		"type": "admin-login-response", "success": true, "token": sess.Token, "expiresAt": sess.ExpiresAt,
		"admin": map[string]any{"id": adminID, "orgId": org.ID, "username": row["username"], "fullName": row["full_name"], "role": row["role"]},
		"org": map[string]any{"id": org.ID, "name": org.Name},
		"adminUiFeatures": features,
	}
	if fmt.Sprint(row["role"]) == "org_admin" {
		if sw, err := h.db.GetOrgAdminStreamWindow(ctx); err == nil {
			allowed, _ := sw.AllowedNow(time.Now())
			loginResp["orgAdminStreamWindow"] = streamWindowPayload(sw, allowed)
		}
	}
	h.sendConn(conn, loginResp)
	adminRow := &db.AdminRow{AdminID: adminID, OrgID: org.ID, Username: fmt.Sprint(row["username"]), FullName: fmt.Sprint(row["full_name"]), Role: fmt.Sprint(row["role"])}
	h.maybeSendAdminIPStatus(socketID, adminRow, conn)
}

func (h *Hub) handleAdminLogout(ctx context.Context, conn *Conn, msg map[string]any) {
	if t := asToken(msg["token"]); t != "" {
		_ = h.db.RevokeAdminSession(ctx, t)
	}
	conn.admin = nil
	if conn.client == nil {
		conn.kind = KindUnknown
	}
	h.sendConn(conn, map[string]any{"type": "admin-logout-response", "success": true})
}

func (h *Hub) handleAdminRegister(ctx context.Context, conn *Conn, msg map[string]any) {
	actor := h.requireAdmin(ctx, conn, msg)
	if actor == nil || actor.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-register-response", "success": false, "error": "UNAUTHORIZED"})
		return
	}
	org, _ := h.db.EnsureOrganization(ctx, asNonEmptyString(msg["orgName"], 200))
	role := asNonEmptyString(msg["role"], 32)
	if role != "it_ops" {
		role = "org_admin"
	}
	res := h.db.CreateAdminAccount(ctx, org.ID, asNonEmptyString(msg["username"], 200), asNonEmptyString(msg["fullName"], 200), asNonEmptyString(msg["password"], 500), role)
	if !res.Success {
		h.sendConn(conn, map[string]any{"type": "admin-register-response", "success": false, "error": res.Error, "message": res.Message})
		return
	}
	h.sendConn(conn, map[string]any{"type": "admin-register-response", "success": true, "role": role, "org": org})
}

func (h *Hub) handleAdminGetClients(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	_ = h.db.ReconcileClientOrgsFromApprovedTransfers(ctx)
	targetOrg := admin.OrgID
	if admin.Role == "super_admin" {
		if oid, ok := toInt64(msg["orgId"]); ok {
			targetOrg = oid
		}
	}
	var rows []db.ClientRow
	var err error
	if admin.Role == "it_ops" && msg["orgId"] == nil {
		rows, err = h.db.GetAllClientsGrouped(ctx)
	} else if admin.Role == "super_admin" && msg["orgId"] == nil {
		rows, err = h.db.GetAllClientsGrouped(ctx)
	} else {
		rows, err = h.db.GetClientsForOrg(ctx, targetOrg)
	}
	if err != nil {
		h.sendConn(conn, map[string]any{"type": "admin-get-clients-response", "success": false})
		return
	}
	clients := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		clients = append(clients, h.mapAdminClientRow(c))
	}
	if admin.Role == "org_admin" || admin.Role == "it_ops" {
		clients = h.filterClientsByAuditGroupOrgAdminScope(ctx, admin.AdminID, admin.OrgID, clients)
	}
	h.sendConn(conn, map[string]any{"type": "admin-get-clients-response", "success": true, "clients": clients, "orgId": targetOrg})
}

func (h *Hub) handleAdminGetOrgLeads(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	var orgID *int64
	if admin.Role == "org_admin" {
		orgID = &admin.OrgID
	}
	leads, _ := h.db.GetOrgLeads(ctx, orgID)
	resp := map[string]any{"type": "admin-get-org-leads-response", "success": true, "leads": leads}
	if ipc := asNonEmptyString(msg["ipcCorrId"], 64); ipc != "" {
		resp["ipcCorrId"] = ipc
	}
	h.sendConn(conn, resp)
}

func (h *Hub) handleAdminGetUIFeatures(ctx context.Context, conn *Conn, msg map[string]any) {
	if h.requireAdmin(ctx, conn, msg) == nil {
		return
	}
	f, _ := h.db.GetAdminUiFeatures(ctx)
	h.sendConn(conn, map[string]any{"type": "admin-get-ui-features-response", "success": true, "adminUiFeatures": f})
}

func (h *Hub) handleAdminSetUIFeatures(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil || admin.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-set-ui-features-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	patch, _ := msg["features"].(map[string]any)
	if patch == nil {
		h.sendConn(conn, map[string]any{"type": "admin-set-ui-features-response", "success": false, "error": "INVALID_INPUT"})
		return
	}
	next, _ := h.db.SetAdminUiFeaturesPatch(ctx, patch)
	h.sendConn(conn, map[string]any{"type": "admin-set-ui-features-response", "success": true, "adminUiFeatures": next})
}

func (h *Hub) handleAdminUpdateClientOrg(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil || admin.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-update-client-org-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	cid, ok1 := toInt64(msg["clientId"])
	oid, ok2 := toInt64(msg["orgId"])
	if !ok1 || !ok2 {
		h.sendConn(conn, map[string]any{"type": "admin-update-client-org-response", "success": false, "error": "INVALID_INPUT"})
		return
	}
	client, _ := h.db.GetClientByID(ctx, cid)
	if client == nil {
		h.sendConn(conn, map[string]any{"type": "admin-update-client-org-response", "success": false, "error": "NOT_FOUND"})
		return
	}
	if client.OrgID == oid {
		h.sendConn(conn, map[string]any{"type": "admin-update-client-org-response", "success": true, "message": "Client is already in this team"})
		return
	}
	if err := h.applyClientOrgTransfer(ctx, cid, client.OrgID, oid, admin.AdminID); err != nil {
		h.sendConn(conn, map[string]any{"type": "admin-update-client-org-response", "success": false, "error": "SERVER_ERROR"})
		return
	}
	h.sendConn(conn, map[string]any{"type": "admin-update-client-org-response", "success": true, "message": "Client transferred"})
}

func (h *Hub) handleAdminRemoveClient(ctx context.Context, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	if admin.Role != "super_admin" && admin.Role != "org_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-remove-client-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	cid, ok := toInt64(msg["clientId"])
	if !ok {
		h.sendConn(conn, map[string]any{"type": "admin-remove-client-response", "success": false, "error": "INVALID_INPUT"})
		return
	}
	row, _ := h.db.GetClientByID(ctx, cid)
	if row == nil {
		h.sendConn(conn, map[string]any{"type": "admin-remove-client-response", "success": false, "error": "NOT_FOUND"})
		return
	}
	if admin.Role == "org_admin" && row.OrgID != admin.OrgID {
		h.sendConn(conn, map[string]any{"type": "admin-remove-client-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	_ = h.db.DisableClient(ctx, cid)
	if row.SocketID != nil {
		h.mu.RLock()
		c := h.conns[*row.SocketID]
		h.mu.RUnlock()
		if c != nil {
			h.sendConn(c, map[string]any{"type": "client-disabled", "success": true})
			_ = c.ws.Close()
		}
	}
	h.sendConn(conn, map[string]any{"type": "admin-remove-client-response", "success": true})
	_ = h.broadcastClientsListToAdmins(ctx, row.OrgID)
}

func (h *Hub) handleAdminConnectToClient(ctx context.Context, adminSID string, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	if ok, ip := h.sensitiveAccessAllowed(); !ok {
		h.sendConn(conn, map[string]any{"type": "access-restricted", "code": "NOT_IN_OFFICE", "adminIp": ip})
		return
	}
	var client *db.ClientRow
	if cid, ok := toInt64(msg["clientId"]); ok {
		client, _ = h.db.GetClientByID(ctx, cid)
	} else if fn := asNonEmptyString(msg["clientFullName"], 200); fn != "" {
		client, _ = h.db.GetClientByOrgAndFullName(ctx, admin.OrgID, fn)
	}
	if client == nil || client.Disabled == 1 {
		h.sendConn(conn, map[string]any{"type": "connect-response", "success": false, "error": "CLIENT_UNAVAILABLE"})
		return
	}
	if admin.Role != "super_admin" && client.OrgID != admin.OrgID {
		h.sendConn(conn, map[string]any{"type": "connect-response", "success": false, "error": "FORBIDDEN"})
		return
	}
	if admin.Role == "org_admin" || admin.Role == "it_ops" {
		if !h.orgAdminAllowsAuditGroupClient(ctx, admin, client.ID) {
			h.sendConn(conn, map[string]any{
				"type": "connect-response", "success": false, "error": "FORBIDDEN",
				"message": "This member is not in any audit group assigned to you.",
				"clientId": client.ID,
			})
			return
		}
	}
	if admin.Role == "org_admin" {
		if ok, denyMsg := h.orgAdminStreamConnectAllowed(ctx); !ok {
			h.sendConn(conn, map[string]any{
				"type": "connect-response", "success": false, "error": "STREAM_WINDOW_CLOSED",
				"message": denyMsg, "clientId": client.ID,
			})
			return
		}
	}
	live := h.resolveLiveClient(ctx, client)
	if live == nil {
		h.sendConn(conn, map[string]any{"type": "connect-response", "success": false, "error": "CLIENT_UNAVAILABLE"})
		return
	}
	clientSID := live.socketID
	h.unlinkAdminFromStaleClientSockets(adminSID, client.ID, clientSID)
	if !h.adminAlreadyViewing(adminSID, clientSID) {
		if h.countAdminTargets(adminSID) >= h.cfg.MaxAdminViewerTargets {
			h.sendConn(conn, map[string]any{"type": "connect-response", "success": false, "error": "ADMIN_VIEWER_LIMIT", "clientId": client.ID})
			return
		}
		if h.countClientViewers(clientSID) >= h.cfg.MaxViewersPerClient {
			h.sendConn(conn, map[string]any{"type": "connect-response", "success": false, "error": "CLIENT_VIEWER_LIMIT", "clientId": client.ID})
			return
		}
	}
	aid := &admin.AdminID
	alreadyViewing := h.adminAlreadyViewing(adminSID, clientSID)
	hasRelay := false
	if admin.Role == "org_admin" || admin.Role == "it_ops" {
		if grant, _ := h.db.GetActiveStreamRelay(ctx, admin.AdminID); grant != nil {
			hasRelay = true
		}
	}
	plan := h.sessionTransportPlan(ctx, adminSID, client.ID, alreadyViewing, hasRelay)
	clientPlan := h.enrichTransportPlan(plan, client.ID, "publisher")
	adminPlan := h.enrichTransportPlan(plan, client.ID, "subscriber")
	clientTransport := streamTransportFields(clientPlan)
	adminTransport := streamTransportFields(adminPlan)

	sessID, _ := h.db.CreateSession(ctx, client.OrgID, client.ID, aid)
	h.linkViewer(adminSID, clientSID)

	prepare := map[string]any{
		"type": "prepare-peer", "agentName": admin.FullName, "agentSocketId": adminSID, "sessionId": sessID,
	}
	for k, v := range clientTransport {
		prepare[k] = v
	}
	h.sendConn(live.conn, prepare)

	startOffer := map[string]any{
		"type": "start-offer", "success": true, "sessionId": sessID,
		"clientId": client.ID, "clientFullName": client.FullName, "clientSocketId": clientSID,
	}
	for k, v := range adminTransport {
		startOffer[k] = v
	}
	h.sendConn(conn, startOffer)

	connectResp := map[string]any{
		"type": "connect-response", "success": true, "sessionId": sessID,
		"clientId": client.ID, "clientFullName": client.FullName, "clientSocketId": clientSID,
		"message": fmt.Sprintf("Connecting to \"%s\"...", client.FullName),
	}
	for k, v := range adminTransport {
		connectResp[k] = v
	}
	h.sendConn(conn, connectResp)
}

type liveClient struct {
	conn     *Conn
	socketID string
}

func (h *Hub) resolveLiveClient(ctx context.Context, client *db.ClientRow) *liveClient {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for sid, c := range h.conns {
		if c.client != nil && c.client.ID == client.ID {
			return &liveClient{conn: c, socketID: sid}
		}
	}
	if client.SocketID != nil {
		if c, ok := h.conns[*client.SocketID]; ok {
			return &liveClient{conn: c, socketID: *client.SocketID}
		}
	}
	return nil
}

func (h *Hub) handleAdminStopViewing(adminSID string, conn *Conn, msg map[string]any) {
	if h.requireAdmin(context.Background(), conn, msg) == nil {
		return
	}
	clientSID := asNonEmptyString(msg["clientSocketId"], 200)
	if cid, ok := toInt64(msg["clientId"]); ok && cid > 0 {
		n := h.unlinkAdminFromClient(adminSID, cid, conn)
		if n > 0 {
			h.sendConn(conn, map[string]any{"type": "admin-stop-viewing-response", "success": true, "unlinked": n})
			return
		}
	}
	if clientSID == "" {
		h.sendConn(conn, map[string]any{"type": "admin-stop-viewing-response", "success": false})
		return
	}
	h.unlinkViewer(adminSID, clientSID)
	h.mu.RLock()
	cc := h.conns[clientSID]
	h.mu.RUnlock()
	if cc != nil && cc.kind == KindClient {
		name := "Admin"
		if conn.admin != nil {
			name = conn.admin.FullName
		}
		h.sendConn(cc, map[string]any{"type": "agent-disconnected", "agentSocketId": adminSID, "agentName": name})
	}
	h.sendConn(conn, map[string]any{"type": "admin-stop-viewing-response", "success": true})
}

func (h *Hub) handleAdminFocusClientApp(ctx context.Context, adminSID string, conn *Conn, msg map[string]any) {
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil {
		return
	}
	cid, ok := toInt64(msg["clientId"])
	if !ok {
		h.sendConn(conn, map[string]any{"type": "admin-focus-client-app-response", "success": false, "error": "INVALID_INPUT"})
		return
	}
	client, _ := h.db.GetClientByID(ctx, cid)
	if client == nil || client.SocketID == nil {
		h.sendConn(conn, map[string]any{"type": "admin-focus-client-app-response", "success": false, "error": "CLIENT_UNAVAILABLE"})
		return
	}
	if !h.adminAlreadyViewing(adminSID, *client.SocketID) {
		h.sendConn(conn, map[string]any{"type": "admin-focus-client-app-response", "success": false, "error": "NOT_VIEWING"})
		return
	}
	h.mu.RLock()
	cc := h.conns[*client.SocketID]
	h.mu.RUnlock()
	if cc != nil {
		h.sendConn(cc, map[string]any{"type": "focus-client-app"})
	}
	h.sendConn(conn, map[string]any{"type": "admin-focus-client-app-response", "success": true})
}

func (h *Hub) relaySignaling(fromSID string, from *Conn, msg map[string]any) {
	targetSID := asNonEmptyString(msg["targetSocketId"], 200)
	targetName := asNonEmptyString(msg["targetName"], 200)
	typ := msgType(msg)

	if typ == "client-screen-sources" && from.kind == KindClient && from.client != nil {
		if h.applyClientScreenSources(from, msg) {
			_ = h.broadcastClientsListToAdmins(context.Background(), from.client.OrgID)
		}
		return
	}

	h.mu.RLock()
	var target *Conn
	if targetSID != "" {
		target = h.conns[targetSID]
	} else if targetName != "" {
		for _, c := range h.conns {
			if c.client != nil && c.client.FullName == targetName {
				target = c
				break
			}
			if c.admin != nil && c.admin.FullName == targetName {
				target = c
				break
			}
		}
	}
	h.mu.RUnlock()

	if typ == "client-screen-sources" && target == nil {
		return
	}
	if target == nil {
		h.sendConn(from, map[string]any{"type": "error", "error": "TARGET_UNAVAILABLE"})
		return
	}
	from.signalSeq++
	relay := map[string]any{}
	for k, v := range msg {
		if k == "targetSocketId" || k == "targetName" {
			continue
		}
		relay[k] = v
	}
	relay["seq"] = from.signalSeq
	relay["timestamp"] = time.Now().UnixMilli()
	relay["fromSocketId"] = fromSID
	if from.client != nil {
		relay["fromName"] = from.client.FullName
	} else if from.admin != nil {
		relay["fromName"] = from.admin.FullName
	}
	h.sendConn(target, relay)
}

func (h *Hub) handleLegacyRegister(ctx context.Context, socketID string, conn *Conn, msg map[string]any) {
	name := asNonEmptyString(msg["name"], 200)
	role := asNonEmptyString(msg["role"], 32)
	if name == "" || (role != "client" && role != "agent") {
		h.sendConn(conn, map[string]any{"type": "register-response", "success": false})
		return
	}
	if role == "client" {
		dev := legacyPseudoDevice(name, socketID)
		res, _ := h.db.UpsertClientAuth(ctx, dev, "default", name, socketID)
		if !res.Success {
			h.sendConn(conn, map[string]any{"type": "register-response", "success": false})
			return
		}
		conn.kind = KindClient
		conn.client = &ClientIdentity{ID: res.Client.ID, OrgID: res.Client.OrgID, FullName: name, DeviceID: dev}
		h.sendConn(conn, map[string]any{"type": "register-response", "success": true, "name": name, "role": "client"})
		_ = h.broadcastClientsListToAdmins(ctx, res.Client.OrgID)
		return
	}
	conn.kind = KindLegacyAgent
	h.sendConn(conn, map[string]any{"type": "register-response", "success": true, "name": name, "role": "agent"})
}

func (h *Hub) handleLegacyGetClients(ctx context.Context, conn *Conn) {
	org, _ := h.db.EnsureOrganization(ctx, "default")
	rows, _ := h.db.GetClientsForOrg(ctx, org.ID)
	list := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		list = append(list, map[string]any{"name": c.FullName, "status": h.effectiveStatus(c)})
	}
	h.sendConn(conn, map[string]any{"type": "clients-list", "success": true, "clients": list})
}

func (h *Hub) handleLegacyConnect(ctx context.Context, adminSID string, conn *Conn, msg map[string]any) {
	clientName := asNonEmptyString(msg["clientName"], 200)
	agentName := asNonEmptyString(msg["agentName"], 200)
	if agentName == "" {
		agentName = "legacy-agent"
	}
	org, _ := h.db.EnsureOrganization(ctx, "default")
	client, _ := h.db.FindOnlineClientByOrgAndFullName(ctx, org.ID, clientName)
	if client == nil {
		h.sendConn(conn, map[string]any{"type": "connect-response", "success": false, "error": "CLIENT_UNAVAILABLE"})
		return
	}
	live := h.resolveLiveClient(ctx, client)
	if live == nil {
		h.sendConn(conn, map[string]any{"type": "connect-response", "success": false, "error": "CLIENT_UNAVAILABLE"})
		return
	}
	sessID, _ := h.db.CreateSession(ctx, org.ID, client.ID, nil)
	h.sendConn(live.conn, map[string]any{"type": "agent-connect-request", "agentName": agentName, "agentSocketId": adminSID, "sessionId": sessID})
	h.sendConn(conn, map[string]any{"type": "connect-response", "success": true, "sessionId": sessID})
}

func (h *Hub) disconnect(socketID string) {
	ctx := context.Background()
	h.mu.Lock()
	conn, ok := h.conns[socketID]
	if !ok {
		h.mu.Unlock()
		return
	}
	delete(h.conns, socketID)
	if conn.ip != "" {
		if h.ipCount[conn.ip] > 1 {
			h.ipCount[conn.ip]--
		} else {
			delete(h.ipCount, conn.ip)
		}
	}
	h.mu.Unlock()

	conn.closeSendLoop()

	if conn.kind == KindClient {
		client, _ := h.db.SetClientOfflineBySocket(ctx, socketID)
		if client != nil {
			h.sfu.clearPublisher(client.ID)
			_ = h.broadcastClientsListToAdmins(ctx, client.OrgID)
		}
		var adminSIDs []string
		h.mu.Lock()
		for adminSID := range h.clientViewerLinks[socketID] {
			adminSIDs = append(adminSIDs, adminSID)
		}
		h.mu.Unlock()
		for _, adminSID := range adminSIDs {
			h.unlinkViewer(adminSID, socketID)
		}
	}
	if conn.kind == KindAdmin {
		var clientSIDs []string
		h.mu.Lock()
		for clientSID := range h.adminViewerLinks[socketID] {
			clientSIDs = append(clientSIDs, clientSID)
		}
		h.mu.Unlock()

		name := "Admin"
		if conn.admin != nil {
			name = conn.admin.FullName
		}
		for _, clientSID := range clientSIDs {
			h.mu.RLock()
			cc := h.conns[clientSID]
			h.mu.RUnlock()
			if cc != nil {
				h.sendConn(cc, map[string]any{"type": "agent-disconnected", "agentSocketId": socketID, "agentName": name})
			}
			h.unlinkViewer(socketID, clientSID)
		}
	}
	log.Printf("🔌 Disconnected: %s", socketID)
}

func (h *Hub) effectiveStatus(c db.ClientRow) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, conn := range h.conns {
		if conn.client != nil && conn.client.ID == c.ID {
			// Any live socket = streamable (matches Observe modal; avoids "online but not sharing").
			return "sharing"
		}
	}
	return "offline"
}

func (h *Hub) applyClientScreenSources(conn *Conn, msg map[string]any) bool {
	raw, _ := msg["sources"].([]any)
	mapped := make([]ScreenSource, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := asNonEmptyString(m["id"], 128)
		name := asNonEmptyString(m["name"], 200)
		if id == "" || name == "" {
			continue
		}
		var idx *int
		if n, ok := toInt64(m["index"]); ok && n >= 0 {
			v := int(n)
			idx = &v
		}
		mapped = append(mapped, ScreenSource{ID: id, Name: name, Index: idx})
		if len(mapped) >= 8 {
			break
		}
	}
	sig := screenSourcesSignature(mapped)
	changed := conn.screenSourcesSig != sig
	conn.screenSources = mapped
	conn.screenSourcesSig = sig
	return changed
}

func screenSourcesSignature(sources []ScreenSource) string {
	var b strings.Builder
	for _, s := range sources {
		idx := ""
		if s.Index != nil {
			idx = fmt.Sprintf("%d", *s.Index)
		}
		b.WriteString(idx)
		b.WriteByte(':')
		b.WriteString(s.ID)
		b.WriteByte('|')
	}
	return b.String()
}

func (h *Hub) screenSourcesJSON(clientID int64) []any {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, conn := range h.conns {
		if conn.client != nil && conn.client.ID == clientID {
			out := make([]any, 0, len(conn.screenSources))
			for _, s := range conn.screenSources {
				row := map[string]any{"id": s.ID, "name": s.Name}
				if s.Index != nil {
					row["index"] = *s.Index
				}
				out = append(out, row)
			}
			return out
		}
	}
	return []any{}
}

func (h *Hub) mapAdminClientRow(c db.ClientRow) map[string]any {
	return map[string]any{
		"id": c.ID, "fullName": c.FullName, "status": h.effectiveStatus(c),
		"orgId": c.OrgID, "orgName": c.OrgName, "claimedOrgName": c.ClaimedOrgName,
		"lastHeartbeatMs": c.LastHeartbeat, "lastOnlineMs": c.LastOnlineAt, "lastOfflineMs": c.LastOfflineAt,
		"screenSources": h.screenSourcesJSON(c.ID),
	}
}

func (h *Hub) broadcastClientsListToAdmins(ctx context.Context, orgID int64) error {
	rows, err := h.db.GetClientsForOrg(ctx, orgID)
	if err != nil {
		return err
	}
	clients := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		clients = append(clients, h.mapAdminClientRow(c))
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, conn := range h.conns {
		if conn.kind != KindAdmin || conn.admin == nil {
			continue
		}
		if (conn.admin.Role == "org_admin" || conn.admin.Role == "it_ops") && conn.admin.OrgID != orgID {
			continue
		}
		out := clients
		if conn.admin.Role == "it_ops" {
			filtered := make([]map[string]any, 0)
			for _, c := range clients {
				if c["status"] == "sharing" {
					filtered = append(filtered, c)
				}
			}
			out = filtered
		}
		if conn.admin.Role == "org_admin" || conn.admin.Role == "it_ops" {
			out = h.filterClientsByAuditGroupOrgAdminScope(ctx, conn.admin.AdminID, conn.admin.OrgID, out)
		}
		h.sendConn(conn, map[string]any{"type": "admin-clients-updated", "success": true, "orgId": orgID, "clients": out})
	}
	return nil
}

func (h *Hub) handleIcePathReport(ctx context.Context, socketID string, conn *Conn, msg map[string]any) {
	sid, _ := toInt64(msg["sessionId"])
	cid, _ := toInt64(msg["clientId"])
	if conn.client != nil {
		cid = conn.client.ID
	}
	if sid <= 0 || cid <= 0 {
		return
	}
	row, _ := h.db.GetViewingSessionForClient(ctx, sid, cid)
	if row == nil {
		return
	}
	usingTurn, _ := msg["usingTurn"].(bool)
	_ = h.db.RecordIcePathReport(ctx, sid, cid, nil, map[string]any{
		"localType": msg["localType"], "remoteType": msg["remoteType"], "usingTurn": usingTurn,
		"timeToIceMs": msg["timeToIceMs"], "candidateType": msg["candidateType"], "phase": msg["phase"], "rtt": msg["rtt"],
	})
	phase, _ := toInt64(msg["phase"])
	if !usingTurn && phase == 1 && conn.kind == KindAdmin {
		plan := h.ice.SessionPlan(ctx, ice.SessionInput{
			ClientViewerCount:      h.countClientViewersByClientID(cid),
			AdminViewerTargetCount: h.countAdminTargets(socketID),
			ForceTurn:              true,
		})
		h.sendConn(conn, map[string]any{
			"type": "stream-transport-hint", "sessionId": sid, "clientId": cid,
			"reason": "p2p_phase1_failed", "streamTransport": plan.ToMap(),
		})
	}
}

func (h *Hub) handleStreamTransportUpgrade(ctx context.Context, socketID string, conn *Conn, msg map[string]any) {
	if conn.kind != KindAdmin && conn.kind != KindClient {
		return
	}
	cid, _ := toInt64(msg["clientId"])
	hasRelay := false
	if conn.admin != nil {
		if grant, _ := h.db.GetActiveStreamRelay(ctx, conn.admin.AdminID); grant != nil {
			hasRelay = true
		}
	}
	plan := h.ice.SessionPlan(ctx, ice.SessionInput{
		ClientViewerCount:      h.countClientViewersByClientID(cid),
		AdminViewerTargetCount: h.countAdminTargets(socketID),
		HasStreamRelayGrant:    hasRelay,
		ForceTurn:              true,
	})
	h.sendConn(conn, map[string]any{
		"type":            "stream-transport-upgrade",
		"success":         true,
		"streamTransport": plan.ToMap(),
	})
}

func (h *Hub) auditProxyList(ctx context.Context, conn *Conn, msg map[string]any) {
	ipc := asNonEmptyString(msg["ipcCorrId"], 64)
	admin := h.requireAdmin(ctx, conn, msg)
	if admin == nil || admin.Role != "super_admin" {
		h.sendConn(conn, map[string]any{"type": "admin-audit-org-access-list-response", "success": false, "error": "FORBIDDEN", "ipcCorrId": ipc})
		return
	}
	if !h.audit.Configured {
		h.sendConn(conn, map[string]any{"type": "admin-audit-org-access-list-response", "success": false, "error": "AUDIT_PROXY_NOT_CONFIGURED", "ipcCorrId": ipc})
		return
	}
	q := ""
	if st := asNonEmptyString(msg["status"], 32); st != "" {
		q = "?status=" + st
	}
	ok, _, data, err := auditproxy.FetchJSON(ctx, h.audit, "/api/superadmin/audit-org-access"+q, http.MethodGet, nil)
	if err != nil || !ok {
		h.sendConn(conn, map[string]any{"type": "admin-audit-org-access-list-response", "success": false, "error": "AUDIT_PROXY_FETCH_FAILED", "ipcCorrId": ipc})
		return
	}
	reqs, _ := data["requests"].([]any)
	h.sendConn(conn, map[string]any{"type": "admin-audit-org-access-list-response", "success": true, "requests": reqs, "pendingCount": data["pendingCount"], "ipcCorrId": ipc})
}
