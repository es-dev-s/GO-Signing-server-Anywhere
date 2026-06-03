package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anywhere/signing-server-go/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func nowMs() int64 { return time.Now().UnixMilli() }

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, conn string, maxConns, minConns int32, ssl bool) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(conn)
	if err != nil {
		return nil, err
	}
	if maxConns < 1 {
		maxConns = 1
	}
	if maxConns > 15 {
		// Supabase session pooler (port 5432) hard-limits to pool_size (~15).
		maxConns = 15
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = minConns
	if cfg.MinConns > cfg.MaxConns {
		cfg.MinConns = cfg.MaxConns
	}
	if ssl {
		cfg.ConnConfig.TLSConfig = nil // use sslmode in URL or require from env
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func normalizeOrgName(input string) string {
	v := strings.TrimSpace(strings.ToLower(input))
	if v == "" {
		return ""
	}
	return v
}

func normalizeDisplayName(input string) string {
	v := strings.TrimSpace(input)
	if v == "" {
		return ""
	}
	return strings.Join(strings.Fields(v), " ")
}

func (s *Store) ResetAllOnStartup(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE clients SET status = 'offline', socket_id = NULL`)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE sessions SET status = 'ended', ended_at = $1 WHERE status IN ('pending','active')`, nowMs())
	return err
}

// SoftReconcileOnStartup ends in-flight WebRTC sessions and clears stale socket_id rows
// without marking every client offline (normal PM2 restarts should not blank the roster).
func (s *Store) SoftReconcileOnStartup(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET status = 'ended', ended_at = $1 WHERE status IN ('pending','active')`, nowMs())
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE clients SET socket_id = NULL WHERE socket_id IS NOT NULL`)
	return err
}

func (s *Store) SeedDefaultSuperAdmin(ctx context.Context, orgName, username, fullName, password string) error {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM admins`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	org, err := s.EnsureOrganization(ctx, orgName)
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO admins (org_id, username, full_name, password_hash, role) VALUES ($1,$2,$3,$4,'super_admin')`,
		org.ID, strings.ToLower(username), fullName, hash)
	return err
}

type Org struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type AdminRow struct {
	AdminID  int64  `json:"admin_id"`
	OrgID    int64  `json:"org_id"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

type ClientRow struct {
	ID             int64   `json:"id"`
	OrgID          int64   `json:"org_id"`
	FullName       string  `json:"full_name"`
	Status         string  `json:"status"`
	SocketID       *string `json:"socket_id"`
	OrgName        *string `json:"org_name"`
	ClaimedOrgName *string `json:"claimed_org_name"`
	LastHeartbeat  int64   `json:"last_heartbeat"`
	LastOnlineAt   *int64  `json:"last_online_at"`
	LastOfflineAt  *int64  `json:"last_offline_at"`
	Disabled       int     `json:"disabled"`
	DeviceID       *string `json:"device_id"`
}

func (s *Store) EnsureOrganization(ctx context.Context, orgName string) (Org, error) {
	norm := normalizeOrgName(orgName)
	if norm == "" {
		norm = "default"
	}
	var o Org
	err := s.pool.QueryRow(ctx, `SELECT id, name FROM organizations WHERE name = $1`, norm).Scan(&o.ID, &o.Name)
	if err == nil {
		return o, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return o, err
	}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO organizations (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id, name`,
		norm).Scan(&o.ID, &o.Name)
	return o, err
}

func (s *Store) GetOrganizationByName(ctx context.Context, orgName string) (*Org, error) {
	norm := normalizeOrgName(orgName)
	if norm == "" {
		return nil, nil
	}
	var o Org
	err := s.pool.QueryRow(ctx, `SELECT id, name FROM organizations WHERE name = $1`, norm).Scan(&o.ID, &o.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func (s *Store) GetOrganizationsWithAdmins(ctx context.Context) ([]Org, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT o.id, o.name FROM organizations o INNER JOIN admins a ON a.org_id = o.id ORDER BY o.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Name); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) GetOrganizations(ctx context.Context) ([]Org, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name FROM organizations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Name); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) GetAdminByOrgAndUsername(ctx context.Context, orgID int64, username string) (map[string]any, error) {
	var id, oid int64
	var un, fn, ph, role string
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, username, full_name, password_hash, role FROM admins WHERE org_id = $1 AND username = $2`,
		orgID, strings.ToLower(username)).Scan(&id, &oid, &un, &fn, &ph, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "org_id": oid, "username": un, "full_name": fn, "password_hash": ph, "role": role}, nil
}

func (s *Store) VerifyAdminPassword(stored, password string) bool {
	return auth.VerifyPassword(password, stored)
}

type SessionToken struct {
	Token     string
	ExpiresAt int64
}

func (s *Store) CreateAdminSession(ctx context.Context, adminID int64) (SessionToken, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	exp := nowMs() + int64(50*365*24*60*60*1000)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO admin_sessions (admin_id, token, expires_at) VALUES ($1,$2,$3)`,
		adminID, token, exp)
	return SessionToken{Token: token, ExpiresAt: exp}, err
}

func (s *Store) GetAdminBySessionToken(ctx context.Context, token string) (*AdminRow, error) {
	var a AdminRow
	var exp int64
	err := s.pool.QueryRow(ctx, `
		SELECT a.id, a.org_id, a.username, a.full_name, a.role, s.expires_at
		FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
		WHERE s.token = $1`, token).Scan(&a.AdminID, &a.OrgID, &a.Username, &a.FullName, &a.Role, &exp)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if exp < nowMs() {
		return nil, nil
	}
	return &a, nil
}

func (s *Store) RevokeAdminSession(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE token = $1`, token)
	return err
}

func (s *Store) GetSocketIDForDevice(ctx context.Context, deviceID string) (*string, error) {
	var sid *string
	err := s.pool.QueryRow(ctx, `SELECT socket_id FROM clients WHERE device_id = $1`, deviceID).Scan(&sid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return sid, err
}

type UpsertClientResult struct {
	Success             bool
	Error               string
	Message             string
	Client              ClientRow
	ExtraBroadcastOrgID *int64
}

func (s *Store) UpsertClientAuth(ctx context.Context, deviceID, orgName, fullName, socketID string) (UpsertClientResult, error) {
	fn := normalizeDisplayName(fullName)
	if fn == "" || len(strings.TrimSpace(deviceID)) < 8 {
		return UpsertClientResult{Success: false, Error: "INVALID_INPUT", Message: "Invalid client identity"}, nil
	}
	dev := strings.TrimSpace(deviceID)
	org, err := s.GetOrganizationByName(ctx, orgName)
	if err != nil {
		return UpsertClientResult{}, err
	}
	if org == nil {
		o, e := s.EnsureOrganization(ctx, "default")
		if e != nil {
			return UpsertClientResult{}, e
		}
		org = &o
	}
	var existing ClientRow
	var pendingOrgID *int64
	var existingClaimed *string
	err = s.pool.QueryRow(ctx, `
		SELECT id, org_id, full_name, status, disabled, pending_org_id, claimed_org_name
		FROM clients WHERE device_id = $1`, dev).
		Scan(&existing.ID, &existing.OrgID, &existing.FullName, &existing.Status, &existing.Disabled, &pendingOrgID, &existingClaimed)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return UpsertClientResult{}, err
	}
	if err == nil && existing.Disabled == 1 {
		return UpsertClientResult{Success: false, Error: "CLIENT_DISABLED", Message: "Client has been disabled"}, nil
	}
	t := nowMs()
	requestedRaw := strings.TrimSpace(orgName)
	if err == nil {
		prevOrgID := existing.OrgID
		applyOrgID := existing.OrgID
		var claimed any
		if pendingOrgID != nil && *pendingOrgID > 0 {
			applyOrgID = *pendingOrgID
			claimed = nil
		} else if requestedRaw != "" {
			claimed = requestedRaw
		} else if existingClaimed != nil {
			claimed = *existingClaimed
		} else {
			claimed = nil
		}
		_, e := s.pool.Exec(ctx, `
			UPDATE clients SET org_id=$1, pending_org_id=NULL, full_name=$2, status='sharing', socket_id=$3,
				last_heartbeat=$4, last_online_at=COALESCE(last_online_at,$4), claimed_org_name=$5
			WHERE device_id=$6`,
			applyOrgID, fn, socketID, t, claimed, dev)
		if e != nil {
			return UpsertClientResult{}, e
		}
		existing.Status = "sharing"
		existing.FullName = fn
		existing.OrgID = applyOrgID
		res := UpsertClientResult{Success: true, Client: existing}
		if prevOrgID != applyOrgID {
			res.ExtraBroadcastOrgID = &prevOrgID
		}
		return res, nil
	}
	var id int64
	e := s.pool.QueryRow(ctx, `
		INSERT INTO clients (org_id, full_name, device_id, status, socket_id, last_heartbeat, disabled, last_online_at, claimed_org_name)
		VALUES ($1,$2,$3,'sharing',$4,$5,0,$5,$6) RETURNING id`,
		org.ID, fn, dev, socketID, t, strings.TrimSpace(orgName)).Scan(&id)
	if e != nil {
		return UpsertClientResult{Success: false, Error: "CONFLICT", Message: "Client identity conflict"}, nil
	}
	return UpsertClientResult{Success: true, Client: ClientRow{ID: id, OrgID: org.ID, FullName: fn, Status: "sharing"}}, nil
}

func (s *Store) UpdateClientHeartbeat(ctx context.Context, socketID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE clients SET last_heartbeat = $1 WHERE socket_id = $2`, nowMs(), socketID)
	return err
}

func (s *Store) SetClientOfflineBySocket(ctx context.Context, socketID string) (*ClientRow, error) {
	var c ClientRow
	err := s.pool.QueryRow(ctx, `SELECT id, full_name, org_id FROM clients WHERE socket_id = $1`, socketID).
		Scan(&c.ID, &c.FullName, &c.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t := nowMs()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `UPDATE clients SET status='offline', socket_id=NULL, last_offline_at=$1 WHERE socket_id=$2`, t, socketID)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE sessions SET status='ended', ended_at=$1 WHERE client_id=$2 AND status IN ('pending','active')`, nowMs(), c.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) CleanupStaleClients(ctx context.Context, timeoutMs int64) ([]ClientRow, error) {
	cutoff := nowMs() - timeoutMs
	rows, err := s.pool.Query(ctx, `
		SELECT id, full_name, socket_id, org_id FROM clients
		WHERE status != 'offline' AND last_heartbeat < $1 AND last_heartbeat > 0`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stale []ClientRow
	for rows.Next() {
		var c ClientRow
		var sid *string
		if err := rows.Scan(&c.ID, &c.FullName, &sid, &c.OrgID); err != nil {
			return nil, err
		}
		c.SocketID = sid
		stale = append(stale, c)
	}
	if len(stale) == 0 {
		return nil, rows.Err()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	gone := nowMs()
	_, err = tx.Exec(ctx, `
		UPDATE clients SET status='offline', socket_id=NULL, last_offline_at=$1
		WHERE status != 'offline' AND last_heartbeat < $2 AND last_heartbeat > 0`, gone, cutoff)
	if err != nil {
		return nil, err
	}
	for _, c := range stale {
		_, _ = tx.Exec(ctx, `UPDATE sessions SET status='ended', ended_at=$1 WHERE client_id=$2 AND status IN ('pending','active')`, nowMs(), c.ID)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return stale, rows.Err()
}

func (s *Store) scanClientRows(ctx context.Context, query string, args ...any) ([]ClientRow, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientRow
	for rows.Next() {
		var c ClientRow
		var on *string
		var con *string
		if err := rows.Scan(&c.ID, &c.FullName, &c.Status, &c.OrgID, &on, &con, &c.LastHeartbeat, &c.LastOnlineAt, &c.LastOfflineAt); err != nil {
			return nil, err
		}
		c.OrgName = on
		c.ClaimedOrgName = con
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetClientsForOrg(ctx context.Context, orgID int64) ([]ClientRow, error) {
	return s.scanClientRows(ctx, `
		SELECT c.id, c.full_name, c.status, c.org_id, o.name, c.claimed_org_name, c.last_heartbeat, c.last_online_at, c.last_offline_at
		FROM clients c JOIN organizations o ON o.id = c.org_id
		WHERE c.org_id = $1 AND c.disabled = 0
		ORDER BY CASE c.status WHEN 'sharing' THEN 0 WHEN 'online' THEN 1 ELSE 2 END, c.full_name`,
		orgID)
}

func (s *Store) GetAllClientsGrouped(ctx context.Context) ([]ClientRow, error) {
	return s.scanClientRows(ctx, `
		SELECT c.id, c.full_name, c.status, c.org_id, o.name, c.claimed_org_name, c.last_heartbeat, c.last_online_at, c.last_offline_at
		FROM clients c JOIN organizations o ON o.id = c.org_id
		WHERE c.disabled = 0
		ORDER BY o.name, CASE c.status WHEN 'sharing' THEN 0 WHEN 'online' THEN 1 ELSE 2 END, c.full_name`)
}

func (s *Store) GetClientByID(ctx context.Context, id int64) (*ClientRow, error) {
	rows, err := s.scanClientRows(ctx, `
		SELECT c.id, c.full_name, c.status, c.org_id, o.name, c.claimed_org_name, c.last_heartbeat, c.last_online_at, c.last_offline_at
		FROM clients c JOIN organizations o ON o.id = c.org_id WHERE c.id = $1`, id)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	c := rows[0]
	err = s.pool.QueryRow(ctx, `SELECT socket_id, disabled FROM clients WHERE id = $1`, id).Scan(&c.SocketID, &c.Disabled)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) FindOnlineClientByOrgAndFullName(ctx context.Context, orgID int64, fullName string) (*ClientRow, error) {
	c, err := s.GetClientByOrgAndFullName(ctx, orgID, fullName)
	if err != nil || c == nil {
		return nil, err
	}
	if c.Status == "offline" {
		return nil, nil
	}
	return c, nil
}

func (s *Store) GetClientByOrgAndFullName(ctx context.Context, orgID int64, fullName string) (*ClientRow, error) {
	fn := normalizeDisplayName(fullName)
	var c ClientRow
	var sid *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, full_name, status, socket_id, org_id, disabled FROM clients WHERE org_id=$1 AND full_name=$2 AND disabled=0`,
		orgID, fn).Scan(&c.ID, &c.FullName, &c.Status, &sid, &c.OrgID, &c.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	c.SocketID = sid
	return &c, err
}

func (s *Store) CreateSession(ctx context.Context, orgID, clientID int64, adminID *int64) (int64, error) {
	var sid int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sessions (org_id, client_id, admin_id, status) VALUES ($1,$2,$3,'pending') RETURNING id`,
		orgID, clientID, adminID).Scan(&sid)
	return sid, err
}

func (s *Store) GetAdminUiFeatures(ctx context.Context) (map[string]any, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM app_settings WHERE key = 'admin_ui_features'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func (s *Store) SetAdminUiFeaturesPatch(ctx context.Context, patch map[string]any) (map[string]any, error) {
	cur, _ := s.GetAdminUiFeatures(ctx)
	for k, v := range patch {
		cur[k] = v
	}
	b, _ := json.Marshal(cur)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO app_settings (key, value) VALUES ('admin_ui_features', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, string(b))
	return cur, err
}

func (s *Store) InsertCallEvent(ctx context.Context, clientID int64, typ, platform, occurredAt string, durationMs *int64) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO call_events (client_id, type, platform, occurred_at, duration_ms, received_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		clientID, typ, platform, occurredAt, durationMs, nowMs())
	return err
}

func (s *Store) GetOrganizationSummaries(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name FROM organizations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int64
		var name string
		_ = rows.Scan(&id, &name)
		out = append(out, map[string]any{"id": id, "name": name})
	}
	return out, rows.Err()
}

func (s *Store) GetOrgLeads(ctx context.Context, orgID *int64) ([]map[string]any, error) {
	q := `SELECT id, org_id, username, full_name, role FROM admins WHERE role IN ('org_admin','it_ops')`
	var rows pgx.Rows
	var err error
	if orgID != nil {
		rows, err = s.pool.Query(ctx, q+` AND org_id = $1`, *orgID)
	} else {
		rows, err = s.pool.Query(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, oid int64
		var u, f, r string
		_ = rows.Scan(&id, &oid, &u, &f, &r)
		out = append(out, map[string]any{"id": id, "orgId": oid, "username": u, "fullName": f, "role": r})
	}
	return out, rows.Err()
}

func (s *Store) RecordIcePathReport(ctx context.Context, sessionID, clientID int64, adminID *int64, fields map[string]any) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ice_path_reports (session_id, client_id, admin_id, local_type, remote_type, using_turn, time_to_ice_ms, candidate_type, phase, rtt_ms, reported_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		sessionID, clientID, adminID,
		fields["localType"], fields["remoteType"], fields["usingTurn"], fields["timeToIceMs"],
		fields["candidateType"], fields["phase"], fields["rtt"], nowMs())
	return err
}

func (s *Store) GetViewingSessionForClient(ctx context.Context, sessionID, clientID int64) (map[string]any, error) {
	var id, aid int64
	err := s.pool.QueryRow(ctx, `SELECT id, admin_id FROM sessions WHERE id=$1 AND client_id=$2`, sessionID, clientID).Scan(&id, &aid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return map[string]any{"id": id, "admin_id": aid}, err
}

func (s *Store) CreateAdmin(ctx context.Context, orgID int64, username, fullName, password, role string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO admins (org_id, username, full_name, password_hash, role) VALUES ($1,$2,$3,$4,$5)`,
		orgID, strings.ToLower(username), fullName, hash, role)
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE expires_at < $1`, nowMs())
	return err
}

var ErrNotImplemented = fmt.Errorf("not implemented in go port yet")
