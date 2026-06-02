package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateRemoteAccessRequest(ctx context.Context, adminID, orgID int64, requesterIP, reason string, durationHours int) (map[string]any, error) {
	var id int64
	var createdAt any
	err := s.pool.QueryRow(ctx, `
		INSERT INTO remote_access_requests (admin_id, org_id, requester_ip, reason, duration_hours, status)
		VALUES ($1,$2,$3,$4,$5,'pending') RETURNING id, created_at`,
		adminID, orgID, requesterIP, reason, durationHours).Scan(&id, &createdAt)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "created_at": createdAt}, nil
}

func (s *Store) ApproveRemoteAccessRequest(ctx context.Context, requestID, approvedBy int64) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE remote_access_requests SET status='approved', approved_by=$2, approved_at=NOW(),
		expires_at=NOW() + (duration_hours * INTERVAL '1 hour')
		WHERE id=$1 AND status='pending' RETURNING *`, requestID, approvedBy)
	if err != nil {
		return nil, err
	}
	return pgx.CollectOneRow(rows, pgx.RowToMap)
}

func (s *Store) DenyRemoteAccessRequest(ctx context.Context, requestID, approvedBy int64) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE remote_access_requests SET status='denied', approved_by=$2, approved_at=NOW()
		WHERE id=$1 AND status='pending' RETURNING *`, requestID, approvedBy)
	if err != nil {
		return nil, err
	}
	return pgx.CollectOneRow(rows, pgx.RowToMap)
}

func (s *Store) GetActiveRemoteAccess(ctx context.Context, adminID int64) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, admin_id, expires_at, duration_hours FROM remote_access_requests
		WHERE admin_id=$1 AND status='approved' AND expires_at > NOW()
		ORDER BY expires_at DESC LIMIT 1`, adminID)
	if err != nil {
		return nil, err
	}
	m, err := pgx.CollectOneRow(rows, pgx.RowToMap)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return m, err
}

func (s *Store) GetMyRemoteAccessRequests(ctx context.Context, adminID int64) ([]map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT * FROM remote_access_requests WHERE admin_id=$1 ORDER BY created_at DESC LIMIT 50`, adminID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToMap)
}

func (s *Store) GetAllPendingRemoteAccessRequests(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.*, a.username AS requester_name, a.role AS requester_role, o.name AS org_name
		FROM remote_access_requests r
		JOIN admins a ON a.id = r.admin_id
		JOIN organizations o ON o.id = r.org_id
		WHERE r.status='pending' ORDER BY r.created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToMap)
}

func (s *Store) ExpireRemoteAccessRequests(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE remote_access_requests SET status='expired'
		WHERE status='approved' AND expires_at <= NOW()`)
	return err
}

func (s *Store) CreateStreamRelayRequest(ctx context.Context, adminID, orgID int64, requesterIP, reason string, durationHours int) (map[string]any, error) {
	var id int64
	var createdAt any
	err := s.pool.QueryRow(ctx, `
		INSERT INTO stream_relay_requests (admin_id, org_id, requester_ip, reason, duration_hours, status)
		VALUES ($1,$2,$3,$4,$5,'pending') RETURNING id, created_at`,
		adminID, orgID, requesterIP, reason, durationHours).Scan(&id, &createdAt)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "created_at": createdAt}, nil
}

func (s *Store) ApproveStreamRelayRequest(ctx context.Context, requestID, approvedBy int64) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE stream_relay_requests SET status='approved', approved_by=$2, approved_at=NOW(),
		expires_at=NOW() + (duration_hours * INTERVAL '1 hour')
		WHERE id=$1 AND status='pending' RETURNING *`, requestID, approvedBy)
	if err != nil {
		return nil, err
	}
	return pgx.CollectOneRow(rows, pgx.RowToMap)
}

func (s *Store) DenyStreamRelayRequest(ctx context.Context, requestID, approvedBy int64) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE stream_relay_requests SET status='denied', approved_by=$2, approved_at=NOW()
		WHERE id=$1 AND status='pending' RETURNING *`, requestID, approvedBy)
	if err != nil {
		return nil, err
	}
	return pgx.CollectOneRow(rows, pgx.RowToMap)
}

func (s *Store) GetActiveStreamRelay(ctx context.Context, adminID int64) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT * FROM stream_relay_requests
		WHERE admin_id=$1 AND status='approved' AND expires_at > NOW()
		ORDER BY expires_at DESC LIMIT 1`, adminID)
	if err != nil {
		return nil, err
	}
	m, err := pgx.CollectOneRow(rows, pgx.RowToMap)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return m, err
}

func (s *Store) GetMyStreamRelayRequests(ctx context.Context, adminID int64) ([]map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT * FROM stream_relay_requests WHERE admin_id=$1 ORDER BY created_at DESC LIMIT 50`, adminID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToMap)
}

func (s *Store) GetAllPendingStreamRelayRequests(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.*, a.username AS requester_name, a.role AS requester_role, o.name AS org_name
		FROM stream_relay_requests r
		JOIN admins a ON a.id = r.admin_id
		JOIN organizations o ON o.id = r.org_id
		WHERE r.status='pending' ORDER BY r.created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToMap)
}

func (s *Store) ExpireStreamRelayRequests(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE stream_relay_requests SET status='expired'
		WHERE status='approved' AND expires_at <= NOW()`)
	return err
}

func (s *Store) GetClientRowByDeviceID(ctx context.Context, deviceID string) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, org_id, full_name FROM clients WHERE device_id=$1`, deviceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectOneRow(rows, pgx.RowToMap)
}

func (s *Store) GetClientIDByDeviceID(ctx context.Context, deviceID string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `SELECT id FROM clients WHERE device_id=$1 AND disabled=0`, deviceID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

func (s *Store) SyncClientSocketID(ctx context.Context, clientID int64, socketID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE clients SET socket_id=$1 WHERE id=$2`, socketID, clientID)
	return err
}

func (s *Store) DisableClient(ctx context.Context, clientID int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE clients SET disabled=1, status='offline', socket_id=NULL WHERE id=$1`, clientID)
	return err
}

func (s *Store) SetClientPendingOrg(ctx context.Context, clientID, orgID int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE clients SET pending_org_id=$1 WHERE id=$2`, orgID, clientID)
	return err
}

type CreateAdminResult struct {
	Success bool
	Error   string
	Message string
}

func (s *Store) CreateAdminAccount(ctx context.Context, orgID int64, username, fullName, password, role string) CreateAdminResult {
	var exists int
	_ = s.pool.QueryRow(ctx, `SELECT 1 FROM admins WHERE org_id=$1 AND username=$2`, orgID, username).Scan(&exists)
	if exists == 1 {
		return CreateAdminResult{Success: false, Error: "DUPLICATE", Message: "Username already exists"}
	}
	if err := s.CreateAdmin(ctx, orgID, username, fullName, password, role); err != nil {
		return CreateAdminResult{Success: false, Error: "DB_ERROR", Message: err.Error()}
	}
	return CreateAdminResult{Success: true}
}
