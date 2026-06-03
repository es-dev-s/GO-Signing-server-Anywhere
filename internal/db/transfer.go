package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type TransferRequestRow struct {
	ID                  int64
	ClientID            int64
	ClientFullName      string
	FromOrgID           int64
	FromOrgName         string
	ToOrgID             int64
	ToOrgName           string
	RequestedByAdminID  int64
	RequestedByFullName string
	ApprovedByAdminID   *int64
	ApprovedByFullName  *string
	Status              string
	CreatedAt           int64
	UpdatedAt           int64
}

func (s *Store) SetClientOrgNow(ctx context.Context, clientID, orgID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE clients SET org_id = $1, pending_org_id = NULL WHERE id = $2`,
		orgID, clientID)
	return err
}

// ResolvePendingTransfersForClient closes any open transfer requests after an immediate org move.
func (s *Store) ResolvePendingTransfersForClient(ctx context.Context, clientID, approvedByAdminID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE transfer_requests SET status = 'approved', approved_by_admin_id = $1, updated_at = $2
		 WHERE client_id = $3 AND status = 'pending'`,
		approvedByAdminID, nowMs(), clientID)
	return err
}

func (s *Store) GetOrganizationNameByID(ctx context.Context, orgID int64) (string, error) {
	var name string
	err := s.pool.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, orgID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return name, err
}

type CreateTransferResult struct {
	Success   bool
	RequestID int64
	Deduped   bool
	Error     string
	Message   string
}

func (s *Store) CreateTransferRequest(ctx context.Context, clientID, fromOrgID, toOrgID, requestedByAdminID int64) (CreateTransferResult, error) {
	if fromOrgID == toOrgID {
		return CreateTransferResult{Success: false, Error: "INVALID_INPUT", Message: "Source and target organizations must differ"}, nil
	}
	var pendingID int64
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM transfer_requests WHERE client_id = $1 AND status = 'pending' ORDER BY id DESC LIMIT 1`,
		clientID).Scan(&pendingID)
	if err == nil {
		return CreateTransferResult{Success: true, RequestID: pendingID, Deduped: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return CreateTransferResult{}, err
	}
	var existingID int64
	err = s.pool.QueryRow(ctx,
		`SELECT id FROM transfer_requests WHERE client_id = $1 AND to_org_id = $2 AND status = 'pending' ORDER BY id DESC LIMIT 1`,
		clientID, toOrgID).Scan(&existingID)
	if err == nil {
		return CreateTransferResult{Success: true, RequestID: existingID, Deduped: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return CreateTransferResult{}, err
	}
	t := nowMs()
	var id int64
	err = s.pool.QueryRow(ctx,
		`INSERT INTO transfer_requests (client_id, from_org_id, to_org_id, requested_by_admin_id, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'pending', $5, $5) RETURNING id`,
		clientID, fromOrgID, toOrgID, requestedByAdminID, t).Scan(&id)
	if err != nil {
		return CreateTransferResult{}, err
	}
	return CreateTransferResult{Success: true, RequestID: id, Deduped: false}, nil
}

func (s *Store) CreateTransferRequestApproved(ctx context.Context, clientID, fromOrgID, toOrgID, requestedByAdminID, approvedByAdminID int64) (CreateTransferResult, error) {
	t := nowMs()
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO transfer_requests (client_id, from_org_id, to_org_id, requested_by_admin_id, approved_by_admin_id, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, 'approved', $6, $6) RETURNING id`,
		clientID, fromOrgID, toOrgID, requestedByAdminID, approvedByAdminID, t).Scan(&id)
	if err != nil {
		return CreateTransferResult{}, err
	}
	return CreateTransferResult{Success: true, RequestID: id, Deduped: false}, nil
}

func (s *Store) GetTransferRequestByID(ctx context.Context, requestID int64) (*TransferRequestRow, error) {
	var r TransferRequestRow
	var approvedBy *int64
	var approvedName *string
	err := s.pool.QueryRow(ctx, `
		SELECT tr.id, tr.client_id, c.full_name, tr.from_org_id, tr.to_org_id,
		       tr.requested_by_admin_id, tr.approved_by_admin_id, tr.status,
		       COALESCE(tr.created_at, 0), COALESCE(tr.updated_at, 0)
		FROM transfer_requests tr
		JOIN clients c ON c.id = tr.client_id
		WHERE tr.id = $1`, requestID).Scan(
		&r.ID, &r.ClientID, &r.ClientFullName, &r.FromOrgID, &r.ToOrgID,
		&r.RequestedByAdminID, &approvedBy, &r.Status, &r.CreatedAt, &r.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.ApprovedByAdminID = approvedBy
	r.ApprovedByFullName = approvedName
	return &r, nil
}

func (s *Store) UpdateTransferRequestStatus(ctx context.Context, requestID int64, status string, approvedByAdminID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE transfer_requests SET status = $1, approved_by_admin_id = $2, updated_at = $3 WHERE id = $4`,
		status, approvedByAdminID, nowMs(), requestID)
	return err
}

func (s *Store) ListTransferRequests(ctx context.Context, role string, adminOrgID int64) ([]map[string]any, error) {
	const baseSelect = `
		SELECT
			tr.id,
			tr.client_id,
			c.full_name AS client_full_name,
			tr.from_org_id,
			ofrom.name AS from_org_name,
			tr.to_org_id,
			oto.name AS to_org_name,
			tr.requested_by_admin_id,
			a.full_name AS requested_by_full_name,
			tr.approved_by_admin_id,
			a2.full_name AS approved_by_full_name,
			tr.status,
			COALESCE(tr.created_at, 0) AS created_at,
			COALESCE(tr.updated_at, 0) AS updated_at
		FROM transfer_requests tr
		JOIN clients c ON c.id = tr.client_id
		JOIN organizations ofrom ON ofrom.id = tr.from_org_id
		JOIN organizations oto ON oto.id = tr.to_org_id
		JOIN admins a ON a.id = tr.requested_by_admin_id
		LEFT JOIN admins a2 ON a2.id = tr.approved_by_admin_id`

	var rows pgx.Rows
	var err error
	if role == "super_admin" || role == "it_ops" {
		rows, err = s.pool.Query(ctx, baseSelect+` ORDER BY tr.id DESC LIMIT 200`)
	} else {
		rows, err = s.pool.Query(ctx, baseSelect+`
			WHERE tr.from_org_id = $1 OR tr.to_org_id = $2
			ORDER BY tr.id DESC LIMIT 200`, adminOrgID, adminOrgID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, cid, fromID, toID, reqBy int64
		var clientName, fromName, toName, reqName, status string
		var approvedBy *int64
		var approvedName *string
		var createdAt, updatedAt int64
		if err := rows.Scan(&id, &cid, &clientName, &fromID, &fromName, &toID, &toName,
			&reqBy, &reqName, &approvedBy, &approvedName, &status, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		m := map[string]any{
			"id": id, "clientId": cid, "clientName": clientName,
			"fromOrgId": fromID, "fromOrgName": fromName,
			"toOrgId": toID, "toOrgName": toName,
			"requestedByAdminId": reqBy, "requestedByFullName": reqName,
			"status": status, "createdAt": createdAt, "updatedAt": updatedAt,
		}
		if approvedBy != nil {
			m["approvedByAdminId"] = *approvedBy
		}
		if approvedName != nil {
			m["approvedByFullName"] = *approvedName
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
