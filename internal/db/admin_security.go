package db

import (
	"context"
	"errors"

	"github.com/anywhere/signing-server-go/internal/auth"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetAdminByID(ctx context.Context, adminID int64) (*AdminRow, error) {
	var a AdminRow
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, username, full_name, role FROM admins WHERE id = $1`, adminID).
		Scan(&a.AdminID, &a.OrgID, &a.Username, &a.FullName, &a.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) ListResettableAdmins(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.org_id, o.name, a.username, a.full_name, a.role
		FROM admins a
		JOIN organizations o ON o.id = a.org_id
		WHERE a.role IN ('org_admin', 'super_admin')
		ORDER BY o.name, a.full_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, oid int64
		var orgName, u, f, r string
		if err := rows.Scan(&id, &oid, &orgName, &u, &f, &r); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "orgId": oid, "orgName": orgName,
			"username": u, "fullName": f, "role": r,
		})
	}
	return out, rows.Err()
}

func (s *Store) UpdateAdminPassword(ctx context.Context, adminID int64, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE admins SET password_hash = $1 WHERE id = $2`, hash, adminID)
	return err
}

func (s *Store) RevokeAllAdminSessions(ctx context.Context, adminID int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE admin_id = $1`, adminID)
	return err
}
