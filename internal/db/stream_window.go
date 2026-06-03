package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/anywhere/signing-server-go/internal/streamwindow"
	"github.com/jackc/pgx/v5"
)

const orgAdminStreamWindowKey = "org_admin_stream_window"

func (s *Store) GetOrgAdminStreamWindow(ctx context.Context) (streamwindow.Policy, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM app_settings WHERE key = $1`, orgAdminStreamWindowKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return streamwindow.DefaultPolicy(), nil
	}
	if err != nil {
		return streamwindow.Policy{}, err
	}
	if len(raw) == 0 {
		return streamwindow.DefaultPolicy(), nil
	}
	var p streamwindow.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return streamwindow.DefaultPolicy(), nil
	}
	return p.Normalize(), nil
}

func (s *Store) SetOrgAdminStreamWindow(ctx context.Context, p streamwindow.Policy) (streamwindow.Policy, error) {
	p = p.Normalize()
	b, err := json.Marshal(p)
	if err != nil {
		return streamwindow.Policy{}, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO app_settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, orgAdminStreamWindowKey, string(b))
	return p, err
}
