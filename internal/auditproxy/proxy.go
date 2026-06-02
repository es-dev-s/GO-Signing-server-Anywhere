package auditproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/anywhere/signing-server-go/internal/config"
)

type Env struct {
	Origin     string
	Secret     string
	Configured bool
}

func FromConfig(cfg config.Config) Env {
	raw := strings.TrimSpace(cfg.AuditDashboardURL)
	secret := strings.TrimSpace(cfg.AuditSuperadminServiceSecret)
	origin := normalizeOrigin(raw)
	return Env{Origin: origin, Secret: secret, Configured: raw != "" && secret != ""}
}

func normalizeOrigin(raw string) string {
	s := strings.TrimSpace(strings.TrimSuffix(raw, "/"))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(s), "http://") || strings.HasPrefix(strings.ToLower(s), "https://") {
		return s
	}
	return "http://" + s
}

func FetchJSON(ctx context.Context, env Env, path, method string, body []byte) (ok bool, status int, data map[string]any, err error) {
	if env.Origin == "" {
		return false, 0, nil, fmt.Errorf("missing AUDIT_DASHBOARD_URL")
	}
	url := env.Origin + path
	if !strings.HasPrefix(path, "/") {
		url = env.Origin + "/" + path
	}
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return false, 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.Secret)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 45 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return false, 0, nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	data = map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &data)
	}
	return res.StatusCode >= 200 && res.StatusCode < 300, res.StatusCode, data, nil
}

func FormatNetworkError(err error) string {
	if err == nil {
		return "Unknown error"
	}
	return err.Error()
}
