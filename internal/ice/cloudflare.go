package ice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/anywhere/signing-server-go/internal/config"
)

func fetchCloudflareIceForLane(ctx context.Context, keyID, token string) ([]ServerEntry, error) {
	keyID = strings.TrimSpace(keyID)
	token = strings.TrimSpace(token)
	if keyID == "" || token == "" {
		return nil, nil
	}
	body := []byte(`{"ttl":86400}`)
	path := fmt.Sprintf("https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate-ice-servers", keyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("cloudflare ice http %d: %s", res.StatusCode, truncate(string(raw), 200))
	}
	var parsed struct {
		IceServers []ServerEntry `json:"iceServers"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	return filterPort53(parsed.IceServers), nil
}

// FetchCloudflareIceServers loads TURN ICE from the primary Cloudflare turn key (legacy).
func FetchCloudflareIceServers(ctx context.Context, cfg config.Config) ([]ServerEntry, error) {
	return fetchCloudflareIceForLane(ctx, cfg.CloudflareTurnKeyID, cfg.CloudflareTurnKeyAPIToken)
}

// FetchAllCloudflareIceServers merges TURN credentials from every configured lane (parallel relay candidates).
func FetchAllCloudflareIceServers(ctx context.Context, pool *ProviderPool) []ServerEntry {
	if pool == nil {
		return nil
	}
	var merged []ServerEntry
	for _, lane := range pool.Lanes() {
		entries, err := fetchCloudflareIceForLane(ctx, lane.TurnKeyID, lane.TurnKeyToken)
		if err != nil {
			pool.MarkFailure(lane.Lane, err.Error())
			continue
		}
		if len(entries) > 0 {
			pool.MarkSuccess(lane.Lane)
			merged = mergeIceLists(merged, entries)
		}
	}
	return merged
}

func filterPort53(entries []ServerEntry) []ServerEntry {
	var out []ServerEntry
	for _, e := range entries {
		urls := expandURLs(e.URLs)
		filtered := make([]string, 0, len(urls))
		for _, u := range urls {
			if strings.Contains(u, ":53") {
				continue
			}
			filtered = append(filtered, u)
		}
		if len(filtered) == 0 {
			continue
		}
		row := ServerEntry{URLs: filtered[0]}
		if len(filtered) > 1 {
			row.URLs = filtered
		}
		if e.Username != "" {
			row.Username = e.Username
		}
		if e.Credential != "" {
			row.Credential = e.Credential
		}
		out = append(out, row)
	}
	return out
}

func expandURLs(urls any) []string {
	switch u := urls.(type) {
	case string:
		if strings.TrimSpace(u) != "" {
			return []string{strings.TrimSpace(u)}
		}
	case []string:
		return u
	case []any:
		var out []string
		for _, x := range u {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

// MintSFUSessions creates Cloudflare Realtime SFU sessions when multi-viewer mode is active.
func MintSFUSessions(ctx context.Context, cfg config.Config, in SessionInput) (*SFUHint, error) {
	appID := strings.TrimSpace(cfg.CloudflareRealtimeAppID)
	token := strings.TrimSpace(cfg.CloudflareRealtimeAPIToken)
	if appID == "" || token == "" {
		return nil, fmt.Errorf("sfu not configured")
	}
	pub, err := cfNewSession(ctx, appID, token)
	if err != nil {
		return nil, err
	}
	sub, err := cfNewSession(ctx, appID, token)
	if err != nil {
		return nil, err
	}
	_ = in
	_ = pub
	_ = sub
	return &SFUHint{
		Enabled:             true,
		PublisherSessionID:  pub,
		SubscriberSessionID: sub,
	}, nil
}

func cfNewSession(ctx context.Context, appID, token string) (string, error) {
	url := fmt.Sprintf("https://rtc.live.cloudflare.com/v1/apps/%s/sessions/new", appID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("sessions/new http %d: %s", res.StatusCode, truncate(string(raw), 240))
	}
	var parsed struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	if parsed.SessionID == "" {
		return "", fmt.Errorf("empty sessionId")
	}
	return parsed.SessionID, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
