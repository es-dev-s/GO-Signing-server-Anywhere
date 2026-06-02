package ice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RealtimeClient calls Cloudflare Realtime SFU (Connection API). Token stays on server.
type RealtimeClient struct {
	AppID  string
	Token  string
	client *http.Client
}

func NewRealtimeClient(appID, token string) *RealtimeClient {
	return &RealtimeClient{
		AppID:  strings.TrimSpace(appID),
		Token:  strings.TrimSpace(token),
		client: &http.Client{Timeout: 45 * time.Second},
	}
}

func (c *RealtimeClient) base() string {
	return fmt.Sprintf("https://rtc.live.cloudflare.com/v1/apps/%s", c.AppID)
}

func (c *RealtimeClient) post(ctx context.Context, path string, body any) (map[string]any, error) {
	return c.do(ctx, http.MethodPost, path, body)
}

func (c *RealtimeClient) put(ctx context.Context, path string, body any) (map[string]any, error) {
	return c.do(ctx, http.MethodPut, path, body)
}

func (c *RealtimeClient) do(ctx context.Context, method, path string, body any) (map[string]any, error) {
	if c.AppID == "" || c.Token == "" {
		return nil, fmt.Errorf("realtime sfu not configured")
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	if out == nil {
		out = map[string]any{}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return out, fmt.Errorf("realtime api %s %d: %s", path, res.StatusCode, truncate(string(raw), 300))
	}
	return out, nil
}

func (c *RealtimeClient) NewSession(ctx context.Context) (string, error) {
	out, err := c.post(ctx, "/sessions/new", nil)
	if err != nil {
		return "", err
	}
	sid, _ := out["sessionId"].(string)
	if sid == "" {
		return "", fmt.Errorf("missing sessionId")
	}
	return sid, nil
}

func (c *RealtimeClient) TracksNew(ctx context.Context, sessionID string, body map[string]any) (map[string]any, error) {
	return c.post(ctx, "/sessions/"+sessionID+"/tracks/new", body)
}

func (c *RealtimeClient) Renegotiate(ctx context.Context, sessionID string, body map[string]any) (map[string]any, error) {
	return c.put(ctx, "/sessions/"+sessionID+"/renegotiate", body)
}

func (c *RealtimeClient) TracksClose(ctx context.Context, sessionID string, body map[string]any) (map[string]any, error) {
	return c.put(ctx, "/sessions/"+sessionID+"/tracks/close", body)
}

func ClientTrackName(clientID int64) string {
	return fmt.Sprintf("client-%d-screen", clientID)
}
