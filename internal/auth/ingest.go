package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type IngestPayload struct {
	ClientID int64 `json:"clientId"`
	OrgID    int64 `json:"orgId"`
	Exp      int64 `json:"exp"`
}

func SignIngestToken(secret string, clientID, orgID int64, ttlMs int64) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("no ingest secret")
	}
	body, err := json.Marshal(IngestPayload{
		ClientID: clientID,
		OrgID:    orgID,
		Exp:      time.Now().UnixMilli() + ttlMs,
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(enc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return enc + "." + sig, nil
}

func VerifyIngestToken(secret, token string) (IngestPayload, error) {
	var out IngestPayload
	if secret == "" {
		return out, fmt.Errorf("NO_SECRET")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return out, fmt.Errorf("INVALID_PARTS")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return out, fmt.Errorf("SIGNATURE_MISMATCH")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return out, fmt.Errorf("DECODE")
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	if out.ClientID <= 0 || out.OrgID <= 0 {
		return out, fmt.Errorf("INVALID_IDS")
	}
	if out.Exp < time.Now().UnixMilli() {
		return out, fmt.Errorf("EXPIRED")
	}
	return out, nil
}
