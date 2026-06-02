package ice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anywhere/signing-server-go/internal/config"
)

type ServerEntry struct {
	URLs       any    `json:"urls"`
	Username   string `json:"username,omitempty"`
	Credential string `json:"credential,omitempty"`
}

func MintTurnCredentials(secret string, ttlSec int) (username, credential string) {
	if secret == "" {
		return os.Getenv("TURN_USERNAME"), os.Getenv("TURN_CREDENTIAL")
	}
	exp := time.Now().Unix() + int64(ttlSec)
	username = fmt.Sprintf("%d:screenshare", exp)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username))
	credential = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return username, credential
}

func BuildHomeIceServers(cfg config.Config, username, credential string) []ServerEntry {
	var out []ServerEntry
	add := func(url string) {
		if strings.TrimSpace(url) == "" {
			return
		}
		out = append(out, ServerEntry{URLs: url, Username: username, Credential: credential})
	}
	add(cfg.TurnStunURL)
	add(cfg.TurnUDPURL)
	add(cfg.TurnTCPURL)
	add(cfg.TurnTLSURL)
	add(cfg.TurnTLSTCPURL)
	if len(out) == 0 && cfg.IceServersJSON != "" {
		var parsed struct {
			IceServers []ServerEntry `json:"iceServers"`
		}
		if json.Unmarshal([]byte(cfg.IceServersJSON), &parsed) == nil && len(parsed.IceServers) > 0 {
			return parsed.IceServers
		}
	}
	return out
}

// WelcomeIceServers is a sync fallback; prefer Manager.WelcomePlan in production.
func WelcomeIceServers(cfg config.Config) []ServerEntry {
	m := NewManager(cfg)
	return m.WelcomePlan().IceServersFull
}

func IsCloudflarePrimary(cfg config.Config) bool {
	return strings.EqualFold(cfg.IceTurnSource, "cloudflare") && cfg.CloudflareTurnKeyID != "" && cfg.CloudflareTurnKeyAPIToken != ""
}

func LogIceConfig(cfg config.Config, plan TransportPlan) {
	if cfg.Production {
		return
	}
	fmt.Printf("[ICE] mode=%s reason=%s stun=%d full=%d sfu=%v\n",
		plan.Mode, plan.Reason, len(plan.IceServersStun), len(plan.IceServersFull), plan.SFU != nil && plan.SFU.Enabled)
}
