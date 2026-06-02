package hub

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const maxMessageBytes = 64 * 1024
const maxHTTPBodyBytes = 256 * 1024

var webrtcRelayTypes = map[string]struct{}{
	"offer": {}, "answer": {}, "ice-candidate": {}, "client-ready": {},
	"request-offer": {}, "enable-client-media": {}, "client-screen-sources": {},
}

// highVolumeTypes are not rate-limited (streaming + transport control).
var highVolumeTypes = map[string]struct{}{
	"sfu-api":                          {},
	"sfu-register-publisher":           {},
	"media-provider-failed":            {},
	"request-stream-transport-upgrade": {},
	"ice-path-report":                  {},
}

func messageSkipsRateLimit(typ string) bool {
	if typ == "" || typ == "heartbeat" {
		return true
	}
	if _, ok := webrtcRelayTypes[typ]; ok {
		return true
	}
	_, ok := highVolumeTypes[typ]
	return ok
}

func genSocketID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func asNonEmptyString(v any, max int) string {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return ""
		}
		if len(s) > max {
			s = s[:max]
		}
		return s
	case float64:
		return asNonEmptyString(fmt.Sprint(int64(t)), max)
	default:
		return ""
	}
}

func asToken(v any) string {
	return asNonEmptyString(v, 512)
}

func msgType(msg map[string]any) string {
	return asNonEmptyString(msg["type"], 64)
}

func parseWorkstationIPs(raw any) []string {
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, x := range arr {
		s := asNonEmptyString(x, 64)
		if s == "" {
			continue
		}
		if z := strings.Index(s, "%"); z != -1 {
			s = s[:z]
		}
		s = strings.Trim(s, "[]")
		if len(s) < 3 {
			continue
		}
		out = append(out, s)
		if len(out) >= 32 {
			break
		}
	}
	return out
}

func toInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
