package config

import (
	"os"
	"strconv"
	"strings"
)

// Config mirrors Node signing-server env (see Signing server/.env.example).
type Config struct {
	Host string
	Port int

	WsConnectToken     string
	IngestTokenSecret  string
	IngestTokenTTLMs   int64
	AllowCallNoToken   bool

	DatabaseURL string
	PgPoolMax   int32
	PgPoolMin   int32
	PgSSL       bool

	EnforceTLS      bool
	AllowedOrigins  map[string]struct{}
	MaxConnections  int
	MaxPerIP        int

	HeartbeatCheckMs      int64
	ClientHeartbeatTimeoutMs int64
	WsPingIntervalMs      int64
	DeviceTakeoverCooldownMs int64

	MaxAdminViewerTargets int
	MaxViewersPerClient   int
	RateCapacity          float64
	RateRefillPerSec      float64

	EnableTaskbarTelemetry bool
	EnableTaskbarIngestLogs bool

	AuditDashboardURL            string
	AuditSuperadminServiceSecret string

	SeedSuperAdmin      bool
	BootstrapOrg        string
	BootstrapUsername   string
	BootstrapPassword   string
	BootstrapFullName   string

	WipeDBOnStart bool
	Production    bool

	// ICE (subset — full builder in internal/ice)
	IceServersJSON           string
	IceTurnSource            string
	CloudflareTurnKeyID       string
	CloudflareTurnKeyAPIToken string
	CloudflareTurnKeyID2      string
	CloudflareTurnKeyAPIToken2 string
	TurnStunURL              string
	TurnUDPURL               string
	TurnTCPURL               string
	TurnTLSURL               string
	TurnTLSTCPURL            string
	TurnUsername             string
	TurnCredential           string
	TurnSecret               string

	// Streaming transport policy (P2P → TURN → optional Cloudflare SFU)
	IcePhaseOneMs                    int
	StreamTurnViewerThreshold        int
	StreamTurnAdminTargetsThreshold  int
	StreamSFUViewerThreshold         int
	StreamSFUAdminTargetsThreshold   int
	EnableCloudflareSFU              bool
	CloudflareRealtimeAppID          string
	CloudflareRealtimeAPIToken       string
	CloudflareRealtimeAppID2         string
	CloudflareRealtimeAPIToken2      string
	MediaProviderCooldownMs          int
	MediaProviderProbeIntervalMs   int
}

func Load() Config {
	c := Config{
		Host: getenv("HOST", "0.0.0.0"),
		Port: getenvInt("PORT", 8085),

		WsConnectToken:    strings.TrimSpace(os.Getenv("WS_CONNECT_TOKEN")),
		IngestTokenSecret: firstNonEmpty(os.Getenv("INGEST_TOKEN_SECRET"), os.Getenv("CALL_EVENTS_SECRET")),
		IngestTokenTTLMs:  int64(getenvInt("INGEST_TOKEN_TTL_MS", 900000)),
		AllowCallNoToken:  truthy(os.Getenv("ALLOW_CALL_EVENTS_WITHOUT_TOKEN")),

		DatabaseURL: firstNonEmpty(os.Getenv("SUPABASE_DATABASE_URL"), os.Getenv("DATABASE_URL")),
		PgPoolMax:   int32(getenvInt("PG_POOL_MAX", 10)),
		PgPoolMin:   int32(getenvInt("PG_POOL_MIN", 0)),
		PgSSL:       truthy(os.Getenv("SUPABASE_REQUIRE_SSL")) || os.Getenv("PGSSLMODE") == "require",

		EnforceTLS:     truthy(os.Getenv("ENFORCE_TLS")),
		AllowedOrigins: parseOrigins(os.Getenv("ALLOWED_ORIGINS")),
		MaxConnections: getenvInt("MAX_CONNECTIONS", 4000),
		MaxPerIP:       getenvInt("MAX_PER_IP", 2000),

		HeartbeatCheckMs:         int64(getenvInt("HEARTBEAT_CHECK_INTERVAL_MS", 8000)),
		ClientHeartbeatTimeoutMs: int64(getenvInt("CLIENT_HEARTBEAT_TIMEOUT_MS", 90000)),
		WsPingIntervalMs:         int64(getenvInt("WS_PING_INTERVAL_MS", 25000)),
		DeviceTakeoverCooldownMs: int64(getenvInt("DEVICE_TAKEOVER_COOLDOWN_MS", 3000)),

		MaxAdminViewerTargets: getenvInt("MAX_ADMIN_VIEWER_TARGETS", 32),
		MaxViewersPerClient:   getenvInt("MAX_VIEWERS_PER_CLIENT", 8),
		RateCapacity:          float64(getenvInt("SIGNALING_RATE_CAPACITY", 300)),
		RateRefillPerSec:      float64(getenvInt("SIGNALING_RATE_REFILL_PER_SEC", 120)),

		EnableTaskbarTelemetry:  !falsy(os.Getenv("ENABLE_TASKBAR_TELEMETRY")),
		EnableTaskbarIngestLogs: truthy(os.Getenv("ENABLE_TASKBAR_INGEST_LOGS")),

		AuditDashboardURL:            strings.TrimSpace(os.Getenv("AUDIT_DASHBOARD_URL")),
		AuditSuperadminServiceSecret: strings.TrimSpace(os.Getenv("AUDIT_SUPERADMIN_SERVICE_SECRET")),

		SeedSuperAdmin:    truthy(os.Getenv("SEED_SUPER_ADMIN")),
		BootstrapOrg:      getenv("BOOTSTRAP_ADMIN_ORG", "default"),
		BootstrapUsername: getenv("BOOTSTRAP_ADMIN_USERNAME", "admin"),
		BootstrapPassword: getenv("BOOTSTRAP_ADMIN_PASSWORD", ""),
		BootstrapFullName: getenv("BOOTSTRAP_ADMIN_FULL_NAME", "Super Admin"),

		WipeDBOnStart: truthy(os.Getenv("SIGNALING_WIPE_DB")),
		Production:    os.Getenv("NODE_ENV") == "production" || truthy(os.Getenv("GO_ENV_PRODUCTION")),

		IceServersJSON:            firstNonEmpty(os.Getenv("ICE_SERVERS_JSON"), os.Getenv("ANYWHERE_ICE_SERVERS_JSON")),
		IceTurnSource:             strings.TrimSpace(os.Getenv("ICE_TURN_SOURCE")),
		CloudflareTurnKeyID:        strings.TrimSpace(os.Getenv("CLOUDFLARE_TURN_KEY_ID")),
		CloudflareTurnKeyAPIToken:  strings.TrimSpace(os.Getenv("CLOUDFLARE_TURN_KEY_API_TOKEN")),
		CloudflareTurnKeyID2:       strings.TrimSpace(os.Getenv("CLOUDFLARE_TURN_KEY_ID_2")),
		CloudflareTurnKeyAPIToken2: strings.TrimSpace(os.Getenv("CLOUDFLARE_TURN_KEY_API_TOKEN_2")),
		TurnStunURL:                 getenv("TURN_STUN_URL", ""),
		TurnUDPURL:                  getenv("TURN_UDP_URL", ""),
		TurnTCPURL:                  getenv("TURN_TCP_URL", ""),
		TurnTLSURL:                  getenv("TURN_TLS_URL", ""),
		TurnTLSTCPURL:               getenv("TURN_TLSTCP_URL", ""),
		TurnUsername:                getenv("TURN_USERNAME", ""),
		TurnCredential:              getenv("TURN_CREDENTIAL", ""),
		TurnSecret:                  getenv("TURN_SECRET", ""),

		IcePhaseOneMs:                   getenvInt("ICE_PHASE_ONE_MS", 5000),
		StreamTurnViewerThreshold:       getenvInt("STREAM_TURN_VIEWER_THRESHOLD", 2),
		StreamTurnAdminTargetsThreshold: getenvInt("STREAM_TURN_ADMIN_TARGETS_THRESHOLD", 4),
		StreamSFUViewerThreshold:        getenvInt("STREAM_SFU_VIEWER_THRESHOLD", 3),
		StreamSFUAdminTargetsThreshold:  getenvInt("STREAM_SFU_ADMIN_TARGETS_THRESHOLD", 8),
		EnableCloudflareSFU:        truthy(os.Getenv("ENABLE_CLOUDFLARE_SFU")),
		CloudflareRealtimeAppID:    strings.TrimSpace(os.Getenv("CLOUDFLARE_REALTIME_APP_ID")),
		CloudflareRealtimeAPIToken: strings.TrimSpace(firstNonEmpty(
			os.Getenv("CLOUDFLARE_REALTIME_API_TOKEN"),
			os.Getenv("CLOUDFLARE_CALLS_API_TOKEN"),
		)),
		CloudflareRealtimeAppID2: strings.TrimSpace(os.Getenv("CLOUDFLARE_REALTIME_APP_ID_2")),
		CloudflareRealtimeAPIToken2: strings.TrimSpace(firstNonEmpty(
			os.Getenv("CLOUDFLARE_REALTIME_API_TOKEN_2"),
			os.Getenv("CLOUDFLARE_CALLS_API_TOKEN_2"),
		)),
		MediaProviderCooldownMs:        getenvInt("MEDIA_PROVIDER_COOLDOWN_MS", 45000),
		MediaProviderProbeIntervalMs: getenvInt("MEDIA_PROVIDER_PROBE_INTERVAL_MS", 90000),
	}
	return c
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "on" || s == "yes"
}

func falsy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "0" || s == "false" || s == "off" || s == "no"
}

func parseOrigins(raw string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			m[p] = struct{}{}
		}
	}
	return m
}
