package ice

// StreamMode selects the media path the signaling server recommends for a session.
type StreamMode string

const (
	ModeP2PPreferred StreamMode = "p2p-preferred" // STUN phase-1, TURN phase-2 on failure
	ModeTurnRelay    StreamMode = "turn-relay"    // Full ICE incl. TURN from the start
	ModeSFU          StreamMode = "sfu"           // Cloudflare Realtime SFU (multi-viewer)
)

// TransportPlan is sent to clients in welcome / connect / prepare-peer messages.
type TransportPlan struct {
	Version          int            `json:"version"`
	Mode             StreamMode     `json:"mode"`
	Reason           string         `json:"reason,omitempty"`
	PhaseOneMs       int            `json:"phaseOneMs"`
	IceServers       []ServerEntry  `json:"iceServers"`
	IceServersStun   []ServerEntry  `json:"iceServersStunOnly"`
	IceServersFull   []ServerEntry  `json:"iceServersFull"`
	ViewerCount      int            `json:"viewerCount,omitempty"`
	AdminTargetCount int            `json:"adminTargetCount,omitempty"`
	SFU              *SFUHint       `json:"sfu,omitempty"`
}

type SFUHint struct {
	Enabled             bool     `json:"enabled"`
	Role                string   `json:"role,omitempty"` // publisher | subscriber
	TrackName           string   `json:"trackName,omitempty"`
	PublisherSessionID  string   `json:"publisherSessionId,omitempty"`
	SubscriberSessionID string   `json:"subscriberSessionId,omitempty"`
	PublisherClientID   int64    `json:"publisherClientId,omitempty"`
	ProviderLane        int      `json:"providerLane,omitempty"`  // 1=primary CF, 2=secondary CF
	ProviderLanes       []int    `json:"providerLanes,omitempty"` // healthy lanes to try
	FallbackModes       []string `json:"fallbackModes,omitempty"`   // e.g. turn-relay, p2p-preferred
	StunURL             string   `json:"stunUrl,omitempty"`
}

// SessionInput drives per-connection stream policy.
type SessionInput struct {
	ClientViewerCount      int
	AdminViewerTargetCount int
	HasStreamRelayGrant    bool
	ForceTurn              bool
}
