package hub

import (
	"sync"
	"time"
)

type sfuPublisherState struct {
	SessionID    string
	TrackName    string
	ProviderLane int
	UpdatedAt    time.Time
}

type sfuRegistry struct {
	mu         sync.RWMutex
	publishers map[int64]*sfuPublisherState // client DB id
}

func newSfuRegistry() *sfuRegistry {
	return &sfuRegistry{publishers: make(map[int64]*sfuPublisherState)}
}

func (r *sfuRegistry) setPublisher(clientID int64, sessionID, trackName string, providerLane int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.publishers[clientID] = &sfuPublisherState{
		SessionID:    sessionID,
		TrackName:    trackName,
		ProviderLane: providerLane,
		UpdatedAt:    time.Now(),
	}
}

func (r *sfuRegistry) getPublisher(clientID int64) *sfuPublisherState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.publishers[clientID]
}

func (r *sfuRegistry) clearPublisher(clientID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.publishers, clientID)
}
