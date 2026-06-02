package ice

import (
	"context"
	"fmt"
	"strings"
)

// RealtimeOp runs one Connection API call against a lane-specific client.
type RealtimeOp func(ctx context.Context, rt *RealtimeClient) (map[string]any, error)

// RunRealtime tries provider lanes in order until one succeeds.
func (p *ProviderPool) RunRealtime(ctx context.Context, preferred ProviderLane, op RealtimeOp) (map[string]any, ProviderLane, error) {
	if p == nil || len(p.lanes) == 0 {
		return nil, 0, fmt.Errorf("no cloudflare realtime lanes configured")
	}
	var lastErr error
	for _, lane := range p.LaneOrder(preferred) {
		if !p.isUsable(lane) {
			continue
		}
		l := p.laneByID(lane)
		if l == nil || strings.TrimSpace(l.RealtimeAppID) == "" || strings.TrimSpace(l.RealtimeToken) == "" {
			continue
		}
		rt := p.RealtimeClient(lane)
		out, err := op(ctx, rt)
		if err != nil {
			lastErr = err
			p.MarkFailure(lane, err.Error())
			continue
		}
		p.MarkSuccess(lane)
		return out, lane, nil
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, fmt.Errorf("all realtime lanes unavailable")
}

// NewSessionFailover creates a Realtime session on the first healthy lane.
func (p *ProviderPool) NewSessionFailover(ctx context.Context, preferred ProviderLane) (sessionID string, lane ProviderLane, err error) {
	out, lane, err := p.RunRealtime(ctx, preferred, func(ctx context.Context, rt *RealtimeClient) (map[string]any, error) {
		sid, e := rt.NewSession(ctx)
		if e != nil {
			return nil, e
		}
		return map[string]any{"sessionId": sid}, nil
	})
	if err != nil {
		return "", 0, err
	}
	sid, _ := out["sessionId"].(string)
	if sid == "" {
		return "", 0, fmt.Errorf("missing sessionId")
	}
	return sid, lane, nil
}
