package ratelimit

import "time"

// TokenBucket matches Node signaling rate limiter.
type TokenBucket struct {
	capacity     float64
	refillPerSec float64
	tokens       float64
	last         time.Time
}

func New(capacity, refillPerSec float64) *TokenBucket {
	return &TokenBucket{
		capacity:     capacity,
		refillPerSec: refillPerSec,
		tokens:       capacity,
		last:         time.Now(),
	}
}

func (b *TokenBucket) Take(cost float64) bool {
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens = min(b.capacity, b.tokens+elapsed*b.refillPerSec)
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
