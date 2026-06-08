package aoa

import (
	"context"
	"maps"
	"sync"
	"time"
)

// DPoPReplayCache rejects replayed DPoP proofs by their jti. Implementations
// MUST be safe for concurrent use and MUST perform an atomic check-and-record:
// Seen returns (true, nil) if jti was already recorded and unexpired (a
// replay); otherwise it records jti with the given expiry and returns
// (false, nil). A non-nil error signals a backend failure; the middleware
// fails closed (rejects the request) in that case.
type DPoPReplayCache interface {
	Seen(ctx context.Context, jti string, exp time.Time) (bool, error)
}

// InMemoryReplayCache returns the default jti replay cache: a concurrency-safe
// TTL map. Single-instance only - for multi-instance deployments supply a
// distributed implementation (see examples/dpop-redis).
func InMemoryReplayCache() DPoPReplayCache {
	return &memReplay{seen: make(map[string]time.Time), sweepEvery: time.Minute}
}

type memReplay struct {
	mu         sync.Mutex
	seen       map[string]time.Time
	sweepEvery time.Duration
	lastSweep  time.Time
}

func (m *memReplay) Seen(_ context.Context, jti string, exp time.Time) (bool, error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(now)
	if e, ok := m.seen[jti]; ok && e.After(now) {
		return true, nil
	}
	m.seen[jti] = exp
	return false, nil
}

// sweep deletes expired entries, at most once per sweepEvery. Caller holds mu
func (m *memReplay) sweep(now time.Time) {
	if now.Sub(m.lastSweep) < m.sweepEvery {
		return
	}
	maps.DeleteFunc(m.seen, func(_ string, e time.Time) bool {
		return !e.After(now)
	})
	m.lastSweep = now
}
