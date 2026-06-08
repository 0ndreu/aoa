package aoa

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestInMemoryReplayCache_FirstSeenThenReplay(t *testing.T) {
	c := InMemoryReplayCache()
	exp := time.Now().Add(time.Minute)

	seen, err := c.Seen(context.Background(), "jti-1", exp)
	if err != nil || seen {
		t.Fatalf("first Seen = (%v, %v), want (false, nil)", seen, err)
	}
	seen, err = c.Seen(context.Background(), "jti-1", exp)
	if err != nil || !seen {
		t.Fatalf("replay Seen = (%v, %v), want (true, nil)", seen, err)
	}
}

func TestInMemoryReplayCache_ExpiredEntryNotReplay(t *testing.T) {
	c := InMemoryReplayCache()
	past := time.Now().Add(-time.Second) // already expired

	if seen, _ := c.Seen(context.Background(), "jti-x", past); seen {
		t.Fatal("first insert reported replay")
	}
	// same jti again: the prior entry has expired, so this is NOT a replay
	if seen, _ := c.Seen(context.Background(), "jti-x", time.Now().Add(time.Minute)); seen {
		t.Fatal("expired entry treated as replay")
	}
}

func TestMemReplay_SweepEvictsExpired(t *testing.T) {
	// a sweepEvery of 0 forces sweep to run on every call so the eviction loop
	// (delete expired keys) is exercised.
	m := &memReplay{seen: make(map[string]time.Time), sweepEvery: 0}
	// record a key that expires in the past
	if seen, _ := m.Seen(context.Background(), "stale", time.Now().Add(-time.Hour)); seen {
		t.Fatal("first insert reported replay")
	}
	// a later call triggers sweep, which must delete the stale entry
	if seen, _ := m.Seen(context.Background(), "fresh", time.Now().Add(time.Minute)); seen {
		t.Fatal("unexpected replay for fresh key")
	}
	m.mu.Lock()
	_, present := m.seen["stale"]
	m.mu.Unlock()
	if present {
		t.Error("sweep did not evict the expired entry")
	}
}

func TestInMemoryReplayCache_ConcurrentSingleWinner(t *testing.T) {
	c := InMemoryReplayCache()
	exp := time.Now().Add(time.Minute)
	var wg sync.WaitGroup
	var replays int32
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if seen, _ := c.Seen(context.Background(), "jti-race", exp); seen {
				mu.Lock()
				replays++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if replays != 49 {
		t.Errorf("replays = %d, want 49 (exactly one winner)", replays)
	}
}
