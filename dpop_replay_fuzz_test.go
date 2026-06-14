package aoa

import (
	"context"
	"testing"
	"time"
)

// FuzzReplayCacheSeen checks the check-and-record invariant for arbitrary jti
// strings on a fresh cache: first sighting is new, immediate re-sighting is a
// replay. Must never panic.
func FuzzReplayCacheSeen(f *testing.F) {
	f.Add("jti-1")
	f.Add("")
	f.Add("\x00\xff")
	f.Fuzz(func(t *testing.T, jti string) {
		c := InMemoryReplayCache()
		ctx := context.Background()
		exp := time.Now().Add(time.Minute)

		seen1, err := c.Seen(ctx, jti, exp)
		if err != nil {
			t.Fatalf("first Seen(%q) error: %v", jti, err)
		}
		if seen1 {
			t.Fatalf("first Seen(%q) reported a replay", jti)
		}

		seen2, err := c.Seen(ctx, jti, exp)
		if err != nil {
			t.Fatalf("second Seen(%q) error: %v", jti, err)
		}
		if !seen2 {
			t.Fatalf("second Seen(%q) did not report a replay", jti)
		}
	})
}
