package aoa

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/0ndreu/aoa/internal/jwktest"
)

func TestStaticKeySource_ReturnsSet(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	ks := &staticKeySource{set: s.PublicSet(t)}

	set, err := ks.setForKID(context.Background(), "kid-1")
	if err != nil {
		t.Fatalf("setForKID: %v", err)
	}
	if set.Len() != 1 {
		t.Errorf("set len = %d, want 1", set.Len())
	}
}

func TestRemoteKeySource_FetchesAndCaches(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	srv := jwktest.NewJWKSServer(t, s.PublicSet(t))
	rs := newRemoteKeySource(srv.URL(), 5*time.Minute)

	if _, err := rs.setForKID(context.Background(), "kid-1"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if _, err := rs.setForKID(context.Background(), "kid-1"); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if srv.Hits() != 1 {
		t.Errorf("JWKS fetched %d times, want 1 (second served from cache)", srv.Hits())
	}
}

func TestRemoteKeySource_RefreshOnceOnUnknownKID(t *testing.T) {
	s1 := jwktest.NewRSASigner(t, "kid-1")
	srv := jwktest.NewJWKSServer(t, s1.PublicSet(t))
	rs := newRemoteKeySource(srv.URL(), 5*time.Minute)

	if _, err := rs.setForKID(context.Background(), "kid-1"); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	s2 := jwktest.NewRSASigner(t, "kid-2")
	srv.SetKeys(s2.PublicSet(t))

	set, err := rs.setForKID(context.Background(), "kid-2")
	if err != nil {
		t.Fatalf("refresh lookup: %v", err)
	}
	if _, ok := set.LookupKeyID("kid-2"); !ok {
		t.Error("refreshed set missing kid-2")
	}
	if srv.Hits() != 2 {
		t.Errorf("hits = %d, want 2 (prime + one refresh)", srv.Hits())
	}
}

func TestRemoteKeySource_UnreachableErrors(t *testing.T) {
	rs := newRemoteKeySource("http://127.0.0.1:1/jwks.json", 5*time.Minute)
	if _, err := rs.setForKID(context.Background(), "kid-1"); err == nil {
		t.Fatal("expected error from unreachable JWKS")
	}
}

// Regression: when a refresh fails, joiners must not return the stale cached
// set as if the fetch succeeded. Otherwise concurrent requests get split
// outcomes: the leader returns 401 while joiners pass on stale keys.
func TestRemoteKeySource_FailedRefreshNoStaleLeak(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-old")
	rs := newRemoteKeySource("http://127.0.0.1:1/jwks.json", time.Minute)
	rs.set = s.PublicSet(t)
	rs.fetchedAt = time.Now().Add(-time.Hour) // stale -> forces a refresh

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := range errs {
		go func(i int) { defer wg.Done(); _, errs[i] = rs.setForKID(context.Background(), "kid-old") }(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e == nil {
			t.Errorf("caller %d got stale keys on a failed refresh; want error", i)
		}
	}
}

func TestRemoteKeySource_SingleFlight(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	srv := jwktest.NewJWKSServer(t, s.PublicSet(t))
	rs := newRemoteKeySource(srv.URL(), 5*time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = rs.setForKID(context.Background(), "kid-1") }()
	}
	wg.Wait()
	if srv.Hits() != 1 {
		t.Errorf("hits = %d, want 1 (concurrent lookups single-flighted)", srv.Hits())
	}
}
