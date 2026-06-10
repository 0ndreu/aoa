package aoa

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// keySource returns the JWK set for a given key ID.
type keySource interface {
	setForKID(ctx context.Context, kid string) (jwk.Set, error)
}

type staticKeySource struct{ set jwk.Set }

func (s *staticKeySource) setForKID(context.Context, string) (jwk.Set, error) {
	return s.set, nil
}

// remoteKeySource fetches and caches a JWKS from a URI, refreshing on TTL
// expiry or unknown kid. Concurrent refreshes are single-flighted.
type remoteKeySource struct {
	uri    string
	ttl    time.Duration
	client *http.Client

	mu        sync.Mutex
	set       jwk.Set
	fetchedAt time.Time
	fetching  chan struct{} // non-nil while a fetch is in flight
	lastErr   error         // error from the most recent fetch; nil on success
}

func newRemoteKeySource(uri string, ttl time.Duration) *remoteKeySource {
	return &remoteKeySource{uri: uri, ttl: ttl, client: &http.Client{Timeout: 10 * time.Second}}
}

func (r *remoteKeySource) setForKID(ctx context.Context, kid string) (jwk.Set, error) {
	r.mu.Lock()
	cur := r.set
	stale := cur == nil || time.Since(r.fetchedAt) > r.ttl
	present := false
	if cur != nil {
		_, present = cur.LookupKeyID(kid)
	}
	r.mu.Unlock()

	if cur != nil && present && !stale {
		return cur, nil
	}
	return r.refresh(ctx)
}

// refresh fetches the JWKS once, sharing an in-flight fetch across callers
func (r *remoteKeySource) refresh(ctx context.Context) (jwk.Set, error) {
	r.mu.Lock()
	if r.fetching != nil {
		done := r.fetching
		r.mu.Unlock()
		<-done
		r.mu.Lock()
		set, err := r.set, r.lastErr
		r.mu.Unlock()
		// mirror the leader's outcome: if the in-flight fetch failed, every
		// joiner fails too. Otherwise some callers would pass on a stale set
		// while the leader returns 401, giving split outcomes for the same keys.
		if err != nil {
			return nil, fmt.Errorf("aoa: jwks refresh failed: %w", err)
		}
		return set, nil
	}
	done := make(chan struct{})
	r.fetching = done
	r.mu.Unlock()

	set, err := r.fetch(ctx)

	r.mu.Lock()
	if err == nil {
		r.set = set
		r.fetchedAt = time.Now()
	}
	r.lastErr = err
	r.fetching = nil
	r.mu.Unlock()
	close(done)

	if err != nil {
		return nil, err
	}
	return set, nil
}

func (r *remoteKeySource) fetch(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aoa: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aoa: jwks status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return jwk.Parse(body)
}
