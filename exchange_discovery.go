package aoa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// discovery resolves and caches an AS's token_endpoint from its RFC 8414
// metadata (/.well-known/oauth-authorization-server). One entry per issuer.
type discovery struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]string // issuer -> token_endpoint
}

func newDiscovery(c *http.Client) *discovery {
	if c == nil {
		c = http.DefaultClient
	}
	return &discovery{client: c, cache: map[string]string{}}
}

func (d *discovery) tokenEndpoint(ctx context.Context, issuer string) (string, error) {
	d.mu.Lock()
	if ep, ok := d.cache[issuer]; ok {
		d.mu.Unlock()
		return ep, nil
	}
	d.mu.Unlock()

	// metaURL is built by appending the well-known suffix to the issuer
	// (OIDC-Discovery style), which is what Keycloak/Auth0/Okta serve. The strict
	// RFC 8414 par.3.1 form for a path-bearing issuer inserts the suffix between host
	// and path; that variant is not attempted here. For such an AS, configure
	// ExchangeConfig.TokenEndpoint explicitly instead of Issuer.
	metaURL := strings.TrimRight(issuer, "/") + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("aoa: fetch AS metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("aoa: AS metadata status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var meta struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("aoa: parse AS metadata: %w", err)
	}
	if meta.TokenEndpoint == "" {
		return "", fmt.Errorf("aoa: AS metadata has no token_endpoint")
	}
	// RFC 8414 par.2: the issuer in the document must match the requested issuer.
	if meta.Issuer != issuer {
		return "", fmt.Errorf("aoa: AS metadata issuer %q != %q", meta.Issuer, issuer)
	}
	d.mu.Lock()
	d.cache[issuer] = meta.TokenEndpoint
	d.mu.Unlock()
	return meta.TokenEndpoint, nil
}
