package aoa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverTokenEndpoint(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		hits++
		_, _ = w.Write([]byte(`{"issuer":"` + issuerOf(r) + `","token_endpoint":"` + issuerOf(r) + `/oauth/token"}`))
	}))
	defer srv.Close()

	d := newDiscovery(http.DefaultClient)
	got, err := d.tokenEndpoint(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != srv.URL+"/oauth/token" {
		t.Fatalf("endpoint = %q", got)
	}
	// second call is cached
	if _, err := d.tokenEndpoint(context.Background(), srv.URL); err != nil {
		t.Fatalf("cached: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected 1 network hit (cached), got %d", hits)
	}
}

func issuerOf(r *http.Request) string { return "http://" + r.Host }
