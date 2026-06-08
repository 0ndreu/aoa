package chiadapter_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/0ndreu/aoa"
	chiadapter "github.com/0ndreu/aoa/adapters/chi"
)

func TestMount_ServesMetadataAtWellKnownPath(t *testing.T) {
	meta := aoa.ProtectedResourceMetadata{Resource: "https://mcp.example.com"}
	r := chi.NewRouter()
	if err := chiadapter.Mount(r, meta, aoa.HandlerOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + aoa.WellKnownSuffix)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", resp.Header.Get("Content-Type"))
	}
}

func TestMount_ServesMetadataAtPathSuffix(t *testing.T) {
	meta := aoa.ProtectedResourceMetadata{Resource: "https://mcp.example.com/api/v1"}
	r := chi.NewRouter()
	if err := chiadapter.Mount(r, meta, aoa.HandlerOptions{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	srv := httptest.NewServer(r)
	defer srv.Close()

	wantPath := "/.well-known/oauth-protected-resource/api/v1"
	resp, err := http.Get(srv.URL + wantPath)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status at %q = %d, want 200", wantPath, resp.StatusCode)
	}

	// bare suffix is not where this resource's metadata lives
	resp404, err := http.Get(srv.URL + aoa.WellKnownSuffix)
	if err != nil {
		t.Fatalf("GET bare suffix: %v", err)
	}
	defer resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("bare suffix status = %d, want 404", resp404.StatusCode)
	}
}

func TestMount_RejectsInvalidMetadata(t *testing.T) {
	r := chi.NewRouter()
	err := chiadapter.Mount(r, aoa.ProtectedResourceMetadata{}, aoa.HandlerOptions{})
	if err == nil {
		t.Fatal("expected error from invalid metadata, got nil")
	}
}

func TestMount_PropagatesAllowInsecureLocalhost(t *testing.T) {
	meta := aoa.ProtectedResourceMetadata{Resource: "http://localhost:8080"}
	r := chi.NewRouter()
	if err := chiadapter.Mount(r, meta, aoa.HandlerOptions{}); err == nil {
		t.Fatal("expected strict validation error, got nil")
	}
	r2 := chi.NewRouter()
	if err := chiadapter.Mount(r2, meta, aoa.HandlerOptions{AllowInsecureLocalhost: true}); err != nil {
		t.Fatalf("unexpected error with opt-in: %v", err)
	}
}
