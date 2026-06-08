package aoa

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewMetadataHandler_GET_ReturnsJSON(t *testing.T) {
	meta := ProtectedResourceMetadata{
		Resource:             "https://mcp.example.com",
		AuthorizationServers: []string{"https://idp.example.com"},
		ScopesSupported:      []string{"mcp:read"},
	}
	h, err := NewMetadataHandler(meta, HandlerOptions{})
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var got ProtectedResourceMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got.Resource != meta.Resource {
		t.Errorf("Resource = %q, want %q", got.Resource, meta.Resource)
	}
}

func TestNewMetadataHandler_RejectsInvalidMetadata(t *testing.T) {
	_, err := NewMetadataHandler(ProtectedResourceMetadata{}, HandlerOptions{})
	if err == nil {
		t.Fatal("expected error from invalid metadata, got nil")
	}
}

func TestNewMetadataHandler_NonGET_Returns405(t *testing.T) {
	h, err := NewMetadataHandler(ProtectedResourceMetadata{Resource: "https://mcp.example.com"}, HandlerOptions{})
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/.well-known/oauth-protected-resource", nil)
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want 405", method, rr.Code)
			}
			if got := rr.Header().Get("Allow"); got != "GET, HEAD" {
				t.Errorf("%s: Allow = %q, want GET, HEAD", method, got)
			}
		})
	}
}

func TestNewMetadataHandler_HEAD_ReturnsEmptyBody(t *testing.T) {
	h, err := NewMetadataHandler(ProtectedResourceMetadata{Resource: "https://mcp.example.com"}, HandlerOptions{})
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/.well-known/oauth-protected-resource", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD body length = %d, want 0", rr.Body.Len())
	}
}

func TestNewMetadataHandler_SetsCacheControl(t *testing.T) {
	h, err := NewMetadataHandler(ProtectedResourceMetadata{Resource: "https://mcp.example.com"}, HandlerOptions{})
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Cache-Control"); got == "" {
		t.Errorf("Cache-Control header missing")
	}
}

func TestNewMetadataHandler_CORS(t *testing.T) {
	meta := ProtectedResourceMetadata{Resource: "https://mcp.example.com"}

	t.Run("disabled_by_default", func(t *testing.T) {
		h, err := NewMetadataHandler(meta, HandlerOptions{})
		if err != nil {
			t.Fatalf("NewMetadataHandler: %v", err)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, WellKnownSuffix, nil)
		req.Header.Set("Origin", "https://client.example.com")
		h.ServeHTTP(rr, req)
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("CORS leaked when disabled: %q", got)
		}
	})

	t.Run("enabled_get_sets_origin", func(t *testing.T) {
		h, err := NewMetadataHandler(meta, HandlerOptions{EnableCORS: true})
		if err != nil {
			t.Fatalf("NewMetadataHandler: %v", err)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, WellKnownSuffix, nil)
		req.Header.Set("Origin", "https://client.example.com")
		h.ServeHTTP(rr, req)
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
		}
	})

	t.Run("enabled_options_preflight_204", func(t *testing.T) {
		h, err := NewMetadataHandler(meta, HandlerOptions{EnableCORS: true})
		if err != nil {
			t.Fatalf("NewMetadataHandler: %v", err)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodOptions, WellKnownSuffix, nil)
		req.Header.Set("Origin", "https://client.example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Errorf("OPTIONS status = %d, want 204", rr.Code)
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("ACAO = %q, want *", got)
		}
		if got := rr.Header().Get("Access-Control-Allow-Methods"); got == "" {
			t.Error("Access-Control-Allow-Methods missing")
		}
	})

	t.Run("disabled_options_falls_through_to_405", func(t *testing.T) {
		h, err := NewMetadataHandler(meta, HandlerOptions{})
		if err != nil {
			t.Fatalf("NewMetadataHandler: %v", err)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodOptions, WellKnownSuffix, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("OPTIONS status (CORS off) = %d, want 405", rr.Code)
		}
	})
}

func TestNewMetadataHandler_HandlerOptions(t *testing.T) {
	t.Run("custom_cache_control", func(t *testing.T) {
		meta := ProtectedResourceMetadata{Resource: "https://mcp.example.com"}
		h, err := NewMetadataHandler(meta, HandlerOptions{CacheControl: "no-store"})
		if err != nil {
			t.Fatalf("NewMetadataHandler: %v", err)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, WellKnownSuffix, nil)
		h.ServeHTTP(rr, req)
		if got := rr.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
	})

	t.Run("default_cache_control_when_empty", func(t *testing.T) {
		meta := ProtectedResourceMetadata{Resource: "https://mcp.example.com"}
		h, err := NewMetadataHandler(meta, HandlerOptions{})
		if err != nil {
			t.Fatalf("NewMetadataHandler: %v", err)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, WellKnownSuffix, nil)
		h.ServeHTTP(rr, req)
		if got := rr.Header().Get("Cache-Control"); got != "public, max-age=3600" {
			t.Errorf("Cache-Control = %q, want library default", got)
		}
	})

	t.Run("allow_insecure_localhost_passes_through_to_validate", func(t *testing.T) {
		meta := ProtectedResourceMetadata{Resource: "http://localhost:8080"}
		// without the opt, strict Validate rejects
		if _, err := NewMetadataHandler(meta, HandlerOptions{}); err == nil {
			t.Fatal("expected strict validation error, got nil")
		}
		// with the opt, accepted
		if _, err := NewMetadataHandler(meta, HandlerOptions{AllowInsecureLocalhost: true}); err != nil {
			t.Fatalf("unexpected error with opt-in: %v", err)
		}
	})
}

func TestMetadataPathFor(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     string
		wantErr  bool
	}{
		{name: "no_path", resource: "https://mcp.example.com", want: "/.well-known/oauth-protected-resource"},
		{name: "root_path", resource: "https://mcp.example.com/", want: "/.well-known/oauth-protected-resource"},
		{name: "single_segment", resource: "https://mcp.example.com/api", want: "/.well-known/oauth-protected-resource/api"},
		{name: "multi_segment", resource: "https://mcp.example.com/api/v1", want: "/.well-known/oauth-protected-resource/api/v1"},
		{name: "trailing_slash", resource: "https://mcp.example.com/api/", want: "/.well-known/oauth-protected-resource/api"},
		{name: "with_port", resource: "https://mcp.example.com:8443/api", want: "/.well-known/oauth-protected-resource/api"},
		{name: "not_absolute", resource: "/api", wantErr: true},
		{name: "garbage", resource: "://", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MetadataPathFor(tt.resource)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewMetadataHandler_ServedAtPathSuffixViaServeMux(t *testing.T) {
	meta := ProtectedResourceMetadata{Resource: "https://mcp.example.com/api/v1"}
	h, err := NewMetadataHandler(meta, HandlerOptions{})
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	path, err := MetadataPathFor(meta.Resource)
	if err != nil {
		t.Fatalf("MetadataPathFor: %v", err)
	}
	wantPath := "/.well-known/oauth-protected-resource/api/v1"
	if path != wantPath {
		t.Fatalf("MetadataPathFor returned %q, want %q", path, wantPath)
	}

	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// bare WellKnownSuffix should 404 (not registered)
	resp404, err := http.Get(srv.URL + WellKnownSuffix)
	if err != nil {
		t.Fatalf("GET bare suffix: %v", err)
	}
	defer resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("bare suffix status = %d, want 404 (handler should only be reachable at the suffixed path)", resp404.StatusCode)
	}
}

func TestNewMetadataHandler_MarshalError(t *testing.T) {
	// channels are not JSON-marshallable; Extra carries it through the merge
	// path in MarshalJSON, surfacing the marshal failure to NewMetadataHandler.
	meta := ProtectedResourceMetadata{
		Resource: "https://mcp.example.com",
		Extra:    map[string]any{"x_bad": make(chan int)},
	}
	if _, err := NewMetadataHandler(meta, HandlerOptions{}); err == nil {
		t.Fatal("expected marshal error, got nil")
	}
}
