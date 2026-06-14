package aoa

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func challengeFor(t *testing.T, ae *authError, realm, resourceMeta string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
	defaultErrorHandler(realm, resourceMeta)(rr, req, ae)
	return rr.Code, rr.Header().Get("WWW-Authenticate")
}

func TestDefaultErrorHandler_NoToken_NoErrorCode(t *testing.T) {
	code, wa := challengeFor(t, errNoToken, "https://mcp.example.com",
		"https://mcp.example.com/.well-known/oauth-protected-resource")
	if code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", code)
	}
	if strings.Contains(wa, "error=") {
		t.Errorf("no-token challenge must omit error code: %q", wa)
	}
	if !strings.Contains(wa, `realm="https://mcp.example.com"`) {
		t.Errorf("missing realm: %q", wa)
	}
	if !strings.Contains(wa, `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`) {
		t.Errorf("missing resource_metadata: %q", wa)
	}
}

func TestDefaultErrorHandler_InvalidToken(t *testing.T) {
	code, wa := challengeFor(t, errInvalidToken("bad signature"), "realmX", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", code)
	}
	if !strings.Contains(wa, `error="invalid_token"`) {
		t.Errorf("missing error code: %q", wa)
	}
	if strings.Contains(wa, "resource_metadata") {
		t.Errorf("resource_metadata must be absent when not configured: %q", wa)
	}
}

func TestAuthError_Error(t *testing.T) {
	// authError is handed to ErrorHandler as a plain error, so the error
	// interface must produce a useful message for both the coded and the
	// no-code (no-token) cases.
	tests := []struct {
		name string
		ae   *authError
		want string
	}{
		{"no code", errNoToken, "aoa: unauthorized (401)"},
		{"coded", errInvalidToken("bad signature"), "aoa: invalid_token: bad signature"},
		{"insufficient scope", errInsufficientScope([]string{"mcp:read"}),
			"aoa: insufficient_scope: the request requires higher privileges than provided by the access token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ae.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultErrorHandler_InsufficientScope_403(t *testing.T) {
	code, wa := challengeFor(t, errInsufficientScope([]string{"mcp:read", "mcp:write"}), "realmX", "")
	if code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", code)
	}
	if !strings.Contains(wa, `error="insufficient_scope"`) {
		t.Errorf("missing error code: %q", wa)
	}
	if !strings.Contains(wa, `scope="mcp:read mcp:write"`) {
		t.Errorf("missing/space-joined scope param: %q", wa)
	}
}

func TestErrInvalidDPoPProof_PreservesReason(t *testing.T) {
	// the specific reason must be kept on the authError for the audit event,
	// while the client-facing description stays generic (no internal leakage).
	ae := errInvalidDPoPProof("htm mismatch")
	if ae.reason != "htm mismatch" {
		t.Errorf("reason = %q, want %q", ae.reason, "htm mismatch")
	}
	if strings.Contains(ae.description, "htm") {
		t.Errorf("description leaks internal reason: %q", ae.description)
	}
}

func TestBuildChallenge_DPoPAlgs(t *testing.T) {
	ae := errDPoPRequired([]string{"ES256", "RS256"})
	got := buildChallenge(ae, "realmX", "")
	if !strings.Contains(got, `algs="ES256 RS256"`) {
		t.Errorf("missing algs param: %q", got)
	}
	if strings.Contains(got, "error=") {
		t.Errorf("no-token DPoP challenge must omit error code: %q", got)
	}
}

func TestDefaultErrorHandler_UseDPoPNonce_SetsHeader(t *testing.T) {
	ae := errUseDPoPNonce([]string{"ES256"})
	ae.nonce = "nonce-abc"
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", nil)
	defaultErrorHandler("realmX", "")(rr, req, ae)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
	if rr.Header().Get("DPoP-Nonce") != "nonce-abc" {
		t.Errorf("missing DPoP-Nonce header: %q", rr.Header().Get("DPoP-Nonce"))
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		t.Errorf("missing use_dpop_nonce: %q", rr.Header().Get("WWW-Authenticate"))
	}
}

func TestDefaultErrorHandler_OptionalNoToken_BothChallenges(t *testing.T) {
	ae := errNoTokenDPoPOptional([]string{"ES256"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
	defaultErrorHandler("realmX", "")(rr, req, ae)
	vals := rr.Header().Values("WWW-Authenticate")
	if len(vals) != 2 {
		t.Fatalf("want 2 WWW-Authenticate headers, got %d: %v", len(vals), vals)
	}
	var hasBearer, hasDPoP bool
	for _, v := range vals {
		if strings.HasPrefix(v, "Bearer ") {
			hasBearer = true
		}
		if strings.HasPrefix(v, "DPoP ") {
			hasDPoP = true
		}
	}
	if !hasBearer || !hasDPoP {
		t.Errorf("want both Bearer and DPoP challenges, got %v", vals)
	}
}
