package aoa

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0ndreu/aoa/internal/jwktest"
)

// failingReplay always errors, to exercise the fail-closed path.
type failingReplay struct{}

func (failingReplay) Seen(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("backend down")
}

// dpopMW builds a minimal middleware in the given mode for stage-level tests.
func dpopMW(mode DPoPMode) *bearerMW {
	return &bearerMW{
		dpopMode:     mode,
		dpopAlgs:     map[string]struct{}{"ES256": {}, "RS256": {}, "EdDSA": {}},
		dpopAlgsList: []string{"ES256", "RS256", "EdDSA"},
		proofMaxAge:  60 * time.Second,
		skew:         60 * time.Second,
		replay:       InMemoryReplayCache(),
	}
}

const dpopTestURL = "https://mcp.example.com/mcp"

func TestVerifyDPoP_HappyPath(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	token := "access-token-abc"
	claims := &Claims{cnfJKT: s.Thumbprint(t)}
	proof := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token)})

	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Set("DPoP", proof)

	if ae := dpopMW(DPoPRequired).verifyDPoP(r, token, claims, "DPoP"); ae != nil {
		t.Fatalf("verifyDPoP = %v, want nil", ae)
	}
}

func TestVerifyDPoP_BoundTokenAsBearerRejected(t *testing.T) {
	claims := &Claims{cnfJKT: "some-thumbprint"} // bound token
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	// optional mode, presented as Bearer - must be rejected (downgrade defense)
	ae := dpopMW(DPoPOptional).verifyDPoP(r, "tok", claims, "Bearer")
	if ae == nil || ae.code != "invalid_token" {
		t.Fatalf("verifyDPoP = %v, want invalid_token reject", ae)
	}
}

func TestVerifyDPoP_OptionalUnboundBearerAccepted(t *testing.T) {
	claims := &Claims{} // un-bound token (no cnf.jkt)
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	if ae := dpopMW(DPoPOptional).verifyDPoP(r, "tok", claims, "Bearer"); ae != nil {
		t.Fatalf("verifyDPoP = %v, want nil (unbound Bearer ok in Optional)", ae)
	}
}

func TestVerifyDPoP_OptionalUnboundBearerWithStrayDPoPHeaderRejected(t *testing.T) {
	// an un-bound token presented as Bearer but carrying a stray DPoP header is
	// a scheme/proof mismatch and must be rejected (design pipeline step 0).
	s := jwktest.NewECSigner(t, "")
	claims := &Claims{} // un-bound
	proof := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL})
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Set("DPoP", proof)
	if ae := dpopMW(DPoPOptional).verifyDPoP(r, "tok", claims, "Bearer"); ae == nil {
		t.Fatal("Bearer scheme with a stray DPoP header must be rejected")
	}
}

func TestVerifyDPoP_RequiredBearerRejected(t *testing.T) {
	claims := &Claims{} // even un-bound: Required forbids Bearer
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	if ae := dpopMW(DPoPRequired).verifyDPoP(r, "tok", claims, "Bearer"); ae == nil {
		t.Fatal("Required mode must reject Bearer")
	}
}

func TestVerifyDPoP_ProofDefects(t *testing.T) {
	token := "access-token-abc"
	good := athFor(token)
	tests := []struct {
		name  string
		claim jwktest.DPoPClaims
	}{
		{"htm mismatch", jwktest.DPoPClaims{Method: "GET", HTU: dpopTestURL, ATH: good}},
		{"htu mismatch", jwktest.DPoPClaims{Method: "POST", HTU: "https://evil.example.com/mcp", ATH: good}},
		{"ath mismatch", jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: "wrong"}},
		{"stale iat", jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: good, IAT: time.Now().Add(-10 * time.Minute)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := jwktest.NewECSigner(t, "")
			claims := &Claims{cnfJKT: s.Thumbprint(t)}
			proof := s.DPoPProof(t, tt.claim)
			r := httptest.NewRequest("POST", dpopTestURL, nil)
			r.Header.Set("DPoP", proof)
			if ae := dpopMW(DPoPRequired).verifyDPoP(r, token, claims, "DPoP"); ae == nil {
				t.Fatalf("%s: expected rejection", tt.name)
			}
		})
	}
}

func TestVerifyDPoP_ThumbprintMismatch(t *testing.T) {
	token := "access-token-abc"
	signer := jwktest.NewECSigner(t, "") // proof signed by this key
	other := jwktest.NewECSigner(t, "")  // token bound to a DIFFERENT key
	claims := &Claims{cnfJKT: other.Thumbprint(t)}
	proof := signer.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token)})
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Set("DPoP", proof)
	if ae := dpopMW(DPoPRequired).verifyDPoP(r, token, claims, "DPoP"); ae == nil {
		t.Fatal("expected cnf.jkt thumbprint mismatch rejection")
	}
}

func TestVerifyDPoP_Replay(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	token := "access-token-abc"
	claims := &Claims{cnfJKT: s.Thumbprint(t)}
	mw := dpopMW(DPoPRequired)
	proof := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token), JTI: "fixed-jti"})

	r1 := httptest.NewRequest("POST", dpopTestURL, nil)
	r1.Header.Set("DPoP", proof)
	if ae := mw.verifyDPoP(r1, token, claims, "DPoP"); ae != nil {
		t.Fatalf("first use = %v, want nil", ae)
	}
	r2 := httptest.NewRequest("POST", dpopTestURL, nil)
	r2.Header.Set("DPoP", proof)
	if ae := mw.verifyDPoP(r2, token, claims, "DPoP"); ae == nil {
		t.Fatal("replayed proof (same jti) must be rejected")
	}
}

func TestVerifyDPoP_DPoPSchemeUnboundTokenRejected(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	token := "tok"
	claims := &Claims{} // un-bound token presented under the DPoP scheme
	proof := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token)})
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Set("DPoP", proof)
	if ae := dpopMW(DPoPRequired).verifyDPoP(r, token, claims, "DPoP"); ae == nil {
		t.Fatal("DPoP scheme with an un-bound token must be rejected")
	}
}

func TestVerifyDPoP_TwoDPoPHeadersRejected(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	token := "tok"
	claims := &Claims{cnfJKT: s.Thumbprint(t)}
	proof := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token)})
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Add("DPoP", proof)
	r.Header.Add("DPoP", proof) // two headers
	if ae := dpopMW(DPoPRequired).verifyDPoP(r, token, claims, "DPoP"); ae == nil {
		t.Fatal("more than one DPoP header must be rejected")
	}
}

func TestVerifyDPoP_UnparseableProofRejected(t *testing.T) {
	claims := &Claims{cnfJKT: "thumb"}
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Set("DPoP", "not-a-jws")
	if ae := dpopMW(DPoPRequired).verifyDPoP(r, "tok", claims, "DPoP"); ae == nil {
		t.Fatal("garbage DPoP proof must be rejected")
	}
}

func TestVerifyDPoP_ReplayBackendErrorFailsClosed(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	token := "tok"
	claims := &Claims{cnfJKT: s.Thumbprint(t)}
	mw := dpopMW(DPoPRequired)
	mw.replay = failingReplay{}
	proof := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token)})
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Set("DPoP", proof)
	ae := mw.verifyDPoP(r, token, claims, "DPoP")
	if ae == nil || ae.auditOutcome != OutcomeError {
		t.Fatalf("replay backend error must fail closed with Outcome=Error, got %v", ae)
	}
}

func TestVerifyDPoP_AlgNoneRejected(t *testing.T) {
	// a proof whose alg is not in the allowlist (here: HS256/none simulated via
	// an empty allowlist) must be rejected by parseAndVerifyProof.
	s := jwktest.NewECSigner(t, "")
	token := "tok"
	claims := &Claims{cnfJKT: s.Thumbprint(t)}
	mw := dpopMW(DPoPRequired)
	mw.dpopAlgs = map[string]struct{}{"RS256": {}} // ES256 excluded
	proof := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token)})
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Set("DPoP", proof)
	if ae := mw.verifyDPoP(r, token, claims, "DPoP"); ae == nil {
		t.Fatal("proof with a disallowed alg must be rejected")
	}
}

func TestRequestHTU_TrustForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest("POST", "http://internal-host/mcp", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "mcp.example.com")

	if got := requestHTU(r, false); got != "http://internal-host/mcp" {
		t.Errorf("trustFwd=false: htu = %q, want http://internal-host/mcp", got)
	}
	if got := requestHTU(r, true); got != "https://mcp.example.com/mcp" {
		t.Errorf("trustFwd=true: htu = %q, want https://mcp.example.com/mcp", got)
	}
}

func TestHTUEqual(t *testing.T) {
	if !htuEqual("https://Host.example.com/mcp", "https://host.example.com/mcp") {
		t.Error("scheme/host should compare case-insensitively")
	}
	if htuEqual("https://a/x", "https://a/y") {
		t.Error("different paths must not be equal")
	}
	if htuEqual("://bad-url", "https://a/x") {
		t.Error("an unparseable URL must not compare equal")
	}
}

func TestVerifyDPoP_NonceRequired(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	token := "access-token-abc"
	claims := &Claims{cnfJKT: s.Thumbprint(t)}
	mw := dpopMW(DPoPRequired)
	mw.nonce = NewDPoPNonceSource([]byte("secret"))

	// no nonce in the proof -> use_dpop_nonce + a fresh nonce to echo
	noNonce := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token)})
	r := httptest.NewRequest("POST", dpopTestURL, nil)
	r.Header.Set("DPoP", noNonce)
	ae := mw.verifyDPoP(r, token, claims, "DPoP")
	if ae == nil || ae.code != "use_dpop_nonce" || ae.nonce == "" {
		t.Fatalf("want use_dpop_nonce with a nonce, got %v", ae)
	}

	// retry with the issued nonce -> accepted
	withNonce := s.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: dpopTestURL, ATH: athFor(token), Nonce: ae.nonce})
	r2 := httptest.NewRequest("POST", dpopTestURL, nil)
	r2.Header.Set("DPoP", withNonce)
	if ae := mw.verifyDPoP(r2, token, claims, "DPoP"); ae != nil {
		t.Fatalf("retry with nonce = %v, want nil", ae)
	}
}
