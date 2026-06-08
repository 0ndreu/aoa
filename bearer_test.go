package aoa

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0ndreu/aoa/internal/jwktest"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func okOpts(t *testing.T) BearerOpts {
	t.Helper()
	s := jwktest.NewRSASigner(t, "kid-1")
	return BearerOpts{
		Resource: "https://mcp.example.com",
		Issuer:   "https://idp.example.com",
		KeysJWKS: s.PublicJWKS(t),
	}
}

func TestRequireBearer_ConstructionErrors(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*BearerOpts)
	}{
		{"no key source", func(o *BearerOpts) { o.KeysJWKS = nil; o.JWKSURI = "" }},
		{"no audience config", func(o *BearerOpts) { o.Resource = ""; o.Audience = nil }},
		{"no issuer", func(o *BearerOpts) { o.Issuer = "" }},
		{"negative proof max age", func(o *BearerOpts) { o.DPoP = DPoPRequired; o.DPoPProofMaxAge = -time.Second }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := okOpts(t)
			tt.mut(&o)
			if _, err := RequireBearer(o); err == nil {
				t.Fatalf("expected construction error for %q", tt.name)
			}
		})
	}
}

func TestRequireBearer_ValidConstruction(t *testing.T) {
	if _, err := RequireBearer(okOpts(t)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveKeySource_HonorsJWKSCacheTTL(t *testing.T) {
	custom, err := resolveKeySource(BearerOpts{JWKSURI: "https://idp.example.com/jwks", JWKSCacheTTL: 30 * time.Second})
	if err != nil {
		t.Fatalf("resolveKeySource: %v", err)
	}
	rs, ok := custom.(*remoteKeySource)
	if !ok {
		t.Fatalf("want *remoteKeySource, got %T", custom)
	}
	if rs.ttl != 30*time.Second {
		t.Errorf("ttl = %v, want 30s", rs.ttl)
	}

	def, err := resolveKeySource(BearerOpts{JWKSURI: "https://idp.example.com/jwks"})
	if err != nil {
		t.Fatalf("resolveKeySource (default): %v", err)
	}
	if def.(*remoteKeySource).ttl != defaultJWKSTTL {
		t.Errorf("default ttl = %v, want %v", def.(*remoteKeySource).ttl, defaultJWKSTTL)
	}
}

func TestValidateBearerOpts(t *testing.T) {
	tests := []struct {
		name    string
		mut     func(*BearerOpts)
		wantErr bool
	}{
		{"valid", func(*BearerOpts) {}, false},
		{"no key source", func(o *BearerOpts) { o.KeysJWKS = nil; o.JWKSURI = "" }, true},
		{"no audience config", func(o *BearerOpts) { o.Resource = ""; o.Audience = nil }, true},
		{"no issuer", func(o *BearerOpts) { o.Issuer = "" }, true},
		{"dpop required now valid", func(o *BearerOpts) { o.DPoP = DPoPRequired }, false},
		{"negative proof max age", func(o *BearerOpts) { o.DPoP = DPoPRequired; o.DPoPProofMaxAge = -time.Second }, true},
		{"unsupported token lookup", func(o *BearerOpts) { o.TokenLookup = TokenLookup(99) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := okOpts(t)
			tt.mut(&o)
			err := validateBearerOpts(o)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q", tt.name)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.name, err)
			}
		})
	}
}

func protectedServer(t *testing.T, opts BearerOpts) *httptest.Server {
	t.Helper()
	guard, err := RequireBearer(opts)
	if err != nil {
		t.Fatalf("RequireBearer: %v", err)
	}
	h := guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Error("handler reached without claims in context")
		}
		_, _ = w.Write([]byte("hello " + claims.Subject))
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func doGet(t *testing.T, url, bearer string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	return resp
}

func TestPipeline_ValidToken_200(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t)}
	srv := protectedServer(t, opts)

	signed := s.Sign(t, jwt.NewBuilder().
		Subject("u1").Issuer("https://idp.example.com").
		Audience([]string{"https://mcp.example.com"}).
		Expiration(time.Now().Add(time.Hour)))
	resp := doGet(t, srv.URL, string(signed))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// F1 regression: many real IdPs publish JWKS keys without an "alg" member.
// aoa must still verify tokens against them (algorithm inferred from key type).
func TestPipeline_AlglessJWKS_200(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKSNoAlg(t)}
	srv := protectedServer(t, opts)

	signed := s.Sign(t, jwt.NewBuilder().
		Subject("u1").Issuer("https://idp.example.com").
		Audience([]string{"https://mcp.example.com"}).
		Expiration(time.Now().Add(time.Hour)))
	resp := doGet(t, srv.URL, string(signed))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alg-less JWKS rejected a valid token: status = %d, want 200", resp.StatusCode)
	}
}

func TestPipeline_NoToken_401_NoErrorCode(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t)}
	srv := protectedServer(t, opts)
	resp := doGet(t, srv.URL, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if strings.Contains(wa, "error=") {
		t.Errorf("missing-token challenge must omit error: %q", wa)
	}
	if !strings.Contains(wa, "resource_metadata=") {
		t.Errorf("expected resource_metadata hint: %q", wa)
	}
}

func TestPipeline_WrongIssuer_401(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t)}
	srv := protectedServer(t, opts)
	signed := s.Sign(t, jwt.NewBuilder().
		Subject("u1").Issuer("https://evil.example.com").
		Audience([]string{"https://mcp.example.com"}).
		Expiration(time.Now().Add(time.Hour)))
	resp := doGet(t, srv.URL, string(signed))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPipeline_RejectsNoneAlg(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t)}
	srv := protectedServer(t, opts)
	none := jwktest.NoneToken(`{"sub":"attacker","iss":"https://idp.example.com","aud":["https://mcp.example.com"]}`)
	resp := doGet(t, srv.URL, none)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("alg=none accepted! status = %d, want 401", resp.StatusCode)
	}
}

func TestPipeline_RejectsSymmetricAlg(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t)}
	srv := protectedServer(t, opts)
	hs := jwktest.HS256Token(t, []byte("guessed-secret"), jwt.NewBuilder().
		Subject("attacker").Issuer("https://idp.example.com").
		Audience([]string{"https://mcp.example.com"}).
		Expiration(time.Now().Add(time.Hour)))
	resp := doGet(t, srv.URL, hs)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("HS256 accepted! status = %d, want 401", resp.StatusCode)
	}
}

func signedFor(t *testing.T, s *jwktest.Signer, aud []string, scope string) string {
	t.Helper()
	b := jwt.NewBuilder().Subject("u1").Issuer("https://idp.example.com").
		Audience(aud).Expiration(time.Now().Add(time.Hour))
	if scope != "" {
		b = b.Claim("scope", scope)
	}
	return string(s.Sign(t, b))
}

func TestPipeline_AudienceMismatch_401(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t)}
	srv := protectedServer(t, opts)
	resp := doGet(t, srv.URL, signedFor(t, s, []string{"https://other.example.com"}, ""))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPipeline_AudienceViaExtraAudience_200(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{
		Resource: "https://mcp.example.com",
		Audience: []string{"https://legacy.example.com"},
		Issuer:   "https://idp.example.com", KeysJWKS: s.PublicJWKS(t),
	}
	srv := protectedServer(t, opts)
	resp := doGet(t, srv.URL, signedFor(t, s, []string{"https://legacy.example.com"}, ""))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestPipeline_InsufficientScope_403(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{
		Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t),
		RequiredScopes: []string{"mcp:read", "mcp:write"},
	}
	srv := protectedServer(t, opts)
	resp := doGet(t, srv.URL, signedFor(t, s, []string{"https://mcp.example.com"}, "mcp:read"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Errorf("missing insufficient_scope: %q", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestPipeline_AllScopesPresent_200(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{
		Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t),
		RequiredScopes: []string{"mcp:read"},
	}
	srv := protectedServer(t, opts)
	resp := doGet(t, srv.URL, signedFor(t, s, []string{"https://mcp.example.com"}, "mcp:read mcp:write"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestPipeline_ClaimValidatorRejects_401(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{
		Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t),
		ClaimValidator: func(*Claims) error { return errors.New("nope") },
	}
	srv := protectedServer(t, opts)
	resp := doGet(t, srv.URL, signedFor(t, s, []string{"https://mcp.example.com"}, ""))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

type captureEmitter struct{ events []Event }

func (c *captureEmitter) Emit(_ context.Context, e Event) { c.events = append(c.events, e) }

func TestPipeline_EmitsAuditEvents(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	cap := &captureEmitter{}
	opts := BearerOpts{
		Resource: "https://mcp.example.com", Issuer: "https://idp.example.com",
		KeysJWKS: s.PublicJWKS(t), AuditEmitter: cap,
	}
	srv := protectedServer(t, opts)

	doGet(t, srv.URL, signedFor(t, s, []string{"https://mcp.example.com"}, "")).Body.Close()
	doGet(t, srv.URL, "").Body.Close()

	if len(cap.events) != 2 {
		t.Fatalf("emitted %d events, want 2", len(cap.events))
	}
	if cap.events[0].Kind != EventTokenValidated || cap.events[0].Outcome != OutcomeAllow {
		t.Errorf("event 0 = %+v, want validated/allow", cap.events[0])
	}
	if cap.events[1].Kind != EventTokenRejected || cap.events[1].Outcome != OutcomeDeny {
		t.Errorf("event 1 = %+v, want rejected/deny", cap.events[1])
	}
	if cap.events[0].Resource != "https://mcp.example.com" {
		t.Errorf("event 0 missing resource: %+v", cap.events[0])
	}
}

// Regression: post-parse rejections (audience/scope/claim-validator) must carry
// the token's identity in the audit event so security teams can investigate
// blocked requests.
func TestPipeline_AuditCarriesIdentityOnPostParseReject(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	cap := &captureEmitter{}
	opts := BearerOpts{
		Resource: "https://mcp.example.com", Issuer: "https://idp.example.com",
		KeysJWKS: s.PublicJWKS(t), AuditEmitter: cap,
		RequiredScopes: []string{"mcp:admin"},
	}
	srv := protectedServer(t, opts)

	// valid signature & audience, but missing the required scope -> rejected
	// after jwt.Parse, when identity is known
	doGet(t, srv.URL, signedFor(t, s, []string{"https://mcp.example.com"}, "mcp:read")).Body.Close()

	if len(cap.events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(cap.events))
	}
	ev := cap.events[0]
	if ev.Error != "insufficient_scope" {
		t.Fatalf("event = %+v, want insufficient_scope", ev)
	}
	if ev.Subject != "u1" {
		t.Errorf("audit event missing subject: %+v", ev)
	}
	if ev.Issuer != "https://idp.example.com" {
		t.Errorf("audit event missing issuer: %+v", ev)
	}
	if len(ev.Audience) != 1 || ev.Audience[0] != "https://mcp.example.com" {
		t.Errorf("audit event missing audience: %+v", ev)
	}
	if len(ev.Scope) != 1 || ev.Scope[0] != "mcp:read" {
		t.Errorf("audit event missing granted scope: %+v", ev)
	}
}

// Regression: the "scope" claim may arrive as a JSON array (Azure AD, Auth0,
// RFC 8693 token exchange), not only a space-delimited string.
func TestPipeline_ScopeArrayForm_200(t *testing.T) {
	s := jwktest.NewRSASigner(t, "kid-1")
	opts := BearerOpts{
		Resource: "https://mcp.example.com", Issuer: "https://idp.example.com", KeysJWKS: s.PublicJWKS(t),
		RequiredScopes: []string{"mcp:read"},
	}
	srv := protectedServer(t, opts)
	signed := string(s.Sign(t, jwt.NewBuilder().
		Subject("u1").Issuer("https://idp.example.com").
		Audience([]string{"https://mcp.example.com"}).
		Claim("scope", []string{"mcp:read", "mcp:write"}).
		Expiration(time.Now().Add(time.Hour))))
	resp := doGet(t, srv.URL, signed)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("array-form scope rejected: status = %d, want 200", resp.StatusCode)
	}
}

func TestRequireBearer_DPoPModesConstruct(t *testing.T) {
	for _, mode := range []DPoPMode{DPoPOff, DPoPOptional, DPoPRequired} {
		o := okOpts(t)
		o.DPoP = mode
		if _, err := RequireBearer(o); err != nil {
			t.Fatalf("mode %d construction error: %v", mode, err)
		}
	}
}

func TestRequireBearer_EndToEndDPoP(t *testing.T) {
	// authorization server side: a signing key for access tokens, and a
	// client DPoP key the token is bound to via cnf.jkt.
	as := jwktest.NewRSASigner(t, "kid-as")
	clientKey := jwktest.NewECSigner(t, "")

	const resource = "https://mcp.example.com"
	const target = "https://mcp.example.com/mcp"

	mw, err := RequireBearer(BearerOpts{
		Resource: resource,
		Issuer:   "https://idp.example.com",
		KeysJWKS: as.PublicJWKS(t),
		DPoP:     DPoPRequired,
	})
	if err != nil {
		t.Fatalf("RequireBearer: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// mint a cnf-bound access token
	accessToken := string(as.Sign(t, jwt.NewBuilder().
		Issuer("https://idp.example.com").
		Audience([]string{resource}).
		Subject("user-1").
		Expiration(time.Now().Add(time.Hour)).
		Claim("cnf", map[string]any{"jkt": clientKey.Thumbprint(t)})))

	// valid DPoP request -> 200
	proof := clientKey.DPoPProof(t, jwktest.DPoPClaims{Method: "POST", HTU: target, ATH: athFor(accessToken)})
	r := httptest.NewRequest("POST", target, nil)
	r.Header.Set("Authorization", "DPoP "+accessToken)
	r.Header.Set("DPoP", proof)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid DPoP request = %d, want 200 (WWW-Authenticate: %q)", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}

	// same token presented as plain Bearer -> 401 DPoP challenge (downgrade defense)
	rb := httptest.NewRequest("POST", target, nil)
	rb.Header.Set("Authorization", "Bearer "+accessToken)
	rrb := httptest.NewRecorder()
	handler.ServeHTTP(rrb, rb)
	if rrb.Code != http.StatusUnauthorized {
		t.Fatalf("bound-token-as-Bearer = %d, want 401", rrb.Code)
	}
	if !strings.HasPrefix(rrb.Header().Get("WWW-Authenticate"), "DPoP ") {
		t.Errorf("want DPoP challenge, got %q", rrb.Header().Get("WWW-Authenticate"))
	}
}

// TestRequireBearer_DPoPOffRejectsBoundTokenAsBearer pins the load-bearing rule
// in DPoPOff (the default): a sender-constrained token (carrying cnf.jkt) is
// never accepted as a plain Bearer token, even when DPoP enforcement is off.
// an un-bound token must still be accepted as Bearer.
func TestRequireBearer_DPoPOffRejectsBoundTokenAsBearer(t *testing.T) {
	as := jwktest.NewRSASigner(t, "kid-as")
	clientKey := jwktest.NewECSigner(t, "")

	const resource = "https://mcp.example.com"
	const target = "https://mcp.example.com/mcp"

	mw, err := RequireBearer(BearerOpts{
		Resource: resource,
		Issuer:   "https://idp.example.com",
		KeysJWKS: as.PublicJWKS(t),
		DPoP:     DPoPOff, // default mode
	})
	if err != nil {
		t.Fatalf("RequireBearer: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	base := jwt.NewBuilder().
		Issuer("https://idp.example.com").
		Audience([]string{resource}).
		Subject("user-1").
		Expiration(time.Now().Add(time.Hour))

	// a cnf.jkt-bound token presented as plain Bearer -> 401 DPoP challenge,
	// even though the middleware is in DPoPOff.
	bound := string(as.Sign(t, jwt.NewBuilder().
		Issuer("https://idp.example.com").
		Audience([]string{resource}).
		Subject("user-1").
		Expiration(time.Now().Add(time.Hour)).
		Claim("cnf", map[string]any{"jkt": clientKey.Thumbprint(t)})))
	rb := httptest.NewRequest("POST", target, nil)
	rb.Header.Set("Authorization", "Bearer "+bound)
	rrb := httptest.NewRecorder()
	handler.ServeHTTP(rrb, rb)
	if rrb.Code != http.StatusUnauthorized {
		t.Fatalf("bound-token-as-Bearer in DPoPOff = %d, want 401", rrb.Code)
	}
	if !strings.HasPrefix(rrb.Header().Get("WWW-Authenticate"), "DPoP ") {
		t.Errorf("want DPoP challenge, got %q", rrb.Header().Get("WWW-Authenticate"))
	}

	// an un-bound token presented as plain Bearer -> 200
	unbound := string(as.Sign(t, base))
	ru := httptest.NewRequest("POST", target, nil)
	ru.Header.Set("Authorization", "Bearer "+unbound)
	rru := httptest.NewRecorder()
	handler.ServeHTTP(rru, ru)
	if rru.Code != http.StatusOK {
		t.Fatalf("un-bound Bearer in DPoPOff = %d, want 200", rru.Code)
	}
}
