package jwktest

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// SignClaims mints a JWT whose payload is exactly claims, signed with this
// signer's key. Use it to forge subject/actor tokens with may_act, act chains,
// or cnf bindings for exchange-validator tests.
func (s *Signer) SignClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	b := jwt.NewBuilder()
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build claims: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(s.alg, s.private))
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}
	return string(signed)
}

// CnfBound returns claims with a cnf.jkt binding to boundKey's public key, for
// minting DPoP-bound subject tokens.
func CnfBound(t *testing.T, base map[string]any, boundKey *Signer) map[string]any {
	t.Helper()
	out := make(map[string]any, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out["cnf"] = map[string]any{"jkt": boundKey.Thumbprint(t)}
	return out
}

// ExchangeResponse is the RFC 8693 JSON the stub returns on success.
type ExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// ExchangeAS is an in-process token endpoint for exchange-client tests. It
// records the last form + headers and returns either a configured success body,
// a configured error, or a one-shot use_dpop_nonce challenge.
type ExchangeAS struct {
	mu          sync.Mutex
	server      *httptest.Server
	ok          ExchangeResponse
	errStatus   int
	errBody     string
	nonceOnce   bool // when true, first DPoP request gets 400 use_dpop_nonce
	nonceServed bool
	lastForm    url.Values
	lastDPoP    string
	lastAuth    string
}

func NewExchangeAS(t *testing.T) *ExchangeAS {
	t.Helper()
	as := &ExchangeAS{}
	as.server = httptest.NewServer(http.HandlerFunc(as.handle))
	t.Cleanup(as.server.Close)
	return as
}

func (as *ExchangeAS) handle(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	as.mu.Lock()
	as.lastForm = r.PostForm
	as.lastDPoP = r.Header.Get("DPoP")
	as.lastAuth = r.Header.Get("Authorization")
	servedNonce, wantNonce := as.nonceServed, as.nonceOnce
	errStatus, errBody, ok := as.errStatus, as.errBody, as.ok
	if wantNonce && !servedNonce {
		as.nonceServed = true
	}
	as.mu.Unlock()

	if wantNonce && !servedNonce {
		w.Header().Set("DPoP-Nonce", "srv-nonce-1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		return
	}
	if errStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(errStatus)
		_, _ = w.Write([]byte(errBody))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ok)
}

func (as *ExchangeAS) Respond(r ExchangeResponse) { as.mu.Lock(); as.ok = r; as.mu.Unlock() }
func (as *ExchangeAS) RespondError(status int, b string) {
	as.mu.Lock()
	as.errStatus, as.errBody = status, b
	as.mu.Unlock()
}
func (as *ExchangeAS) RequireNonceOnce()     { as.mu.Lock(); as.nonceOnce = true; as.mu.Unlock() }
func (as *ExchangeAS) TokenEndpoint() string { return as.server.URL + "/token" }
func (as *ExchangeAS) LastForm() url.Values {
	as.mu.Lock()
	defer as.mu.Unlock()
	out := make(url.Values, len(as.lastForm))
	for k, v := range as.lastForm {
		out[k] = slices.Clone(v)
	}
	return out
}
func (as *ExchangeAS) LastDPoP() string { as.mu.Lock(); defer as.mu.Unlock(); return as.lastDPoP }
func (as *ExchangeAS) LastAuthorization() string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.lastAuth
}

// PrivatePEM returns this signer's private key as PKCS#8 PEM, for feeding
// PrivateKeyJWTAuth / NewDPoPKey (which accept PEM or JWK private-key bytes).
func (s *Signer) PrivatePEM(t *testing.T) []byte {
	t.Helper()
	var rawKey any
	if err := jwk.Export(s.private, &rawKey); err != nil {
		t.Fatalf("raw key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rawKey)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
