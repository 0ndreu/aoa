// Package jwktest provides test-only helpers for generating keys, signing JWTs,
// and serving a JWKS over httptest. Not part of the public API.
package jwktest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Signer holds a private key and its kid for minting test tokens.
type Signer struct {
	kid     string
	alg     jwa.SignatureAlgorithm
	private jwk.Key
	public  jwk.Key
}

// NewRSASigner creates an RSA signer with the given kid.
func NewRSASigner(t *testing.T, kid string) *Signer {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("import priv: %v", err)
	}
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("public of: %v", err)
	}
	for _, k := range []jwk.Key{priv, pub} {
		_ = k.Set(jwk.KeyIDKey, kid)
		_ = k.Set(jwk.AlgorithmKey, jwa.RS256())
	}
	return &Signer{kid: kid, alg: jwa.RS256(), private: priv, public: pub}
}

// NewECSigner creates a P-256 / ES256 signer. kid may be "".
func NewECSigner(t *testing.T, kid string) *Signer {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}
	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("import priv: %v", err)
	}
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("public of: %v", err)
	}
	for _, k := range []jwk.Key{priv, pub} {
		if kid != "" {
			_ = k.Set(jwk.KeyIDKey, kid)
		}
		_ = k.Set(jwk.AlgorithmKey, jwa.ES256())
	}
	return &Signer{kid: kid, alg: jwa.ES256(), private: priv, public: pub}
}

// Thumbprint returns the base64url RFC 7638 SHA-256 thumbprint of the signer's
// public key. This is the value an authorization server puts in an access
// token's cnf.jkt to bind it to this key.
func (s *Signer) Thumbprint(t *testing.T) string {
	t.Helper()
	tp, err := s.public.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// DPoPClaims controls a forged DPoP proof. Zero values get sensible defaults
// (Typ="dpop+jwt", IAT=now, JTI=random). Set fields to forge specific defects.
type DPoPClaims struct {
	Method       string // htm
	HTU          string // htu
	ATH          string // ath; omitted from the proof if ""
	Nonce        string // nonce; omitted if ""
	JTI          string // defaults to a random value
	IAT          time.Time
	Typ          string // defaults to "dpop+jwt"
	EmbedPrivate bool   // when true, embed the PRIVATE key in the jwk header (a defect)
}

// DPoPProof mints a signed DPoP proof per c, signed with this signer's key and
// embedding its public key in the jwk header.
func (s *Signer) DPoPProof(t *testing.T, c DPoPClaims) string {
	t.Helper()
	iat := c.IAT
	if iat.IsZero() {
		iat = time.Now()
	}
	jti := c.JTI
	if jti == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatalf("rand jti: %v", err)
		}
		jti = base64.RawURLEncoding.EncodeToString(b[:])
	}
	payload := map[string]any{
		"jti": jti,
		"htm": c.Method,
		"htu": c.HTU,
		"iat": iat.Unix(),
	}
	if c.ATH != "" {
		payload["ath"] = c.ATH
	}
	if c.Nonce != "" {
		payload["nonce"] = c.Nonce
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	typ := c.Typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	embedded := s.public
	if c.EmbedPrivate {
		embedded = s.private
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set("typ", typ)
	_ = hdr.Set("jwk", embedded)
	signed, err := jws.Sign(body, jws.WithKey(s.alg, s.private, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return string(signed)
}

// PublicSet returns a jwk.Set containing this signer's public key.
func (s *Signer) PublicSet(t *testing.T) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	if err := set.AddKey(s.public); err != nil {
		t.Fatalf("add key: %v", err)
	}
	return set
}

// PublicJWKS returns this signer's public set marshaled as raw JWKS JSON,
// suitable for BearerOpts.KeysJWKS (which hides jwx from the public API).
func (s *Signer) PublicJWKS(t *testing.T) []byte {
	t.Helper()
	buf, err := json.Marshal(s.PublicSet(t)) // jwk.Set implements json.Marshaler
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return buf
}

// Sign builds and signs a JWT from the given builder, using this signer's key.
func (s *Signer) Sign(t *testing.T, b *jwt.Builder) []byte {
	t.Helper()
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), s.private))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// SignRaw signs an arbitrary header and payload, used to mint malformed or alg=none tokens.
func (s *Signer) SignRaw(t *testing.T, payload []byte) []byte {
	t.Helper()
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), s.private))
	if err != nil {
		t.Fatalf("jws sign: %v", err)
	}
	return signed
}

// JWKSServer serves the signer's public set at "/jwks.json". The served set can
// be swapped with SetKeys to simulate rotation. Close it via the returned func.
type JWKSServer struct {
	mu     sync.Mutex
	set    jwk.Set
	server *httptest.Server
	hits   int
}

// NewJWKSServer starts an httptest server serving set at /jwks.json.
func NewJWKSServer(t *testing.T, set jwk.Set) *JWKSServer {
	t.Helper()
	j := &JWKSServer{set: set}
	j.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		j.mu.Lock()
		defer j.mu.Unlock()
		j.hits++
		buf, err := json.Marshal(j.set) // jwk.Set implements json.Marshaler
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	}))
	t.Cleanup(j.server.Close)
	return j
}

// PublicJWKSNoAlg returns the public JWKS JSON with the per-key "alg" member
// removed, simulating the many real-world IdPs (Auth0, Okta, Azure AD,
// Keycloak) whose jwks_uri documents omit "alg". Used to verify aoa still
// accepts such keys (it infers the algorithm from the key type).
func (s *Signer) PublicJWKSNoAlg(t *testing.T) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(s.PublicJWKS(t), &doc); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if keys, ok := doc["keys"].([]any); ok {
		for _, k := range keys {
			if km, ok := k.(map[string]any); ok {
				delete(km, "alg")
			}
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return out
}

// URL is the JWKS endpoint.
func (j *JWKSServer) URL() string { return j.server.URL + "/jwks.json" }

// Hits returns how many times the JWKS endpoint was fetched.
func (j *JWKSServer) Hits() int { j.mu.Lock(); defer j.mu.Unlock(); return j.hits }

// SetKeys swaps the served key set (simulates rotation).
func (j *JWKSServer) SetKeys(set jwk.Set) { j.mu.Lock(); defer j.mu.Unlock(); j.set = set }

// Now is a fixed instant helper for building exp/nbf claims.
func Now() time.Time { return time.Now() }

// HS256Token mints a token signed with HMAC-SHA256 using secret. Used to verify
// that an RS256-configured resource server rejects symmetric-alg tokens
// (the classic RS256->HS256 key-confusion attack).
func HS256Token(t *testing.T, secret []byte, b *jwt.Builder) string {
	t.Helper()
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), secret))
	if err != nil {
		t.Fatalf("hs256 sign: %v", err)
	}
	return string(signed)
}

// NoneToken builds an unsecured ("alg":"none") JWT from raw JSON claims: an
// attacker token with no signature. Used to verify it is rejected.
func NoneToken(claimsJSON string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return hdr + "." + pl + "." // trailing dot: empty signature
}
