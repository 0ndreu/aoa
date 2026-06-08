package aoa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/0ndreu/aoa/internal/jwktest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// signProofRaw signs payload as a dpop+jwt JWS, optionally omitting the jwk
// header - used to forge structural defects the normal minter can't produce.
func signProofRaw(t *testing.T, payload []byte, withJWK bool) []byte {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set("typ", "dpop+jwt")
	if withJWK {
		pub, _ := jwk.PublicKeyOf(priv)
		_ = hdr.Set("jwk", pub)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestParseAndVerifyProof_MissingJWK(t *testing.T) {
	raw := signProofRaw(t, []byte(`{"htm":"GET","htu":"https://x/y"}`), false)
	if _, err := parseAndVerifyProof(raw, allAlgs()); err == nil {
		t.Fatal("expected error for missing jwk header")
	}
}

func TestParseAndVerifyProof_NonJSONClaims(t *testing.T) {
	raw := signProofRaw(t, []byte("this is not json"), true)
	if _, err := parseAndVerifyProof(raw, allAlgs()); err == nil {
		t.Fatal("expected error for non-JSON proof claims")
	}
}

func TestParseAndVerifyProof_Garbage(t *testing.T) {
	if _, err := parseAndVerifyProof([]byte("not-a-jws-at-all"), allAlgs()); err == nil {
		t.Fatal("expected parse error for non-JWS input")
	}
}

func allAlgs() map[string]struct{} {
	return map[string]struct{}{"ES256": {}, "RS256": {}, "EdDSA": {}}
}

func TestParseAndVerifyProof_Valid(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	raw := s.DPoPProof(t, jwktest.DPoPClaims{
		Method: "POST", HTU: "https://mcp.example.com/mcp", ATH: "h", Nonce: "n",
	})
	p, err := parseAndVerifyProof([]byte(raw), allAlgs())
	if err != nil {
		t.Fatalf("parseAndVerifyProof: %v", err)
	}
	if p.htm != "POST" || p.htu != "https://mcp.example.com/mcp" || p.ath != "h" || p.nonce != "n" {
		t.Errorf("decoded claims wrong: %+v", p)
	}
	if p.jkt != s.Thumbprint(t) {
		t.Errorf("jkt = %q, want %q", p.jkt, s.Thumbprint(t))
	}
	if p.jti == "" {
		t.Error("jti empty")
	}
}

func TestParseAndVerifyProof_WrongTyp(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	raw := s.DPoPProof(t, jwktest.DPoPClaims{Method: "GET", HTU: "https://x/y", Typ: "JWT"})
	if _, err := parseAndVerifyProof([]byte(raw), allAlgs()); err == nil {
		t.Fatal("expected error for typ != dpop+jwt")
	}
}

func TestParseAndVerifyProof_AlgNotAllowed(t *testing.T) {
	s := jwktest.NewECSigner(t, "") // ES256
	raw := s.DPoPProof(t, jwktest.DPoPClaims{Method: "GET", HTU: "https://x/y"})
	only := map[string]struct{}{"RS256": {}} // ES256 excluded
	if _, err := parseAndVerifyProof([]byte(raw), only); err == nil {
		t.Fatal("expected error for disallowed alg")
	}
}

func TestParseAndVerifyProof_PrivateKeyInHeader(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	raw := s.DPoPProof(t, jwktest.DPoPClaims{Method: "GET", HTU: "https://x/y", EmbedPrivate: true})
	if _, err := parseAndVerifyProof([]byte(raw), allAlgs()); err == nil {
		t.Fatal("expected error for private key in jwk header")
	}
}

func TestParseAndVerifyProof_BadSignature(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	raw := s.DPoPProof(t, jwktest.DPoPClaims{Method: "GET", HTU: "https://x/y"})
	tampered := raw[:len(raw)-3] + "AAA" // corrupt the signature segment
	if _, err := parseAndVerifyProof([]byte(tampered), allAlgs()); err == nil {
		t.Fatal("expected error for bad signature")
	}
}
