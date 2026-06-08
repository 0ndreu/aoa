package aoa

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0ndreu/aoa/internal/jwktest"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func newTestVerifier(t *testing.T, s *jwktest.Signer, iss string) *tokenVerifier {
	t.Helper()
	ks, err := resolveKeySource(BearerOpts{KeysJWKS: s.PublicJWKS(t), Issuer: iss, Resource: "x"})
	if err != nil {
		t.Fatalf("keysource: %v", err)
	}
	algs, _ := parseAlgs(nil)
	return &tokenVerifier{keys: ks, issuer: iss, skew: 60 * time.Second, algs: algs}
}

func TestTokenVerifier_ValidToken(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	iss := "https://idp.example.com"
	raw := s.Sign(t, jwt.NewBuilder().Subject("alice").Issuer(iss).Expiration(time.Now().Add(time.Hour)))
	v := newTestVerifier(t, s, iss)
	claims, ve := v.verify(context.Background(), string(raw))
	if ve != nil {
		t.Fatalf("verify: %v", ve)
	}
	if claims.Subject != "alice" {
		t.Fatalf("subject = %q", claims.Subject)
	}
}

func TestTokenVerifier_WrongIssuerRejected(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	raw := s.Sign(t, jwt.NewBuilder().Subject("alice").Issuer("https://evil.example.com").Expiration(time.Now().Add(time.Hour)))
	v := newTestVerifier(t, s, "https://idp.example.com")
	if _, ve := v.verify(context.Background(), string(raw)); ve == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestTokenVerifier_DisallowedAlg(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	v := newTestVerifier(t, s, "https://idp.example.com")
	_, ve := v.verify(context.Background(), jwktest.NoneToken(`{"sub":"x","iss":"https://idp.example.com"}`))
	if ve == nil || ve.kind != verifyDisallowedAlg {
		t.Fatalf("want verifyDisallowedAlg, got %v", ve)
	}
}

func TestTokenVerifier_JWKSErrorClassified(t *testing.T) {
	v := &tokenVerifier{keys: errKeySource{}, issuer: "https://idp.example.com", skew: 60 * time.Second}
	v.algs, _ = parseAlgs(nil)
	s := jwktest.NewRSASigner(t, "k1")
	raw := s.Sign(t, jwt.NewBuilder().Subject("a").Issuer("https://idp.example.com").Expiration(time.Now().Add(time.Hour)))
	_, ve := v.verify(context.Background(), string(raw))
	if ve == nil || ve.kind != verifyJWKS {
		t.Fatalf("want verifyJWKS, got %v", ve)
	}
}

func TestTokenVerifier_ExpiredClassified(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	iss := "https://idp.example.com"
	raw := s.Sign(t, jwt.NewBuilder().Subject("a").Issuer(iss).Expiration(time.Now().Add(-time.Hour)))
	v := newTestVerifier(t, s, iss)
	_, ve := v.verify(context.Background(), string(raw))
	if ve == nil || ve.kind != verifyInvalid {
		t.Fatalf("want verifyInvalid for expired token, got %v", ve)
	}
}

// errKeySource is a keySource stub that always fails, to exercise the verifyJWKS path.
type errKeySource struct{}

func (errKeySource) setForKID(ctx context.Context, kid string) (jwk.Set, error) {
	return nil, errors.New("simulated jwks failure")
}
