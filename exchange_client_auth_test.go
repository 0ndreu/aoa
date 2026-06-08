package aoa

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0ndreu/aoa/internal/jwktest"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func applyAuth(t *testing.T, ca ClientAuth) (*http.Request, url.Values) {
	t.Helper()
	form := url.Values{"grant_type": {"x"}}
	req, _ := http.NewRequest(http.MethodPost, "https://as.example.com/token", nil)
	if err := ca.apply(context.Background(), req, form); err != nil {
		t.Fatalf("apply: %v", err)
	}
	return req, form
}

func TestClientSecretBasic(t *testing.T) {
	req, form := applyAuth(t, ClientSecretAuth("cid", "secret", false))
	user, pass, ok := req.BasicAuth()
	if !ok || user != "cid" || pass != "secret" {
		t.Fatalf("basic auth wrong: %q %q %v", user, pass, ok)
	}
	if form.Get("client_id") != "" {
		t.Fatal("basic mode must not put client_id in the form")
	}
}

func TestClientSecretPost(t *testing.T) {
	req, form := applyAuth(t, ClientSecretAuth("cid", "secret", true))
	if _, _, ok := req.BasicAuth(); ok {
		t.Fatal("post mode must not set basic header")
	}
	if form.Get("client_id") != "cid" || form.Get("client_secret") != "secret" {
		t.Fatalf("post form wrong: %v", form)
	}
}

func TestPrivateKeyJWT(t *testing.T) {
	s := jwktest.NewECSigner(t, "k1")
	ca, err := PrivateKeyJWTAuth("cid", s.PrivatePEM(t), "ES256")
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}

	_, form := applyAuth(t, ca)

	if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("assertion type wrong: %s", form.Get("client_assertion_type"))
	}
	assertion := form.Get("client_assertion")
	if strings.Count(assertion, ".") != 2 {
		t.Fatalf("assertion not a JWS: %q", assertion)
	}

	// decode the assertion payload without verifying the signature to check
	// RFC 7523 claim values
	tok, err := jwt.ParseInsecure([]byte(assertion))
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}

	iss, ok := tok.Issuer()
	if !ok || iss != "cid" {
		t.Errorf("iss = %q (ok=%v), want %q", iss, ok, "cid")
	}

	sub, ok := tok.Subject()
	if !ok || sub != "cid" {
		t.Errorf("sub = %q (ok=%v), want %q", sub, ok, "cid")
	}

	aud, ok := tok.Audience()
	if !ok {
		t.Fatal("aud claim missing")
	}
	wantAud := "https://as.example.com/token"
	found := false
	for _, a := range aud {
		if a == wantAud {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("aud = %v, want to contain %q", aud, wantAud)
	}

	iat, ok := tok.IssuedAt()
	if !ok {
		t.Fatal("iat claim missing")
	}
	exp, ok := tok.Expiration()
	if !ok {
		t.Fatal("exp claim missing")
	}
	if diff := exp.Sub(iat); diff < 59*time.Second || diff > 61*time.Second {
		t.Errorf("exp - iat = %v, want ~60s", diff)
	}

	jti, ok := tok.JwtID()
	if !ok || jti == "" {
		t.Errorf("jti missing or empty (ok=%v, jti=%q)", ok, jti)
	}

	// second apply() call must produce a different jti (anti-replay property)
	_, form2 := applyAuth(t, ca)
	assertion2 := form2.Get("client_assertion")
	tok2, err := jwt.ParseInsecure([]byte(assertion2))
	if err != nil {
		t.Fatalf("parse second assertion: %v", err)
	}
	jti2, ok := tok2.JwtID()
	if !ok || jti2 == "" {
		t.Errorf("second jti missing or empty (ok=%v, jti=%q)", ok, jti2)
	}
	if jti == jti2 {
		t.Errorf("jti must differ across calls for anti-replay; both = %q", jti)
	}
}

func TestPrivateKeyJWT_RejectsSymmetricAlg(t *testing.T) {
	s := jwktest.NewECSigner(t, "k1")
	if _, err := PrivateKeyJWTAuth("cid", s.PrivatePEM(t), "HS256"); err == nil {
		t.Fatal("HS256 must be rejected")
	}
}
