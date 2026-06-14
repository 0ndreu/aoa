package aoa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzExchangeValidate feeds arbitrary form bodies to the RFC 8693 request
// parser. It must never panic, and exactly one of (grant, err) must be non-nil.
func FuzzExchangeValidate(f *testing.F) {
	v, err := NewExchangeValidator(ExchangeValidatorOptions{
		KeysJWKS: []byte(`{"keys":[]}`),
		Issuer:   "https://issuer.example",
	})
	if err != nil {
		f.Fatalf("ctor: %v", err)
	}

	f.Add("grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=x&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
	f.Add("")
	f.Add("grant_type=foo")
	f.Add("subject_token=&subject_token_type=&actor_token=a")
	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		grant, err := v.Validate(context.Background(), r)
		if (grant == nil) == (err == nil) {
			t.Fatalf("invariant violated: grant=%v err=%v (exactly one must be non-nil)", grant, err)
		}
	})
}
