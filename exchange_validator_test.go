package aoa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0ndreu/aoa/internal/jwktest"
)

const valIss = "https://idp.example.com"

func newValidator(t *testing.T, s *jwktest.Signer) *ExchangeValidator {
	t.Helper()
	v, err := NewExchangeValidator(ExchangeValidatorOptions{KeysJWKS: s.PublicJWKS(t), Issuer: valIss})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	return v
}

func exchangeReq(t *testing.T, form url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://gw.example.com/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestValidate_Impersonation(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix()})
	v := newValidator(t, s)
	grant, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
		"audience":           {"https://downstream"},
	}))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if grant.IsDelegation || grant.Actor != nil || grant.Act != nil {
		t.Fatal("impersonation must have no actor/act")
	}
	if grant.Subject.Subject != "alice" || grant.RequestedAudience[0] != "https://downstream" {
		t.Fatalf("grant wrong: %+v", grant)
	}
}

func TestValidate_DelegationBuildsActChain(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{
		"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix(),
		"act": map[string]any{"sub": "svc-a"},
	})
	actor := s.SignClaims(t, map[string]any{"sub": "svc-b", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix()})
	v := newValidator(t, s)
	grant, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
		"actor_token":        {actor},
		"actor_token_type":   {string(TokenTypeAccessToken)},
	}))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !grant.IsDelegation {
		t.Fatal("want delegation")
	}
	if grant.Act["sub"] != "svc-b" {
		t.Fatalf("outer act.sub = %v", grant.Act["sub"])
	}
	nested, ok := grant.Act["act"].(map[string]any)
	if !ok || nested["sub"] != "svc-a" {
		t.Fatalf("nested act wrong: %v", grant.Act["act"])
	}
}

func TestValidate_MayActEnforced(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{
		"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix(),
		"may_act": map[string]any{"sub": "svc-allowed"},
	})
	actor := s.SignClaims(t, map[string]any{"sub": "svc-evil", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix()})
	v := newValidator(t, s)
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
		"actor_token":        {actor},
		"actor_token_type":   {string(TokenTypeAccessToken)},
	}))
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "invalid_grant" {
		t.Fatalf("want invalid_grant for may_act violation, got %v", err)
	}
}

func TestValidate_MayActAllowsPermittedActor(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{
		"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix(),
		"may_act": map[string]any{"sub": "svc-allowed"},
	})
	actor := s.SignClaims(t, map[string]any{"sub": "svc-allowed", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix()})
	v := newValidator(t, s)
	grant, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
		"actor_token":        {actor},
		"actor_token_type":   {string(TokenTypeAccessToken)},
	}))
	if err != nil {
		t.Fatalf("permitted actor should pass: %v", err)
	}
	if grant.Act["sub"] != "svc-allowed" {
		t.Fatalf("act.sub = %v", grant.Act["sub"])
	}
}

func TestValidate_CnfPropagated(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	bound := jwktest.NewECSigner(t, "")
	subj := s.SignClaims(t, jwktest.CnfBound(t, map[string]any{
		"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix(),
	}, bound))
	v := newValidator(t, s)
	grant, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
	}))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if grant.Confirmation != bound.Thumbprint(t) {
		t.Fatalf("cnf.jkt not propagated: %q", grant.Confirmation)
	}
}

func TestValidate_BadSubjectTokenRejected(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	v := newValidator(t, s)
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {"not-a-jwt"},
		"subject_token_type": {string(TokenTypeAccessToken)},
	}))
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "invalid_grant" {
		t.Fatalf("want invalid_grant, got %v", err)
	}
}

func TestWriteExchangeResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	err := WriteExchangeResponse(rec, IssuedToken{
		AccessToken: "signed-tok", IssuedTokenType: TokenTypeAccessToken,
		TokenType: "DPoP", ExpiresIn: 300 * time.Second, Scope: []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var got map[string]any
	if e := json.Unmarshal(rec.Body.Bytes(), &got); e != nil {
		t.Fatalf("unmarshal: %v", e)
	}
	if got["access_token"] != "signed-tok" || got["token_type"] != "DPoP" {
		t.Fatalf("body wrong: %v", got)
	}
	if got["issued_token_type"] != string(TokenTypeAccessToken) {
		t.Fatalf("issued_token_type wrong: %v", got["issued_token_type"])
	}
	if got["expires_in"].(float64) != 300 {
		t.Fatalf("expires_in wrong: %v", got["expires_in"])
	}
	if got["scope"] != "read write" {
		t.Fatalf("scope wrong: %v", got["scope"])
	}
}

func TestWriteExchangeResponse_RequiresAccessToken(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := WriteExchangeResponse(rec, IssuedToken{}); err == nil {
		t.Fatal("empty AccessToken must error")
	}
}

// newValidatorWithAudience builds a validator configured to accept only the given audience(s).
func newValidatorWithAudience(t *testing.T, s *jwktest.Signer, aud []string) *ExchangeValidator {
	t.Helper()
	v, err := NewExchangeValidator(ExchangeValidatorOptions{
		KeysJWKS: s.PublicJWKS(t),
		Issuer:   valIss,
		Audience: aud,
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	return v
}

func TestValidate_AudienceMismatchRejected(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{
		"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix(),
		"aud": []string{"https://other-rs"},
	})
	v := newValidatorWithAudience(t, s, []string{"https://this-sts"})
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
	}))
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "invalid_grant" {
		t.Fatalf("want invalid_grant for audience mismatch, got %v", err)
	}
}

func TestValidate_AudienceMatchAccepted(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{
		"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix(),
		"aud": []string{"https://this-sts"},
	})
	v := newValidatorWithAudience(t, s, []string{"https://this-sts"})
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
	}))
	if err != nil {
		t.Fatalf("matching audience should be accepted: %v", err)
	}
}

func TestValidate_NoConfiguredAudienceAcceptsAny(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{
		"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix(),
		"aud": []string{"https://anything"},
	})
	// newValidator has no Audience configured -> accepts any audience
	v := newValidator(t, s)
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
	}))
	if err != nil {
		t.Fatalf("no configured audience should accept any aud: %v", err)
	}
}

func TestValidate_MalformedMayActFailsClosed(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	// may_act is a string (not an object) - malformed; must fail closed
	subj := s.SignClaims(t, map[string]any{
		"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix(),
		"may_act": "not-an-object",
	})
	actor := s.SignClaims(t, map[string]any{"sub": "svc-b", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix()})
	v := newValidator(t, s)
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
		"actor_token":        {actor},
		"actor_token_type":   {string(TokenTypeAccessToken)},
	}))
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "invalid_grant" {
		t.Fatalf("malformed may_act must fail closed with invalid_grant, got %v", err)
	}
}

func TestValidate_UnsupportedGrantType(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	v := newValidator(t, s)
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type": {"authorization_code"},
	}))
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "unsupported_grant_type" {
		t.Fatalf("want unsupported_grant_type, got %v", err)
	}
}

func TestValidate_MissingSubjectToken(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	v := newValidator(t, s)
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type": {grantTypeTokenExchange},
		// subject_token intentionally omitted
	}))
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "invalid_request" {
		t.Fatalf("want invalid_request for missing subject_token, got %v", err)
	}
}

func TestValidate_ActorTokenWithoutType(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix()})
	actor := s.SignClaims(t, map[string]any{"sub": "svc-b", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix()})
	v := newValidator(t, s)
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
		"actor_token":        {actor},
		// actor_token_type intentionally omitted
	}))
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "invalid_request" {
		t.Fatalf("want invalid_request for missing actor_token_type, got %v", err)
	}
}

func TestValidate_ExpiredSubjectRejected(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{
		"sub": "alice", "iss": valIss,
		"exp": time.Now().Add(-2 * time.Hour).Unix(), // expired
	})
	v := newValidator(t, s)
	_, err := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
	}))
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "invalid_grant" {
		t.Fatalf("want invalid_grant for expired subject, got %v", err)
	}
}

// denyPolicy is a test ExchangePolicy that always returns the configured error.
type denyPolicy struct {
	err error
}

func (p *denyPolicy) Authorize(_ context.Context, _ *ExchangeGrant) error {
	return p.err
}

func TestValidate_PolicyRejection(t *testing.T) {
	s := jwktest.NewRSASigner(t, "k1")
	subj := s.SignClaims(t, map[string]any{"sub": "alice", "iss": valIss, "exp": time.Now().Add(time.Hour).Unix()})
	v, err := NewExchangeValidator(ExchangeValidatorOptions{
		KeysJWKS: s.PublicJWKS(t),
		Issuer:   valIss,
		Policy:   &denyPolicy{err: &ExchangeError{Code: "invalid_target"}},
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	_, gErr := v.Validate(context.Background(), exchangeReq(t, url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subj},
		"subject_token_type": {string(TokenTypeAccessToken)},
	}))
	ee, ok := gErr.(*ExchangeError)
	if !ok || ee.Code != "invalid_target" {
		t.Fatalf("want invalid_target from policy, got %v", gErr)
	}
}

func TestWriteExchangeResponse_CacheControl(t *testing.T) {
	rec := httptest.NewRecorder()
	err := WriteExchangeResponse(rec, IssuedToken{
		AccessToken: "tok", TokenType: "Bearer",
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}
