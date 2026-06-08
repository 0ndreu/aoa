package aoa

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/0ndreu/aoa/internal/jwktest"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func newDPoPExchanger(t *testing.T, endpoint string) *TokenExchanger {
	t.Helper()
	s := jwktest.NewECSigner(t, "")
	key, err := NewDPoPKey(s.PrivatePEM(t))
	if err != nil {
		t.Fatalf("dpop key: %v", err)
	}
	x, err := NewTokenExchanger(ExchangeConfig{
		TokenEndpoint: endpoint,
		ClientAuth:    ClientSecretAuth("cid", "secret", true),
		DPoPKey:       key,
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	return x
}

func TestExchange_DPoPProofAttached(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.Respond(jwktest.ExchangeResponse{AccessToken: "d", IssuedTokenType: string(TokenTypeAccessToken), TokenType: "DPoP"})
	x := newDPoPExchanger(t, as.TokenEndpoint())
	res, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if res.TokenType != "DPoP" {
		t.Fatalf("token_type = %q", res.TokenType)
	}
	if as.LastDPoP() == "" {
		t.Fatal("no DPoP header sent")
	}
}

func TestExchange_NonceRetry(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.RequireNonceOnce()
	as.Respond(jwktest.ExchangeResponse{AccessToken: "d", IssuedTokenType: string(TokenTypeAccessToken), TokenType: "DPoP"})
	x := newDPoPExchanger(t, as.TokenEndpoint())
	res, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	if err != nil {
		t.Fatalf("exchange should succeed after nonce retry: %v", err)
	}
	if res.AccessToken != "d" {
		t.Fatalf("unexpected token: %s", res.AccessToken)
	}
}

func TestExchange_NonceLoopGuard(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.RespondError(400, `{"error":"use_dpop_nonce"}`)
	x := newDPoPExchanger(t, as.TokenEndpoint())
	_, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "use_dpop_nonce" {
		t.Fatalf("want surfaced use_dpop_nonce after retry, got %v", err)
	}
}

// TestExchange_NonceCarriedInRetryProof: after a use_dpop_nonce challenge the
// proof sent in the retried (successful) call must carry the server nonce.
// we decode the retried proof via jws.Parse -> payload -> JSON.
func TestExchange_NonceCarriedInRetryProof(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.RequireNonceOnce()
	as.Respond(jwktest.ExchangeResponse{
		AccessToken: "d", IssuedTokenType: string(TokenTypeAccessToken), TokenType: "DPoP",
	})
	x := newDPoPExchanger(t, as.TokenEndpoint())
	if _, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"}); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// as.LastDPoP() is the proof from the SECOND (successful) request.
	proof := as.LastDPoP()
	if proof == "" {
		t.Fatal("no DPoP proof on retried call")
	}

	// jws.Parse returns the parsed message; payload is the first (and only)
	// signature's decoded payload.
	msg, err := jws.Parse([]byte(proof))
	if err != nil {
		t.Fatalf("jws.Parse proof: %v", err)
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
		t.Fatalf("unmarshal proof payload: %v", err)
	}
	const wantNonce = "srv-nonce-1"
	if claims.Nonce != wantNonce {
		t.Fatalf("nonce in retried proof = %q, want %q", claims.Nonce, wantNonce)
	}
}

// TestExchange_PrivateKeyJWTAuth: Exchange with PrivateKeyJWTAuth sends a
// non-empty client_assertion and the correct client_assertion_type in the form.
func TestExchange_PrivateKeyJWTAuth(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.Respond(jwktest.ExchangeResponse{
		AccessToken: "jwt-auth-tok", IssuedTokenType: string(TokenTypeAccessToken), TokenType: "Bearer",
	})

	signer := jwktest.NewECSigner(t, "k1")
	ca, err := PrivateKeyJWTAuth("cid", signer.PrivatePEM(t), "ES256")
	if err != nil {
		t.Fatalf("PrivateKeyJWTAuth: %v", err)
	}

	x, err := NewTokenExchanger(ExchangeConfig{
		TokenEndpoint: as.TokenEndpoint(),
		ClientAuth:    ca,
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}

	res, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if res.AccessToken != "jwt-auth-tok" {
		t.Fatalf("access_token = %q", res.AccessToken)
	}

	f := as.LastForm()
	if f.Get("client_assertion") == "" {
		t.Fatal("client_assertion must be non-empty")
	}
	const wantType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	if got := f.Get("client_assertion_type"); got != wantType {
		t.Fatalf("client_assertion_type = %q, want %q", got, wantType)
	}
}
