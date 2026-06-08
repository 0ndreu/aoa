//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/0ndreu/aoa"
)

// TestKeycloakExchange runs against a live Keycloak (docker-compose up).
// Skips unless KEYCLOAK_TOKEN_ENDPOINT + SUBJECT_TOKEN are set.
func TestKeycloakExchange(t *testing.T) {
	endpoint := os.Getenv("KEYCLOAK_TOKEN_ENDPOINT")
	subject := os.Getenv("SUBJECT_TOKEN")
	if endpoint == "" || subject == "" {
		t.Skip("set KEYCLOAK_TOKEN_ENDPOINT and SUBJECT_TOKEN to run")
	}
	x, err := aoa.NewTokenExchanger(aoa.ExchangeConfig{
		TokenEndpoint: endpoint,
		ClientAuth:    aoa.ClientSecretAuth(os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET"), true),
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	res, err := x.Exchange(context.Background(), aoa.ExchangeRequest{
		SubjectToken:     subject,
		SubjectTokenType: aoa.TokenTypeAccessToken,
		Audience:         []string{os.Getenv("DOWNSTREAM_AUDIENCE")},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("no token issued")
	}
	t.Logf("issued token_type=%s", res.TokenType)
}
