// Command token-exchange demonstrates the agent->user->tool delegation flow:
// obtain a user token upstream via authorization_code (golang.org/x/oauth2 - see
// README), then use aoa.TokenExchanger to mint a downscoped delegation token for
// a downstream tool. Run against Keycloak (see README).
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/0ndreu/aoa"
)

func main() {
	endpoint := envOr("TOKEN_ENDPOINT", "http://localhost:8080/realms/demo/protocol/openid-connect/token")
	subjectToken := os.Getenv("SUBJECT_TOKEN")
	if subjectToken == "" {
		log.Fatal("set SUBJECT_TOKEN to a user access token (README shows the x/oauth2 authorization_code step)")
	}

	x, err := aoa.NewTokenExchanger(aoa.ExchangeConfig{
		TokenEndpoint: endpoint,
		ClientAuth:    aoa.ClientSecretAuth(envOr("CLIENT_ID", "mcp-gateway"), os.Getenv("CLIENT_SECRET"), true),
	})
	if err != nil {
		log.Fatalf("new exchanger: %v", err)
	}

	res, err := x.Exchange(context.Background(), aoa.ExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: aoa.TokenTypeAccessToken,
		Audience:         []string{envOr("DOWNSTREAM_AUDIENCE", "https://tool.example.com")},
		Scope:            []string{"tool:invoke"},
	})
	if err != nil {
		log.Fatalf("exchange: %v", err)
	}
	fmt.Printf("downstream token (type=%s, expires_in=%s):\n%s\n", res.TokenType, res.ExpiresIn, res.AccessToken)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
