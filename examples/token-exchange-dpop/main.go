// Command token-exchange-dpop demonstrates a DPoP-bound token exchange:
// aoa.TokenExchanger attaches a DPoP proof to the exchange and requests a
// sender-constrained downstream token (RFC 9449 par.5). Handles use_dpop_nonce.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/0ndreu/aoa"
)

func main() {
	keyPEM, err := os.ReadFile(envOr("DPOP_KEY", "dpop_key.pem"))
	if err != nil {
		log.Fatalf("read DPoP key (generate an EC P-256 PKCS#8 PEM): %v", err)
	}
	dpopKey, err := aoa.NewDPoPKey(keyPEM)
	if err != nil {
		log.Fatalf("dpop key: %v", err)
	}
	x, err := aoa.NewTokenExchanger(aoa.ExchangeConfig{
		TokenEndpoint: envOr("TOKEN_ENDPOINT", "http://localhost:8080/realms/demo/protocol/openid-connect/token"),
		ClientAuth:    aoa.ClientSecretAuth(envOr("CLIENT_ID", "mcp-gateway"), os.Getenv("CLIENT_SECRET"), true),
		DPoPKey:       dpopKey,
	})
	if err != nil {
		log.Fatalf("new exchanger: %v", err)
	}
	res, err := x.Exchange(context.Background(), aoa.ExchangeRequest{
		SubjectToken:     os.Getenv("SUBJECT_TOKEN"),
		SubjectTokenType: aoa.TokenTypeAccessToken,
		Audience:         []string{envOr("DOWNSTREAM_AUDIENCE", "https://tool.example.com")},
	})
	if err != nil {
		log.Fatalf("exchange: %v", err)
	}
	fmt.Printf("DPoP-bound token (type=%s):\n%s\n", res.TokenType, res.AccessToken)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
