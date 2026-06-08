# token-exchange example

Demonstrates the agent->user->tool delegation flow using `aoa.TokenExchanger`
(RFC 8693). The example consumes a `SUBJECT_TOKEN` you already hold and
exchanges it for a downscoped delegation token for a downstream tool.

## Why aoa doesn't include the upstream login step

Obtaining the initial user token via `authorization_code` is commodity work
covered by `golang.org/x/oauth2` and the official MCP SDK - aoa deliberately
does not reimplement it. aoa's value is in the **exchange**: minting a
sender-constrained, audience-restricted downstream token with correct
`WWW-Authenticate` error shapes and optional DPoP binding.

If you need to obtain a subject token in your own code, the `x/oauth2` flow
looks like this (illustrative - not compiled here):

```go
import "golang.org/x/oauth2"

cfg := oauth2.Config{
    ClientID:     "my-agent",
    ClientSecret: os.Getenv("CLIENT_SECRET"),
    Endpoint: oauth2.Endpoint{
        AuthURL:  "http://localhost:8080/realms/demo/protocol/openid-connect/auth",
        TokenURL: "http://localhost:8080/realms/demo/protocol/openid-connect/token",
    },
    RedirectURL: "http://localhost:9000/callback",
    Scopes:      []string{"openid", "profile"},
}
// ... run the authorization_code redirect flow, then:
tok, err := cfg.Exchange(ctx, code)
subjectToken := tok.AccessToken
```

Once you have `subjectToken`, hand it to `aoa.TokenExchanger.Exchange` as shown
in `main.go`.

## Prerequisites

- Keycloak 26.2+ with token exchange enabled for the `demo` realm
  (preview feature `token-exchange` must be on)
- A confidential client `mcp-gateway` with permission to exchange tokens
  for audience `https://tool.example.com`

You can point at the Docker Compose stack in
`examples/token-exchange-dpop/` which includes a pre-configured Keycloak.

## Run

```bash
export SUBJECT_TOKEN=<user-access-token>
export CLIENT_SECRET=<mcp-gateway-client-secret>
# optional overrides:
export TOKEN_ENDPOINT=http://localhost:8080/realms/demo/protocol/openid-connect/token
export CLIENT_ID=mcp-gateway
export DOWNSTREAM_AUDIENCE=https://tool.example.com

go run .
```
