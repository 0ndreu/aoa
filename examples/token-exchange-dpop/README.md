# token-exchange-dpop example

Demonstrates a DPoP-bound token exchange (RFC 9449 par.5) using
`aoa.TokenExchanger`. The exchanger attaches a DPoP proof to the token-exchange
POST and the server issues a sender-constrained output token. The example also
handles the `use_dpop_nonce` 400 retry automatically.

## Keycloak caveat

Keycloak's standard token exchange (`urn:ietf:params:oauth:grant-type:token-exchange`)
accepts only **Bearer** subject tokens for the `subject_token` parameter - it
cannot accept a DPoP-bound token as input. However, Keycloak **can** issue a
DPoP-bound output token when a valid DPoP proof is attached to the exchange
request.

This means:

- `SUBJECT_TOKEN` is a plain Bearer token (obtained via authorization_code or
  client_credentials).
- The output token (printed by this example) is DPoP-bound: it carries a `cnf.jkt`
  claim and **must** be presented with a matching DPoP proof.

## Generate a DPoP key

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out dpop_key.pem
```

The file must be a PKCS#8 PEM (the default output of `openssl genpkey`).

## Prerequisites

- Keycloak 26.2+ with token exchange enabled
- A confidential client `mcp-gateway` configured to request DPoP-bound tokens

## Run

```bash
# Generate the key if you haven't yet:
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out dpop_key.pem

export SUBJECT_TOKEN=<bearer-user-access-token>
export CLIENT_SECRET=<mcp-gateway-client-secret>
# optional overrides:
export DPOP_KEY=dpop_key.pem
export TOKEN_ENDPOINT=http://localhost:8080/realms/demo/protocol/openid-connect/token
export CLIENT_ID=mcp-gateway
export DOWNSTREAM_AUDIENCE=https://tool.example.com

go run .
```
