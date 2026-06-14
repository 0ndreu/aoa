# Security Policy

_`aoa` is built to fail closed, but it has **not** had an external security audit. Review it against your own threat model before production use._

## Supported versions

`aoa` is pre-1.0 (`v0.x`). Only the latest `v0.x` release is supported; security fixes are released as a new `v0.x` tag.

## Reporting a vulnerability

Please report security issues **privately** via GitHub's [Report a vulnerability](https://github.com/0ndreu/aoa/security/advisories/new) (Security Advisories), not as a public issue. Include a description, affected version, and a reproduction if possible. Expect an initial acknowledgement within a few days.

## What it defends against

- **Algorithm attacks:** `none`, `HS*` against an asymmetric key (alg-confusion), and any algorithm outside `AllowedAlgorithms` are rejected. The signing algorithm comes from the trusted JWKS, never from the token header alone.
- **Claim validation:** `exp`, `nbf`, wrong `iss`, and wrong `aud` (RFC 8707 audience binding) all reject; spoofed-`kid` and malformed tokens fail closed.
- **DPoP downgrade:** a `cnf.jkt`-bound token is never accepted as a plain Bearer in any mode.
- **Replay:** DPoP `jti` values are tracked (pluggable for multi-instance); proofs are bound to method/URL (`htm`/`htu`) and access-token hash (`ath`).
- **Exchange audience restriction:** `ExchangeValidatorOptions.Audience` rejects tokens minted for another resource (RFC 9700).

## What's tested

The validation matrix is unit-tested (including adversarial cases); the four highest-risk components are fuzzed (`Fuzz*`, seeds run on every `go test`); end-to-end conformance against live Keycloak is covered by the standalone [`aoa-conformance`](https://github.com/0ndreu/aoa-conformance) suite. See the README's "What's tested" for detail.
