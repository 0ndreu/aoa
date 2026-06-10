package aoa

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// verifyErrKind classifies a verification failure so callers (Bearer middleware,
// ExchangeValidator) can map it to their own error/challenge shape.
type verifyErrKind int

const (
	verifyMalformed     verifyErrKind = iota // header unparseable
	verifyDisallowedAlg                      // alg not in the allowlist
	verifyJWKS                               // key source error (infra)
	verifyInvalid                            // signature/iss/exp/nbf/iat failed
)

type verifyError struct {
	kind   verifyErrKind
	reason string
}

func (e *verifyError) Error() string { return e.reason }

// tokenVerifier performs the JOSE-level access-token checks shared by the Bearer
// middleware and the token-exchange validator: header parse, alg allowlist, key
// lookup by kid, signature verification, and issuer/expiry/nbf/iat validation.
// It does NOT check audience, scopes, or DPoP binding; those are caller policy.
type tokenVerifier struct {
	keys   keySource
	issuer string
	skew   time.Duration
	algs   map[string]struct{}
}

// verify validates raw and returns its claims, or a non-nil *verifyError.
func (v *tokenVerifier) verify(ctx context.Context, raw string) (*Claims, *verifyError) {
	kid, alg, err := headerKIDAlg(raw)
	if err != nil {
		return nil, &verifyError{verifyMalformed, "header parse failed"}
	}
	if _, allowed := v.algs[alg]; !allowed {
		return nil, &verifyError{verifyDisallowedAlg, "disallowed algorithm: " + alg}
	}
	set, err := v.keys.setForKID(ctx, kid)
	if err != nil {
		return nil, &verifyError{verifyJWKS, "jwks: " + err.Error()}
	}
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(v.issuer),
		jwt.WithAcceptableSkew(v.skew),
	)
	if err != nil {
		return nil, &verifyError{verifyInvalid, err.Error()}
	}
	return newClaims(tok, raw), nil
}
