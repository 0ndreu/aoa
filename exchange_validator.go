package aoa

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ExchangePolicy approves or narrows the requested downscope. Returning an error
// rejects the exchange; return an *ExchangeError to control the code (default
// invalid_target).
type ExchangePolicy interface {
	Authorize(ctx context.Context, g *ExchangeGrant) error
}

// ExchangeValidatorOptions configures an ExchangeValidator.
type ExchangeValidatorOptions struct {
	KeysJWKS          []byte
	JWKSURI           string
	Issuer            string
	JWKSCacheTTL      time.Duration
	AllowedAlgorithms []string
	ClockSkew         time.Duration
	Policy            ExchangePolicy
	Audit             Emitter

	// Audience, when non-empty, is the set of acceptable audiences for the
	// INBOUND subject/actor tokens (this STS's own identifier(s)). A token whose
	// aud does not intersect Audience is rejected (RFC 9700 audience restriction;
	// prevents a token minted for another resource from being exchanged here).
	// When empty, tokens for ANY audience from the trusted issuer are accepted -
	// a deployment risk the consumer MUST mitigate (e.g. via Policy). Strongly
	// recommended to set this.
	Audience []string
}

// ExchangeGrant is the verified, authorized result of an inbound token-exchange
// request. The consumer signs a token from it (aoa does not sign).
type ExchangeGrant struct {
	Subject      *Claims
	Actor        *Claims // nil ⇒ impersonation
	IsDelegation bool

	RequestedAudience  []string
	RequestedScope     []string
	RequestedResource  []string
	RequestedTokenType TokenType

	Act          map[string]any // nested delegation chain to embed; nil for impersonation
	Confirmation string         // cnf.jkt to embed if binding the new token
}

// ExchangeValidator verifies inbound RFC 8693 requests for a resource/gateway
// that mints its own tokens.
type ExchangeValidator struct {
	verifier  *tokenVerifier
	policy    ExchangePolicy
	emitter   Emitter
	audiences []string
}

// NewExchangeValidator validates opts and returns a validator.
func NewExchangeValidator(opts ExchangeValidatorOptions) (*ExchangeValidator, error) {
	if opts.KeysJWKS == nil && opts.JWKSURI == "" {
		return nil, errors.New("aoa: ExchangeValidatorOptions requires KeysJWKS or JWKSURI")
	}
	if opts.Issuer == "" {
		return nil, errors.New("aoa: ExchangeValidatorOptions.Issuer is required")
	}
	algs, err := parseAlgs(opts.AllowedAlgorithms)
	if err != nil {
		return nil, err
	}
	ks, err := resolveKeySource(BearerOpts{
		KeysJWKS: opts.KeysJWKS, JWKSURI: opts.JWKSURI, Issuer: opts.Issuer,
		Resource: "exchange", JWKSCacheTTL: opts.JWKSCacheTTL,
	})
	if err != nil {
		return nil, err
	}
	skew := opts.ClockSkew
	if skew == 0 {
		skew = 60 * time.Second
	}
	emitter := opts.Audit
	if emitter == nil {
		emitter = noopEmitter{}
	}
	return &ExchangeValidator{
		verifier:  &tokenVerifier{keys: ks, issuer: opts.Issuer, skew: skew, algs: algs},
		policy:    opts.Policy,
		emitter:   emitter,
		audiences: opts.Audience,
	}, nil
}

// Validate parses and authorizes the request, returning the grant to sign.
func (v *ExchangeValidator) Validate(ctx context.Context, r *http.Request) (*ExchangeGrant, error) {
	if err := r.ParseForm(); err != nil {
		return v.deny(ctx, &ExchangeError{Code: "invalid_request", Description: "unparseable form"})
	}
	f := r.PostForm
	if f.Get("grant_type") != grantTypeTokenExchange {
		return v.deny(ctx, &ExchangeError{Code: "unsupported_grant_type"})
	}
	subjectToken := f.Get("subject_token")
	if subjectToken == "" || f.Get("subject_token_type") == "" {
		return v.deny(ctx, &ExchangeError{Code: "invalid_request", Description: "subject_token and subject_token_type are required"})
	}
	actorToken := f.Get("actor_token")
	if actorToken != "" && f.Get("actor_token_type") == "" {
		return v.deny(ctx, &ExchangeError{Code: "invalid_request", Description: "actor_token_type is required with actor_token"})
	}

	subject, verr := v.verifier.verify(ctx, subjectToken)
	if verr != nil {
		return v.deny(ctx, &ExchangeError{Code: "invalid_grant", Description: "subject_token invalid"})
	}
	if len(v.audiences) > 0 && !audienceMatches(subject.Audience, v.audiences) {
		return v.deny(ctx, &ExchangeError{Code: "invalid_grant", Description: "subject_token audience not accepted"})
	}

	grant := &ExchangeGrant{
		Subject:            subject,
		RequestedAudience:  f["audience"],
		RequestedScope:     strings.Fields(f.Get("scope")),
		RequestedResource:  f["resource"],
		RequestedTokenType: TokenType(f.Get("requested_token_type")),
		Confirmation:       subject.boundKeyThumbprint(),
	}

	if actorToken != "" {
		actor, verr := v.verifier.verify(ctx, actorToken)
		if verr != nil {
			return v.deny(ctx, &ExchangeError{Code: "invalid_grant", Description: "actor_token invalid"})
		}
		if len(v.audiences) > 0 && !audienceMatches(actor.Audience, v.audiences) {
			return v.deny(ctx, &ExchangeError{Code: "invalid_grant", Description: "actor_token audience not accepted"})
		}
		if !mayActAllows(subject, actor.Subject) {
			return v.deny(ctx, &ExchangeError{Code: "invalid_grant", Description: "actor not permitted (may_act)"})
		}
		grant.Actor = actor
		grant.IsDelegation = true
		grant.Act = buildActChain(actor.Subject, subject)
	} else if !mayActAllows(subject, "") {
		return v.deny(ctx, &ExchangeError{Code: "invalid_grant", Description: "subject requires a permitted actor"})
	}

	if v.policy != nil {
		if err := v.policy.Authorize(ctx, grant); err != nil {
			ee, ok := err.(*ExchangeError)
			if !ok {
				ee = &ExchangeError{Code: "invalid_target", Description: "policy denied"}
			}
			return v.deny(ctx, ee)
		}
	}

	v.emit(ctx, Event{Kind: EventTokenExchanged, Outcome: OutcomeAllow,
		Subject: subject.Subject, Issuer: subject.Issuer, Audience: grant.RequestedAudience, Scope: grant.RequestedScope})
	return grant, nil
}

func (v *ExchangeValidator) deny(ctx context.Context, ee *ExchangeError) (*ExchangeGrant, error) {
	v.emit(ctx, Event{Kind: EventTokenExchanged, Outcome: OutcomeDeny, Error: ee.Code, Reason: ee.Description})
	return nil, ee
}

func (v *ExchangeValidator) emit(ctx context.Context, ev Event) {
	ev.Timestamp = time.Now().UTC()
	v.emitter.Emit(ctx, ev)
}

// mayActAllows reports whether actorSub may act for subject. If the subject has
// no may_act claim, any actor (or none) is allowed - authorization then falls to
// the policy hook. If may_act is present, it must parse and its sub must equal
// actorSub; a present-but-unparseable may_act fails closed (deny).
func mayActAllows(subject *Claims, actorSub string) bool {
	var p struct {
		MayAct json.RawMessage `json:"may_act"`
	}
	if subject.Decode(&p) != nil || len(p.MayAct) == 0 {
		return true // no may_act constraint present
	}
	var ma struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(p.MayAct, &ma) != nil || ma.Sub == "" {
		return false // present but unparseable / no sub -> fail closed
	}
	return ma.Sub == actorSub
}

// buildActChain assembles the RFC 8693 par.4.1 act claim: the new actor is
// outermost; the subject's existing act (if any) is nested inside.
func buildActChain(actorSub string, subject *Claims) map[string]any {
	act := map[string]any{"sub": actorSub}
	var p struct {
		Act map[string]any `json:"act"`
	}
	if subject.Decode(&p) == nil && len(p.Act) > 0 {
		act["act"] = p.Act
	}
	return act
}

// IssuedToken is a token the consumer signed from an ExchangeGrant, to be
// written as the RFC 8693 response. aoa does not sign - AccessToken is provided
// by the caller.
type IssuedToken struct {
	AccessToken     string
	IssuedTokenType TokenType
	TokenType       string // "Bearer" | "DPoP" | "N_A"
	ExpiresIn       time.Duration
	Scope           []string
	RefreshToken    string
}

// WriteExchangeResponse writes the RFC 8693 token-exchange JSON response.
func WriteExchangeResponse(w http.ResponseWriter, t IssuedToken) error {
	if t.AccessToken == "" {
		return errors.New("aoa: IssuedToken.AccessToken is required")
	}
	tt := t.TokenType
	if tt == "" {
		tt = "Bearer"
	}
	out := map[string]any{
		"access_token":      t.AccessToken,
		"issued_token_type": string(t.IssuedTokenType.orDefault()),
		"token_type":        tt,
	}
	if t.ExpiresIn > 0 {
		out["expires_in"] = int(t.ExpiresIn.Seconds())
	}
	if len(t.Scope) > 0 {
		out["scope"] = strings.Join(t.Scope, " ")
	}
	if t.RefreshToken != "" {
		out["refresh_token"] = t.RefreshToken
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(out)
}
