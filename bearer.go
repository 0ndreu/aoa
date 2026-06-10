package aoa

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// DPoPMode controls DPoP enforcement (RFC 9449)
//
// Regardless of mode, a sender-constrained access token (one carrying cnf.jkt)
// is never accepted as a plain Bearer token. Presenting one as Bearer always
// yields 401. The modes differ only in how they treat un-bound tokens:
//   - DPoPOff: DPoP proofs are not processed; un-bound Bearer tokens are
//     accepted. The DPoP scheme is unrecognized.
//   - DPoPOptional: un-bound Bearer tokens are still accepted (migration mode);
//     bound tokens require a verified DPoP proof.
//   - DPoPRequired: all plain Bearer is rejected; every token must be presented
//     as DPoP with a verified, cnf.jkt-bound proof.
type DPoPMode int

const (
	DPoPOff DPoPMode = iota
	DPoPOptional
	DPoPRequired
)

// TokenLookup selects where the bearer token is read from.
type TokenLookup int

const (
	HeaderBearer TokenLookup = iota
)

// BearerOpts configures RequireBearer
type BearerOpts struct {
	JWKSURI  string
	KeysJWKS []byte // raw JWKS JSON (static keys); parsed internally
	Issuer   string
	Audience []string

	Resource string // also accepted as audience; drives resource_metadata hint in WWW-Authenticate
	Realm    string // WWW-Authenticate realm; defaults to Resource, else "MCP"

	RequiredScopes    []string
	ClockSkew         time.Duration
	JWKSCacheTTL      time.Duration // remote JWKS refresh interval; 0 = 5m default
	AllowedAlgorithms []string
	DPoP              DPoPMode
	ClaimValidator    func(*Claims) error
	ErrorHandler      func(http.ResponseWriter, *http.Request, error)
	Logger            *slog.Logger
	AuditEmitter      Emitter
	TokenLookup       TokenLookup

	// DPoPSigningAlgs is the asymmetric-algorithm allowlist for DPoP *proofs*
	// (separate from AllowedAlgorithms, which governs access-token signatures).
	// Default: ["ES256", "RS256", "EdDSA"]. "none" and symmetric "HS*" always rejected.
	DPoPSigningAlgs []string

	// DPoPProofMaxAge bounds how old a proof's iat may be. Default 60s.
	// Future-dated proofs are tolerated up to ClockSkew.
	DPoPProofMaxAge time.Duration

	// DPoPReplay is the jti replay cache. Default: an in-memory TTL cache.
	// Supply a distributed implementation (see examples/dpop-redis) for
	// multi-instance deployments.
	DPoPReplay DPoPReplayCache

	// DPoPNonce, when non-nil, enables the server-nonce challenge.
	// Default nil (no nonce). NewDPoPNonceSource(secret) returns a stateless
	// HMAC source that is multi-instance-safe with no shared store.
	DPoPNonce DPoPNonceSource

	// TrustForwardedHeaders derives htu from X-Forwarded-Proto/-Host instead of
	// the request's own scheme+host. Default false. Enable only behind a trusted
	// proxy that sets these headers (otherwise they are client-spoofable).
	TrustForwardedHeaders bool
}

const defaultJWKSTTL = 5 * time.Minute

type bearerMW struct {
	keys          keySource
	issuer        string
	audiences     []string // accepted set = {Resource} ∪ Audience
	resource      string
	requiredScope []string
	skew          time.Duration
	algs          map[string]struct{} // allowed signature-alg names (e.g. "RS256")
	claimVal      func(*Claims) error
	onError       func(http.ResponseWriter, *http.Request, error)
	logger        *slog.Logger
	emitter       Emitter

	dpopMode     DPoPMode
	dpopAlgs     map[string]struct{} // allowed DPoP proof algs (membership)
	dpopAlgsList []string            // same, for the challenge "algs" param
	proofMaxAge  time.Duration
	replay       DPoPReplayCache
	nonce        DPoPNonceSource
	trustFwd     bool
}

// RequireBearer returns net/http middleware that validates OAuth 2.0 Bearer
// tokens. It returns an error if opts are invalid.
func RequireBearer(opts BearerOpts) (func(http.Handler) http.Handler, error) {
	if err := validateBearerOpts(opts); err != nil {
		return nil, err
	}

	algs, err := parseAlgs(opts.AllowedAlgorithms)
	if err != nil {
		return nil, err
	}

	ks, err := resolveKeySource(opts)
	if err != nil {
		return nil, err
	}

	realm, resourceMeta := deriveChallengeParams(opts)

	onError := opts.ErrorHandler
	if onError == nil {
		onError = defaultErrorHandler(realm, resourceMeta)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	emitter := opts.AuditEmitter
	if emitter == nil {
		emitter = noopEmitter{}
	}
	skew := opts.ClockSkew
	if skew == 0 {
		skew = 60 * time.Second
	}

	accepted := opts.Audience
	if opts.Resource != "" {
		accepted = append([]string{opts.Resource}, opts.Audience...)
	}

	dcfg, err := buildDPoPRuntime(opts)
	if err != nil {
		return nil, err
	}

	mw := &bearerMW{
		keys: ks, issuer: opts.Issuer, audiences: accepted, resource: opts.Resource,
		requiredScope: opts.RequiredScopes, skew: skew, algs: algs,
		claimVal: opts.ClaimValidator, onError: onError, logger: logger, emitter: emitter,
		dpopMode: opts.DPoP, dpopAlgs: dcfg.algs, dpopAlgsList: dcfg.algsList,
		proofMaxAge: dcfg.proofMaxAge, replay: dcfg.replay, nonce: opts.DPoPNonce,
		trustFwd: opts.TrustForwardedHeaders,
	}
	return mw.handler, nil
}

// dpopRuntime holds the resolved DPoP settings (allowlist + defaults).
type dpopRuntime struct {
	algs        map[string]struct{}
	algsList    []string
	proofMaxAge time.Duration
	replay      DPoPReplayCache
}

// buildDPoPRuntime resolves the DPoP proof-alg allowlist, proof max-age, and
// replay cache, applying defaults. It is a no-op (zero value) when DPoP is off
func buildDPoPRuntime(opts BearerOpts) (dpopRuntime, error) {
	if opts.DPoP == DPoPOff {
		return dpopRuntime{}, nil
	}
	names := opts.DPoPSigningAlgs
	if len(names) == 0 {
		names = []string{"ES256", "RS256", "EdDSA"}
	}
	algs, err := parseAlgs(names)
	if err != nil {
		return dpopRuntime{}, err
	}
	proofMaxAge := opts.DPoPProofMaxAge
	if proofMaxAge == 0 {
		proofMaxAge = 60 * time.Second
	}
	replay := opts.DPoPReplay
	if replay == nil {
		replay = InMemoryReplayCache()
	}
	return dpopRuntime{algs: algs, algsList: names, proofMaxAge: proofMaxAge, replay: replay}, nil
}

func validateBearerOpts(opts BearerOpts) error {
	if opts.KeysJWKS == nil && opts.JWKSURI == "" {
		return errors.New("aoa: BearerOpts requires KeysJWKS or JWKSURI")
	}
	if opts.Issuer == "" {
		return errors.New("aoa: BearerOpts.Issuer is required")
	}
	if opts.ClockSkew < 0 {
		return errors.New("aoa: BearerOpts.ClockSkew must not be negative")
	}
	if opts.DPoPProofMaxAge < 0 {
		return errors.New("aoa: BearerOpts.DPoPProofMaxAge must not be negative")
	}
	if opts.Resource == "" && len(opts.Audience) == 0 {
		return errors.New("aoa: BearerOpts requires Resource or Audience (audience validation is mandatory)")
	}
	if opts.TokenLookup != HeaderBearer {
		return errors.New("aoa: only HeaderBearer TokenLookup is supported in v0.1")
	}
	return nil
}

// resolveKeySource builds the keySource. KeysJWKS takes precedence over JWKSURI.
func resolveKeySource(opts BearerOpts) (keySource, error) {
	if opts.KeysJWKS != nil {
		set, err := jwk.Parse(opts.KeysJWKS)
		if err != nil {
			return nil, fmt.Errorf("aoa: parse KeysJWKS: %w", err)
		}
		if opts.JWKSURI != "" && opts.Logger != nil {
			opts.Logger.Warn("aoa: both KeysJWKS and JWKSURI set; KeysJWKS takes precedence")
		}
		return &staticKeySource{set: set}, nil
	}
	ttl := opts.JWKSCacheTTL
	if ttl <= 0 {
		ttl = defaultJWKSTTL
	}
	return newRemoteKeySource(opts.JWKSURI, ttl), nil
}

// deriveChallengeParams computes the WWW-Authenticate realm and the RFC 9728
// resource_metadata hint.
func deriveChallengeParams(opts BearerOpts) (realm, resourceMeta string) {
	realm = opts.Realm
	if realm == "" {
		if opts.Resource != "" {
			realm = opts.Resource
		} else {
			realm = "MCP"
		}
	}
	if opts.Resource != "" {
		if p, err := MetadataPathFor(opts.Resource); err == nil {
			resourceMeta = resourceMetadataURL(opts.Resource, p)
		}
	}
	return realm, resourceMeta
}

// resourceMetadataURL joins the resource origin with the RFC 9728 par.3.1 path.
// metadataPath already incorporates the resource's path component (see
// MetadataPathFor), so only the scheme and host are taken from resource.
func resourceMetadataURL(resource, metadataPath string) string {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		return resource + metadataPath
	}
	return u.Scheme + "://" + u.Host + metadataPath
}

func (m *bearerMW) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, raw, scheme, ok := m.authenticate(w, r)
		if !ok {
			return
		}
		if !m.enforceDPoP(w, r, raw, claims, scheme) {
			return
		}
		ctx := contextWithClaims(r.Context(), claims)
		m.emit(r, Event{Kind: EventTokenValidated, Outcome: OutcomeAllow}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate runs the access-token checks (extraction, signature, issuer,
// expiry, audience, scopes, claim validator). On any failure it writes the deny
// response + audit event and returns ok=false. On success it returns the
// validated claims, the raw token, and the canonical auth scheme.
func (m *bearerMW) authenticate(w http.ResponseWriter, r *http.Request) (claims *Claims, raw, scheme string, ok bool) {
	scheme, raw, found := extractToken(r)
	if !found {
		m.deny(w, r, m.noTokenError(), Event{Kind: EventTokenRejected, Reason: "no token"}, nil)
		return nil, "", "", false
	}
	if scheme == "DPoP" && m.dpopMode == DPoPOff {
		m.deny(w, r, errNoToken, Event{Kind: EventTokenRejected, Reason: "DPoP not enabled"}, nil)
		return nil, "", "", false
	}

	v := &tokenVerifier{keys: m.keys, issuer: m.issuer, skew: m.skew, algs: m.algs}
	claims, ve := v.verify(r.Context(), raw)
	if ve != nil {
		switch ve.kind {
		case verifyMalformed:
			m.deny(w, r, errInvalidToken("malformed token"),
				Event{Kind: EventTokenRejected, Error: "invalid_token", Reason: "header parse failed"}, nil)
		case verifyJWKS:
			m.deny(w, r, errInvalidToken("the access token is invalid"),
				Event{Kind: EventTokenRejected, Outcome: OutcomeError, Error: "invalid_token", Reason: ve.reason}, nil)
		default: // verifyDisallowedAlg, verifyInvalid
			m.deny(w, r, errInvalidToken("the access token is invalid"),
				Event{Kind: EventTokenRejected, Error: "invalid_token", Reason: ve.reason}, nil)
		}
		return nil, "", "", false
	}

	if !audienceMatches(claims.Audience, m.audiences) {
		m.deny(w, r, errInvalidToken("the access token is invalid"),
			Event{Kind: EventTokenRejected, Error: "invalid_token", Reason: "audience mismatch"}, claims)
		return nil, "", "", false
	}
	if missing := missingScopes(claims.Scope, m.requiredScope); len(missing) > 0 {
		m.deny(w, r, errInsufficientScope(m.requiredScope),
			Event{Kind: EventTokenRejected, Error: "insufficient_scope", Reason: "missing scopes: " + strings.Join(missing, " ")}, claims)
		return nil, "", "", false
	}
	if m.claimVal != nil {
		if err := m.claimVal(claims); err != nil {
			m.deny(w, r, errInvalidToken("the access token is invalid"),
				Event{Kind: EventTokenRejected, Error: "invalid_token", Reason: "claim validator: " + err.Error()}, claims)
			return nil, "", "", false
		}
	}
	return claims, raw, scheme, true
}

// enforceDPoP runs the DPoP stage when enabled. On rejection it writes the deny
// response + audit event and returns false; otherwise it returns true (and
// emits the dpop_verified event for a DPoP-scheme request).
func (m *bearerMW) enforceDPoP(w http.ResponseWriter, r *http.Request, raw string, claims *Claims, scheme string) bool {
	if m.dpopMode == DPoPOff {
		// The core rule still holds even when DPoP enforcement is off: a
		// sender-constrained token (one carrying cnf.jkt) is never honored as
		// a plain Bearer token (RFC 9449 par.7.1). That is the downgrade attack
		// DPoP exists to prevent. The proof cannot be verified in Off mode
		// (the DPoP machinery is not configured), so such a request is
		// rejected with a DPoP challenge. Un-bound tokens are unaffected.
		if claims.boundKeyThumbprint() != "" {
			ae := errWrongScheme(m.dpopAlgsList)
			m.deny(w, r, ae, Event{Kind: EventDPoPRejected, Error: ae.code,
				Reason: "sender-constrained token presented as Bearer (DPoP off)"}, claims)
			return false
		}
		return true
	}
	if ae := m.verifyDPoP(r, raw, claims, scheme); ae != nil {
		kind := EventDPoPRejected
		if ae.auditKind != "" {
			kind = ae.auditKind
		}
		ev := Event{Kind: kind, Error: ae.code, Reason: ae.reason}
		if ae.auditOutcome != "" {
			ev.Outcome = ae.auditOutcome
		}
		m.deny(w, r, ae, ev, claims)
		return false
	}
	if scheme == "DPoP" {
		m.emit(r, Event{Kind: EventDPoPVerified, Outcome: OutcomeAllow}, claims)
	}
	return true
}

// extractToken returns the auth scheme ("Bearer" or "DPoP") and token from a
// single Authorization header. ok is false if absent, malformed, empty, or an
// unrecognized scheme.
func extractToken(r *http.Request) (scheme, token string, ok bool) {
	h := r.Header.Values("Authorization")
	if len(h) != 1 {
		return "", "", false
	}
	parts := strings.SplitN(h[0], " ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	t := strings.TrimSpace(parts[1])
	if t == "" {
		return "", "", false
	}
	switch {
	case strings.EqualFold(parts[0], "Bearer"):
		return "Bearer", t, true
	case strings.EqualFold(parts[0], "DPoP"):
		return "DPoP", t, true
	default:
		return "", "", false
	}
}

// noTokenError selects the no-token challenge for the configured DPoP mode.
func (m *bearerMW) noTokenError() *authError {
	switch m.dpopMode {
	case DPoPRequired:
		return errDPoPRequired(m.dpopAlgsList)
	case DPoPOptional:
		return errNoTokenDPoPOptional(m.dpopAlgsList)
	default:
		return errNoToken
	}
}

// headerKIDAlg reads the kid and alg from the JWS protected header without
// verifying the signature.
func headerKIDAlg(raw string) (kid, alg string, err error) {
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return "", "", err
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return "", "", errors.New("no signatures")
	}
	h := sigs[0].ProtectedHeaders()
	kid, _ = h.KeyID()
	if a, ok := h.Algorithm(); ok {
		alg = a.String()
	}
	return kid, alg, nil
}

// deny emits an audit event and writes the challenge. For post-parse
// rejections (audience/scope/claim-validator) pass the parsed claims so the
// audit event carries the token's identity; pass nil before the token is parsed.
func (m *bearerMW) deny(w http.ResponseWriter, r *http.Request, ae *authError, ev Event, c *Claims) {
	if ev.Outcome == "" {
		ev.Outcome = OutcomeDeny
	}
	m.emit(r, ev, c)
	m.onError(w, r, ae)
}

func (m *bearerMW) emit(r *http.Request, ev Event, c *Claims) {
	ev.Timestamp = time.Now().UTC()
	ev.Resource = m.resource
	ev.HTTP = HTTPContext{Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr, UserAgent: r.UserAgent()}
	if c != nil {
		ev.Subject = c.Subject
		ev.Issuer = c.Issuer
		ev.Audience = c.Audience
		ev.Scope = c.Scope
	}
	m.emitter.Emit(r.Context(), ev)
}

// parseAlgs validates the allowlist (default RS256/ES256/EdDSA), rejecting none and symmetric HS*.
func parseAlgs(names []string) (map[string]struct{}, error) {
	if len(names) == 0 {
		names = []string{"RS256", "ES256", "EdDSA"}
	}
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n == "none" || strings.HasPrefix(n, "HS") {
			return nil, fmt.Errorf("aoa: algorithm %q is not allowed (asymmetric only)", n)
		}
		alg, ok := jwa.LookupSignatureAlgorithm(n)
		if !ok {
			return nil, fmt.Errorf("aoa: unknown algorithm %q", n)
		}
		if alg.IsSymmetric() {
			return nil, fmt.Errorf("aoa: algorithm %q is symmetric and not allowed", n)
		}
		out[n] = struct{}{}
	}
	return out, nil
}

// audienceMatches reports whether the token's aud intersects accepted (RFC 8707).
func audienceMatches(aud, accepted []string) bool {
	return slices.ContainsFunc(aud, func(a string) bool {
		return slices.Contains(accepted, a)
	})
}

// missingScopes returns required scopes absent from granted (AND semantics).
func missingScopes(granted, required []string) []string {
	var missing []string
	for _, s := range required {
		if !slices.Contains(granted, s) {
			missing = append(missing, s)
		}
	}
	return missing
}
