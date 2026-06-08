package aoa

import (
	"fmt"
	"net/http"
	"strings"
)

// authError represents an auth failure and maps to an RFC 6750 / RFC 9449
// WWW-Authenticate challenge.
type authError struct {
	status      int      // 401 or 403
	code        string   // RFC 6750 error code; "" means none (e.g. no token)
	description string   // human-readable; never leaks internals
	scopes      []string // required scopes, for insufficient_scope

	scheme       string    // "Bearer" (default/zero) or "DPoP"
	algs         []string  // DPoP challenge "algs" param
	nonce        string    // value for the DPoP-Nonce response header (use_dpop_nonce)
	withBearer   bool      // also emit a separate Bearer challenge (Optional/no-token)
	reason       string    // specific internal reason, for the audit event only (never sent to the client)
	auditOutcome Outcome   // overrides the default Deny outcome (e.g. Error for backend failures)
	auditKind    EventKind // overrides the default EventDPoPRejected kind (e.g. EventJTIReplay)
}

func (e *authError) Error() string {
	if e.code == "" {
		return fmt.Sprintf("aoa: unauthorized (%d)", e.status)
	}
	return fmt.Sprintf("aoa: %s: %s", e.code, e.description)
}

var errNoToken = &authError{status: http.StatusUnauthorized}

func errInvalidToken(desc string) *authError {
	return &authError{status: http.StatusUnauthorized, code: "invalid_token", description: desc}
}

func errInsufficientScope(required []string) *authError {
	return &authError{
		status:      http.StatusForbidden,
		code:        "insufficient_scope",
		description: "the request requires higher privileges than provided by the access token",
		scopes:      required,
	}
}

// errDPoPRequired: DPoPRequired mode, no/Bearer token presented - tell the
// client to use DPoP. No error code (mirrors the no-token Bearer challenge).
func errDPoPRequired(algs []string) *authError {
	return &authError{status: http.StatusUnauthorized, scheme: "DPoP", algs: algs}
}

// errNoTokenDPoPOptional: Optional mode, no token at all - advertise both schemes.
func errNoTokenDPoPOptional(algs []string) *authError {
	return &authError{status: http.StatusUnauthorized, scheme: "DPoP", algs: algs, withBearer: true}
}

// errWrongScheme: a DPoP-bound token presented as Bearer, or Bearer used under
// DPoPRequired. Rejected with a DPoP challenge so the client re-presents bound.
func errWrongScheme(algs []string) *authError {
	return &authError{status: http.StatusUnauthorized, code: "invalid_token",
		description: "the access token requires a DPoP proof", scheme: "DPoP", algs: algs}
}

// errInvalidDPoPProof: the DPoP proof failed verification. Description stays
// generic; the specific reason is preserved in .reason for the audit event only.
func errInvalidDPoPProof(reason string) *authError {
	return &authError{status: http.StatusUnauthorized, code: "invalid_token",
		description: "the DPoP proof is invalid", scheme: "DPoP", reason: reason}
}

// errUseDPoPNonce: the RS requires a server nonce. Caller sets .nonce before use.
func errUseDPoPNonce(algs []string) *authError {
	return &authError{status: http.StatusUnauthorized, code: "use_dpop_nonce",
		description: "authorization server requires nonce in DPoP proof", scheme: "DPoP", algs: algs}
}

// defaultErrorHandler returns the error handler used when BearerOpts.ErrorHandler is nil.
func defaultErrorHandler(realm, resourceMeta string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, _ *http.Request, err error) {
		ae, ok := err.(*authError)
		if !ok {
			ae = errInvalidToken("the access token is invalid")
		}
		if ae.nonce != "" {
			w.Header().Set("DPoP-Nonce", ae.nonce)
		}
		if ae.withBearer {
			w.Header().Add("WWW-Authenticate", buildChallenge(&authError{status: ae.status, scheme: "Bearer"}, realm, resourceMeta))
		}
		w.Header().Add("WWW-Authenticate", buildChallenge(ae, realm, resourceMeta))
		w.WriteHeader(ae.status)
	}
}

// buildChallenge builds a WWW-Authenticate value for ae's scheme (Bearer or
// DPoP) per RFC 6750 par.3 / RFC 9449 par.7.1, plus the RFC 9728 resource_metadata
// hint when set.
func buildChallenge(ae *authError, realm, resourceMeta string) string {
	scheme := ae.scheme
	if scheme == "" {
		scheme = "Bearer"
	}
	var params []string
	if realm != "" {
		params = append(params, kv("realm", realm))
	}
	if ae.code != "" {
		params = append(params, kv("error", ae.code))
		if ae.description != "" {
			params = append(params, kv("error_description", ae.description))
		}
	}
	if ae.code == "insufficient_scope" && len(ae.scopes) > 0 {
		params = append(params, kv("scope", strings.Join(ae.scopes, " ")))
	}
	if scheme == "DPoP" && len(ae.algs) > 0 {
		params = append(params, kv("algs", strings.Join(ae.algs, " ")))
	}
	if resourceMeta != "" {
		params = append(params, kv("resource_metadata", resourceMeta))
	}
	return scheme + " " + strings.Join(params, ", ")
}

func kv(k, v string) string { return fmt.Sprintf("%s=%q", k, v) }
