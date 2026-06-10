package aoa

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// verifyDPoP runs the DPoP stage after the access token is verified. It returns
// nil to allow the request, or an *authError to reject it. scheme is the
// Authorization scheme used for the access token ("Bearer" or "DPoP"), already
// normalized to its canonical form by extractToken.
//
// The core rule (RFC 9449 par.7.1): a token carrying cnf.jkt is
// sender-constrained and is NEVER accepted as plain Bearer, in any mode.
// Enforcement for Optional/Required modes lives here; the DPoPOff case is
// gated in (*bearerMW).enforceDPoP, which never reaches here.
func (m *bearerMW) verifyDPoP(r *http.Request, accessToken string, claims *Claims, scheme string) *authError {
	if scheme != "DPoP" {
		return m.gateBearer(r, claims)
	}
	return m.verifyProof(r, accessToken, claims)
}

// gateBearer decides whether a token presented under the Bearer scheme is
// acceptable while DPoP is enabled. Required forbids Bearer entirely; a
// cnf.jkt-bound token is never accepted as Bearer (downgrade defense); a stray
// DPoP header alongside Bearer is a scheme/proof mismatch.
func (m *bearerMW) gateBearer(r *http.Request, claims *Claims) *authError {
	if m.dpopMode == DPoPRequired {
		return errWrongScheme(m.dpopAlgsList)
	}
	if claims.boundKeyThumbprint() != "" {
		return errWrongScheme(m.dpopAlgsList)
	}
	if len(r.Header.Values("DPoP")) > 0 {
		return errInvalidDPoPProof("DPoP header present with Bearer scheme")
	}
	return nil // Optional + un-bound token: accept as Bearer, no proof needed
}

// verifyProof fully validates a request presented under the DPoP scheme:
// exactly one parseable+signed proof, the request-context claim checks, the
// cnf.jkt binding, the optional nonce, and replay protection.
func (m *bearerMW) verifyProof(r *http.Request, accessToken string, claims *Claims) *authError {
	if claims.boundKeyThumbprint() == "" {
		return errInvalidDPoPProof("access token is not DPoP-bound")
	}
	headers := r.Header.Values("DPoP")
	if len(headers) != 1 {
		return errInvalidDPoPProof("expected exactly one DPoP header")
	}
	proof, err := parseAndVerifyProof([]byte(headers[0]), m.dpopAlgs)
	if err != nil {
		return errInvalidDPoPProof(err.Error())
	}
	if ae := m.checkProofClaims(r, accessToken, claims, proof); ae != nil {
		return ae
	}
	if ae := m.checkNonce(r, proof); ae != nil {
		return ae
	}
	return m.checkReplay(r, proof)
}

// checkProofClaims validates the request-bound proof claims: jti present, htm,
// htu, iat window, ath, and the cnf.jkt thumbprint binding.
func (m *bearerMW) checkProofClaims(r *http.Request, accessToken string, claims *Claims, proof *dpopProof) *authError {
	if proof.jti == "" {
		return errInvalidDPoPProof("proof missing jti")
	}
	if !strings.EqualFold(proof.htm, r.Method) {
		return errInvalidDPoPProof("htm mismatch")
	}
	if !htuEqual(proof.htu, requestHTU(r, m.trustFwd)) {
		return errInvalidDPoPProof("htu mismatch")
	}
	now := time.Now()
	if proof.iat.Before(now.Add(-m.proofMaxAge)) || proof.iat.After(now.Add(m.skew)) {
		return errInvalidDPoPProof("iat out of window")
	}
	if proof.ath != athFor(accessToken) {
		return errInvalidDPoPProof("ath mismatch")
	}
	if proof.jkt != claims.boundKeyThumbprint() {
		return errInvalidDPoPProof("cnf.jkt mismatch")
	}
	return nil
}

// checkNonce enforces the server-issued nonce when a source is configured.
func (m *bearerMW) checkNonce(r *http.Request, proof *dpopProof) *authError {
	if m.nonce == nil {
		return nil
	}
	if proof.nonce == "" || !m.nonce.Valid(r.Context(), r, proof.nonce) {
		ae := errUseDPoPNonce(m.dpopAlgsList)
		ae.nonce = m.nonce.Current(r.Context(), r)
		return ae
	}
	return nil
}

// checkReplay records the proof's jti and fails closed on a backend error.
func (m *bearerMW) checkReplay(r *http.Request, proof *dpopProof) *authError {
	seen, err := m.replay.Seen(r.Context(), proof.jti, proof.iat.Add(m.proofMaxAge))
	if err != nil {
		ae := errInvalidDPoPProof("replay backend error")
		ae.auditOutcome = OutcomeError // fail closed, mark as infra error
		return ae
	}
	if seen {
		ae := errInvalidDPoPProof("jti replay")
		ae.auditKind = EventJTIReplay
		return ae
	}
	return nil
}

// athFor computes the RFC 9449 ath claim: base64url(SHA-256(access token)).
func athFor(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// requestHTU reconstructs the HTTP target URI for htu comparison: scheme + host
// + path, no query/fragment. When trustFwd is set, X-Forwarded-Proto/-Host
// override the request's own scheme/host (for an RS behind a trusted proxy).
func requestHTU(r *http.Request, trustFwd bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if trustFwd {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = p
		}
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = h
		}
	}
	return scheme + "://" + host + r.URL.Path
}

// htuEqual compares two htu values, case-insensitive on scheme/host and exact
// on path (query/fragment are ignored).
func htuEqual(a, b string) bool {
	pa, ea := url.Parse(a)
	pb, eb := url.Parse(b)
	if ea != nil || eb != nil {
		return false
	}
	return strings.EqualFold(pa.Scheme, pb.Scheme) &&
		strings.EqualFold(pa.Host, pb.Host) &&
		pa.Path == pb.Path
}
