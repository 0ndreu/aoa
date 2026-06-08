package aoa

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// dpopProof is a parsed, signature-verified DPoP proof.
type dpopProof struct {
	jkt   string // base64url RFC 7638 thumbprint of the embedded public key
	htm   string
	htu   string
	iat   time.Time
	jti   string
	ath   string
	nonce string
}

type proofClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath"`
	Nonce string `json:"nonce"`
}

// parseAndVerifyProof parses raw as a DPoP proof JWS, enforces the header
// invariants (typ=dpop+jwt, alg in allowedAlgs, a public jwk), verifies the
// signature against the embedded key, and returns the decoded proof. It does
// NOT check htm/htu/iat/ath/cnf/nonce/replay - those are request-context checks
// done in verifyDPoP.
func parseAndVerifyProof(raw []byte, allowedAlgs map[string]struct{}) (*dpopProof, error) {
	msg, err := jws.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse proof: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, errors.New("proof has no signature")
	}
	h := sigs[0].ProtectedHeaders()

	if typ, ok := h.Type(); !ok || typ != "dpop+jwt" {
		return nil, fmt.Errorf("proof typ = %q, want dpop+jwt", typ)
	}
	alg, ok := h.Algorithm()
	if !ok {
		return nil, errors.New("proof missing alg")
	}
	if _, allowed := allowedAlgs[alg.String()]; !allowed {
		return nil, fmt.Errorf("proof alg %q not allowed", alg.String())
	}
	key, ok := h.JWK()
	if !ok {
		return nil, errors.New("proof missing jwk header")
	}
	if priv, err := jwk.IsPrivateKey(key); err != nil || priv {
		return nil, errors.New("proof jwk must be a public key")
	}

	payload, err := jws.Verify(raw, jws.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("proof signature: %w", err)
	}

	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("thumbprint: %w", err)
	}

	var c proofClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("proof claims: %w", err)
	}
	return &dpopProof{
		jkt:   base64.RawURLEncoding.EncodeToString(tp),
		htm:   c.HTM,
		htu:   c.HTU,
		iat:   time.Unix(c.IAT, 0),
		jti:   c.JTI,
		ath:   c.ATH,
		nonce: c.Nonce,
	}, nil
}
