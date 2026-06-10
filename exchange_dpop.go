package aoa

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// DPoPKey is a client-held asymmetric key pair used to mint DPoP proofs when
// exchanging tokens (RFC 9449 par.5). Construct it with NewDPoPKey. jwx is hidden:
// the caller supplies key bytes and never touches a jwx type.
//
// invariant: all fields are set together on success; private==nil iff zero value (see isZero).
type DPoPKey struct {
	private jwk.Key
	public  jwk.Key
	alg     jwa.SignatureAlgorithm
	jkt     string
}

// NewDPoPKey wraps a PEM- or JWK-encoded asymmetric private key for DPoP proof
// signing. Symmetric keys and unparseable input are rejected.
func NewDPoPKey(key []byte) (DPoPKey, error) {
	priv, err := parsePrivateKey(key)
	if err != nil {
		return DPoPKey{}, err
	}
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		return DPoPKey{}, fmt.Errorf("aoa: derive public key: %w", err)
	}
	alg, err := dpopAlgForKey(priv)
	if err != nil {
		return DPoPKey{}, err
	}
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return DPoPKey{}, fmt.Errorf("aoa: thumbprint: %w", err)
	}
	return DPoPKey{private: priv, public: pub, alg: alg,
		jkt: base64.RawURLEncoding.EncodeToString(tp)}, nil
}

func (k DPoPKey) isZero() bool       { return k.private == nil }
func (k DPoPKey) thumbprint() string { return k.jkt }

// proofFor mints a token-endpoint DPoP proof: typ=dpop+jwt, htm, htu (query and
// fragment must already be stripped by the caller), fresh jti, iat=now, and the
// embedded public jwk. No ath, since no access token is presented at this endpoint.
// nonce, when non-empty, is included (use_dpop_nonce retry).
func (k DPoPKey) proofFor(htm, htu, nonce string) (string, error) {
	payload := map[string]any{
		"jti": randomID(),
		"htm": htm,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("aoa: marshal proof: %w", err)
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set("typ", "dpop+jwt")
	_ = hdr.Set("jwk", k.public)
	signed, err := jws.Sign(body, jws.WithKey(k.alg, k.private, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", fmt.Errorf("aoa: sign proof: %w", err)
	}
	return string(signed), nil
}

// dpopAlgForKey picks the DPoP signature algorithm from the key type:
// P-256 EC -> ES256 (other EC curves are rejected per RFC 7518 par.3.4),
// RSA -> RS256 (jwx enforces the 2048-bit minimum at import, so no extra check
// is needed here), OKP -> EdDSA.
func dpopAlgForKey(k jwk.Key) (jwa.SignatureAlgorithm, error) {
	switch k.KeyType() {
	case jwa.EC():
		eck, ok := k.(jwk.ECDSAPrivateKey)
		if !ok {
			return jwa.SignatureAlgorithm{}, fmt.Errorf("aoa: unexpected EC key type %T", k)
		}
		crv, _ := eck.Crv()
		if crv != jwa.P256() {
			return jwa.SignatureAlgorithm{}, fmt.Errorf("aoa: DPoP EC key must use curve P-256 (ES256), got %s", crv)
		}
		return jwa.ES256(), nil
	case jwa.RSA():
		// jwx enforces the 2048-bit RSA minimum at import; no redundant check needed.
		return jwa.RS256(), nil
	case jwa.OKP():
		return jwa.EdDSA(), nil
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("aoa: unsupported DPoP key type %q", k.KeyType())
	}
}
