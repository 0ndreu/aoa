package aoa

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ClientAuth attaches client credentials to an outgoing token request. It is
// implemented by ClientSecretAuth and PrivateKeyJWTAuth; mTLS needs no
// implementation (configure it on ExchangeConfig.HTTPClient's transport).
type ClientAuth interface {
	// apply mutates req headers and/or the form body in place to carry the
	// client's credentials. It must not leak jwx types.
	apply(ctx context.Context, req *http.Request, form url.Values) error
}

type secretAuth struct {
	clientID, secret string
	post             bool
}

// ClientSecretAuth authenticates with a client secret. post=false uses HTTP
// Basic (client_secret_basic); post=true uses form fields (client_secret_post).
func ClientSecretAuth(clientID, secret string, post bool) ClientAuth {
	return &secretAuth{clientID: clientID, secret: secret, post: post}
}

func (a *secretAuth) apply(_ context.Context, req *http.Request, form url.Values) error {
	if a.post {
		form.Set("client_id", a.clientID)
		form.Set("client_secret", a.secret)
		return nil
	}
	req.SetBasicAuth(a.clientID, a.secret)
	return nil
}

type privateKeyJWTAuth struct {
	clientID string
	key      jwk.Key
	alg      jwa.SignatureAlgorithm
}

// PrivateKeyJWTAuth authenticates with a signed JWT assertion (RFC 7523 /
// private_key_jwt). key is a PEM- or JWK-encoded asymmetric private key; alg is
// its signature algorithm (e.g. "ES256", "RS256", "EdDSA"). Symmetric algs and
// "none" are rejected.
func PrivateKeyJWTAuth(clientID string, key []byte, alg string) (ClientAuth, error) {
	sigAlg, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		return nil, fmt.Errorf("aoa: unknown algorithm %q", alg)
	}
	if alg == "none" || sigAlg.IsSymmetric() {
		return nil, fmt.Errorf("aoa: algorithm %q not allowed for private_key_jwt (asymmetric only)", alg)
	}
	k, err := parsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &privateKeyJWTAuth{clientID: clientID, key: k, alg: sigAlg}, nil
}

func (a *privateKeyJWTAuth) apply(_ context.Context, req *http.Request, form url.Values) error {
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(a.clientID).
		Subject(a.clientID).
		Audience([]string{tokenEndpointURL(req)}).
		IssuedAt(now).
		Expiration(now.Add(60 * time.Second)).
		JwtID(randomID()).
		Build()
	if err != nil {
		return fmt.Errorf("aoa: build client assertion: %w", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(a.alg, a.key))
	if err != nil {
		return fmt.Errorf("aoa: sign client assertion: %w", err)
	}
	form.Set("client_id", a.clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", string(signed))
	return nil
}

// tokenEndpointURL returns the request's full URL, the RFC 7523 audience for the
// client assertion.
func tokenEndpointURL(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	return req.URL.String()
}

// parsePrivateKey accepts a PEM (PKCS#8/PKCS#1/SEC1) or JWK private key.
func parsePrivateKey(b []byte) (jwk.Key, error) {
	if block, _ := pem.Decode(b); block != nil {
		raw, err := parsePEMKey(block)
		if err != nil {
			return nil, err
		}
		k, err := jwk.Import(raw)
		if err != nil {
			return nil, fmt.Errorf("aoa: import key: %w", err)
		}
		return k, nil
	}
	k, err := jwk.ParseKey(b) // JWK JSON
	if err != nil {
		return nil, fmt.Errorf("aoa: parse private key (want PEM or JWK): %w", err)
	}
	return k, nil
}

func parsePEMKey(block *pem.Block) (any, error) {
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("aoa: unsupported PEM private key format")
}
