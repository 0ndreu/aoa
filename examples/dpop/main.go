package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/0ndreu/aoa"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	resource = "https://mcp.example.com"
	issuer   = "https://idp.example.com"
)

func main() {
	// authorization-server key that signs access tokens
	asRaw, _ := rsa.GenerateKey(rand.Reader, 2048)
	asPriv, _ := jwk.Import(asRaw)
	_ = asPriv.Set(jwk.KeyIDKey, "kid-as")
	_ = asPriv.Set(jwk.AlgorithmKey, jwa.RS256())
	asPub, _ := jwk.PublicKeyOf(asPriv)
	set := jwk.NewSet()
	_ = set.AddKey(asPub)
	jwksJSON, _ := json.Marshal(set)

	// client DPoP key; its thumbprint (jkt) binds the access token
	cRaw, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cPriv, _ := jwk.Import(cRaw)
	_ = cPriv.Set(jwk.AlgorithmKey, jwa.ES256())
	cPub, _ := jwk.PublicKeyOf(cPriv)
	tp, _ := cPub.Thumbprint(crypto.SHA256)
	jkt := base64.RawURLEncoding.EncodeToString(tp)

	// protected resource server, DPoP required
	mw, err := aoa.RequireBearer(aoa.BearerOpts{
		Resource: resource,
		Issuer:   issuer,
		KeysJWKS: jwksJSON,
		DPoP:     aoa.DPoPRequired,
	})
	if err != nil {
		log.Fatal(err)
	}
	protected := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello, DPoP-authenticated caller\n"))
	}))
	srv := httptest.NewTLSServer(protected)
	defer srv.Close()
	target := srv.URL + "/mcp"
	client := srv.Client()

	// mint an access token bound to the client key via cnf.jkt
	tok, _ := jwt.NewBuilder().
		Issuer(issuer).Audience([]string{resource}).Subject("user-1").
		Expiration(time.Now().Add(time.Hour)).
		Claim("cnf", map[string]any{"jkt": jkt}).
		Build()
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), asPriv))
	accessToken := string(signed)

	// a valid DPoP call: access token plus a matching proof
	req, _ := http.NewRequest("POST", target, nil)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", makeProof(cPriv, cPub, "POST", target, ath(accessToken)))
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("DPoP call    -> %s\n", resp.Status)
	_ = resp.Body.Close()

	// downgrade attempt: same token as plain Bearer
	bad, _ := http.NewRequest("POST", target, nil)
	bad.Header.Set("Authorization", "Bearer "+accessToken)
	resp2, _ := client.Do(bad)
	fmt.Printf("Bearer call  -> %s | WWW-Authenticate: %s\n", resp2.Status, resp2.Header.Get("WWW-Authenticate"))
	_ = resp2.Body.Close()
}

func ath(token string) string {
	s := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func makeProof(priv, pub jwk.Key, method, htu, ath string) string {
	payload, _ := json.Marshal(map[string]any{
		"jti": fmt.Sprintf("%d", time.Now().UnixNano()),
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
		"ath": ath,
	})
	hdr := jws.NewHeaders()
	_ = hdr.Set("typ", "dpop+jwt")
	_ = hdr.Set("jwk", pub)
	signed, _ := jws.Sign(payload, jws.WithKey(jwa.ES256(), priv, jws.WithProtectedHeaders(hdr)))
	return string(signed)
}
