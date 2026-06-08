package jwktest

import (
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func TestSigner_AndServer(t *testing.T) {
	s := NewRSASigner(t, "kid-1")
	srv := NewJWKSServer(t, s.PublicSet(t))

	resp, err := http.Get(srv.URL())
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d", resp.StatusCode)
	}

	signed := s.Sign(t, jwt.NewBuilder().Subject("u1").Issuer("https://idp.example.com"))
	if len(signed) == 0 {
		t.Fatal("empty signed token")
	}
}
