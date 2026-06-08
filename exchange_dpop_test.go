package aoa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/0ndreu/aoa/internal/jwktest"
)

func TestNewDPoPKey_RejectsSymmetric(t *testing.T) {
	if _, err := NewDPoPKey([]byte("not a key")); err == nil {
		t.Fatal("garbage key must error")
	}
}

func TestDPoPKey_ProofForTokenEndpoint(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	key, err := NewDPoPKey(s.PrivatePEM(t))
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	proof, err := key.proofFor("POST", "https://as.example.com/token", "")
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	algs, _ := parseAlgs([]string{"ES256", "RS256", "EdDSA"})
	dp, err := parseAndVerifyProof([]byte(proof), algs)
	if err != nil {
		t.Fatalf("self-verify: %v", err)
	}
	if dp.htm != "POST" || dp.htu != "https://as.example.com/token" {
		t.Fatalf("htm/htu wrong: %s %s", dp.htm, dp.htu)
	}
	if dp.jkt != key.thumbprint() {
		t.Fatalf("jkt mismatch")
	}
	if dp.ath != "" {
		t.Fatal("token-endpoint proof must not carry ath")
	}
}

func TestDPoPKey_ProofWithNonce(t *testing.T) {
	s := jwktest.NewECSigner(t, "")
	key, err := NewDPoPKey(s.PrivatePEM(t))
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	proof, err := key.proofFor("POST", "https://as.example.com/token", "srv-nonce-1")
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	algs, _ := parseAlgs([]string{"ES256", "RS256", "EdDSA"})
	dp, err := parseAndVerifyProof([]byte(proof), algs)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if dp.nonce != "srv-nonce-1" {
		t.Fatalf("nonce = %q", dp.nonce)
	}
}

func TestDPoPKey_RSARoundTrip(t *testing.T) {
	s := jwktest.NewRSASigner(t, "")
	key, err := NewDPoPKey(s.PrivatePEM(t))
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	proof, err := key.proofFor("POST", "https://as/token", "")
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	algs, _ := parseAlgs([]string{"ES256", "RS256", "EdDSA"})
	dp, err := parseAndVerifyProof([]byte(proof), algs)
	if err != nil {
		t.Fatalf("self-verify: %v", err)
	}
	if dp.jkt != key.thumbprint() {
		t.Fatalf("jkt mismatch: got %q, want %q", dp.jkt, key.thumbprint())
	}
}

func TestNewDPoPKey_RejectsNonP256EC(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(raw)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := NewDPoPKey(pemBytes); err == nil {
		t.Fatal("P-384 EC key must be rejected")
	}
}
