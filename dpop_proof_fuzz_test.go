package aoa

import "testing"

// FuzzParseAndVerifyProof feeds arbitrary bytes to the DPoP proof parser. It
// must never panic, and the (proof, err) contract must hold in both directions:
// a successful parse yields a non-nil proof, and a failure yields a nil proof.
func FuzzParseAndVerifyProof(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("garbage"))
	f.Add([]byte("a.b.c"))
	f.Add([]byte("eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0.e30."))
	allowed := allAlgs() // production-representative allowlist: ES256/RS256/EdDSA
	f.Fuzz(func(t *testing.T, raw []byte) {
		proof, err := parseAndVerifyProof(raw, allowed)
		if err == nil && proof == nil {
			t.Fatal("nil error but nil proof")
		}
		if err != nil && proof != nil {
			t.Fatalf("non-nil proof with non-nil error: %v", err)
		}
	})
}
