package aoa

import "testing"

// FuzzHeaderKIDAlg feeds arbitrary token strings to the header reader. The
// primary property is that it never panics on untrusted input (a panic surfaces
// as a fuzz crash). The error-path assertion below is a regression guard: an
// error must never leak a partial kid/alg. A successful parse may return an
// empty alg; an alg-less header is a legitimate parse result that verify
// rejects later, so the success path is intentionally not asserted here.
func FuzzHeaderKIDAlg(f *testing.F) {
	f.Add("")
	f.Add("not.a.jwt")
	f.Add("....")
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30.")
	f.Fuzz(func(t *testing.T, raw string) {
		kid, alg, err := headerKIDAlg(raw)
		if err != nil && (kid != "" || alg != "") {
			t.Fatalf("error result must have empty kid/alg, got kid=%q alg=%q err=%v", kid, alg, err)
		}
	})
}
