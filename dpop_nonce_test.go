package aoa

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestHMACNonce_CurrentIsValid(t *testing.T) {
	ns := NewDPoPNonceSource([]byte("secret-key"))
	r := httptest.NewRequest("POST", "https://mcp.example.com/mcp", nil)
	n := ns.Current(context.Background(), r)
	if n == "" {
		t.Fatal("Current returned empty nonce")
	}
	if !ns.Valid(context.Background(), r, n) {
		t.Error("freshly issued nonce rejected")
	}
}

func TestHMACNonce_TamperedRejected(t *testing.T) {
	ns := NewDPoPNonceSource([]byte("secret-key"))
	r := httptest.NewRequest("POST", "https://mcp.example.com/mcp", nil)
	if ns.Valid(context.Background(), r, "not-a-real-nonce") {
		t.Error("garbage nonce accepted")
	}
	other := NewDPoPNonceSource([]byte("different-secret"))
	if ns.Valid(context.Background(), r, other.Current(context.Background(), r)) {
		t.Error("nonce from a different secret accepted")
	}
}
