package aoa

import "testing"

func TestTokenTypeOrDefault(t *testing.T) {
	if got := TokenType("").orDefault(); got != TokenTypeAccessToken {
		t.Fatalf("empty should default to access_token, got %s", got)
	}
	if got := TokenTypeIDToken.orDefault(); got != TokenTypeIDToken {
		t.Fatalf("non-empty should pass through, got %s", got)
	}
}
