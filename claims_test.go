package aoa

import (
	"context"
	"testing"
)

func TestClaimsFromContext_RoundTrip(t *testing.T) {
	want := &Claims{Subject: "user-123", Scope: []string{"mcp:read"}}
	ctx := contextWithClaims(context.Background(), want)

	got, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.Subject != "user-123" {
		t.Errorf("subject = %q, want user-123", got.Subject)
	}
}

func TestClaimsFromContext_AbsentReturnsFalse(t *testing.T) {
	if _, ok := ClaimsFromContext(context.Background()); ok {
		t.Error("expected ok=false for empty context")
	}
}

func TestClaims_Decode(t *testing.T) {
	c := &Claims{raw: []byte(`{"sub":"u1","tenant":"acme"}`)}
	var got struct {
		Tenant string `json:"tenant"`
	}
	if err := c.Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Tenant != "acme" {
		t.Errorf("tenant = %q, want acme", got.Tenant)
	}
}

func TestClaims_BoundKeyThumbprint(t *testing.T) {
	c := &Claims{raw: []byte(`{"sub":"u1","cnf":{"jkt":"abc123"}}`)}
	c.extractCnf()
	if got := c.boundKeyThumbprint(); got != "abc123" {
		t.Errorf("boundKeyThumbprint = %q, want abc123", got)
	}
}

func TestClaims_BoundKeyThumbprint_AbsentEmpty(t *testing.T) {
	c := &Claims{raw: []byte(`{"sub":"u1"}`)}
	c.extractCnf()
	if got := c.boundKeyThumbprint(); got != "" {
		t.Errorf("boundKeyThumbprint = %q, want empty", got)
	}
}
