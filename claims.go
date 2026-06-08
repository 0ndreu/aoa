package aoa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Claims holds the verified claims from an access token. Standard registered
// claims are fields; use Decode to access non-registered claims.
type Claims struct {
	Subject   string
	Issuer    string
	Audience  []string
	Expiry    time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	Scope     []string // parsed from the space-delimited "scope" claim

	raw    []byte // verified JSON payload, for Decode
	cnfJKT string // value of cnf.jkt, if present (DPoP binding thumbprint)
}

// Decode unmarshals the full token payload into v, giving access to
// non-registered claims. v must be a pointer to a struct or map.
func (c *Claims) Decode(v any) error {
	if len(c.raw) == 0 {
		return errors.New("aoa: no claim payload")
	}
	return json.Unmarshal(c.raw, v)
}

type claimsCtxKey struct{}

func contextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, c)
}

// ClaimsFromContext returns the claims stored by RequireBearer, or false if the
// request has no validated token.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey{}).(*Claims)
	return c, ok
}

func newClaims(t jwt.Token, raw string) *Claims {
	c := &Claims{}
	if v, ok := t.Subject(); ok {
		c.Subject = v
	}
	if v, ok := t.Issuer(); ok {
		c.Issuer = v
	}
	if v, ok := t.Audience(); ok {
		c.Audience = v
	}
	if v, ok := t.Expiration(); ok {
		c.Expiry = v
	}
	if v, ok := t.IssuedAt(); ok {
		c.IssuedAt = v
	}
	if v, ok := t.NotBefore(); ok {
		c.NotBefore = v
	}
	// "scope" is a space-delimited string per RFC 8693, but Azure AD, Auth0, and
	// some token-exchange flows emit it as a JSON array. Accept both. jwx parses
	// a JSON array as []any, so coerce its string elements rather than asking for
	// []string directly (which the underlying AssignIfCompatible rejects).
	var scope string
	if err := t.Get("scope", &scope); err == nil {
		c.Scope = strings.Fields(scope)
	} else {
		var scopes []any
		if err := t.Get("scope", &scopes); err == nil {
			for _, s := range scopes {
				if str, ok := s.(string); ok {
					c.Scope = append(c.Scope, str)
				}
			}
		}
	}
	if parts := strings.SplitN(raw, ".", 3); len(parts) == 3 {
		if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			c.raw = payload
		}
	}
	c.extractCnf()
	return c
}

// extractCnf reads cnf.jkt from the verified payload. Safe to call with an
// empty/invalid payload (leaves cnfJKT empty).
func (c *Claims) extractCnf() {
	if len(c.raw) == 0 {
		return
	}
	var p struct {
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if json.Unmarshal(c.raw, &p) == nil {
		c.cnfJKT = p.Cnf.JKT
	}
}

// boundKeyThumbprint returns the RFC 7638 thumbprint the token is bound to via
// its cnf.jkt claim, or "" if the token is not DPoP-bound.
func (c *Claims) boundKeyThumbprint() string { return c.cnfJKT }
