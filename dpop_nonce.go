package aoa

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"
)

// DPoPNonceSource issues and validates server-chosen DPoP nonces (RFC 9449 par.8).
// Current returns the nonce to advertise in a DPoP-Nonce response header; Valid
// reports whether a nonce presented in a proof is acceptable. Implementations
// MUST be safe for concurrent use.
type DPoPNonceSource interface {
	Current(ctx context.Context, r *http.Request) string
	Valid(ctx context.Context, r *http.Request, nonce string) bool
}

// NewDPoPNonceSource returns a stateless HMAC-based DPoPNonceSource keyed by
// secret. The nonce is an HMAC over a rotating time window, so it requires no
// shared storage and is valid across every RS instance that shares secret.
// The current window and the immediately preceding one are accepted, tolerating
// clock skew and rotation at the boundary.
func NewDPoPNonceSource(secret []byte) DPoPNonceSource {
	return &hmacNonce{secret: secret, window: 5 * time.Minute}
}

type hmacNonce struct {
	secret []byte
	window time.Duration
}

func (h *hmacNonce) windowAt(t time.Time) int64 {
	return t.Unix() / int64(h.window/time.Second)
}

func (h *hmacNonce) make(w int64) string {
	wb := strconv.FormatInt(w, 10)
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(wb))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *hmacNonce) Current(context.Context, *http.Request) string {
	return h.make(h.windowAt(time.Now()))
}

func (h *hmacNonce) Valid(_ context.Context, _ *http.Request, nonce string) bool {
	cur := h.windowAt(time.Now())
	for _, w := range []int64{cur, cur - 1} {
		if hmac.Equal([]byte(nonce), []byte(h.make(w))) {
			return true
		}
	}
	return false
}
