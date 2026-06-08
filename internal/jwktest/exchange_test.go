package jwktest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSignClaimsAndMayAct(t *testing.T) {
	s := NewECSigner(t, "k1")
	raw := s.SignClaims(t, map[string]any{
		"sub":     "alice",
		"iss":     "https://idp.example.com",
		"aud":     []string{"https://api.example.com"},
		"exp":     time.Now().Add(time.Hour).Unix(),
		"may_act": map[string]any{"sub": "svc-gateway"},
	})
	if strings.Count(raw, ".") != 2 {
		t.Fatalf("want a 3-part JWS, got %q", raw)
	}
}

func TestExchangeASStub_ReturnsConfiguredToken(t *testing.T) {
	as := NewExchangeAS(t)
	as.Respond(ExchangeResponse{AccessToken: "new-tok", IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token", TokenType: "Bearer", ExpiresIn: 300})

	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"st"}}
	resp, err := http.PostForm(as.TokenEndpoint(), form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if got["access_token"] != "new-tok" {
		t.Fatalf("access_token = %v", got["access_token"])
	}
	if as.LastForm().Get("subject_token") != "st" {
		t.Fatalf("subject_token not captured")
	}
}
