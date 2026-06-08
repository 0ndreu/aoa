package aoa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0ndreu/aoa/internal/jwktest"
)

func newExchanger(t *testing.T, endpoint string) *TokenExchanger {
	t.Helper()
	x, err := NewTokenExchanger(ExchangeConfig{
		TokenEndpoint: endpoint,
		ClientAuth:    ClientSecretAuth("cid", "secret", false),
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	return x
}

func TestExchange_Impersonation(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.Respond(jwktest.ExchangeResponse{
		AccessToken: "down-tok", IssuedTokenType: string(TokenTypeAccessToken),
		TokenType: "Bearer", ExpiresIn: 300, Scope: "read",
	})
	x := newExchanger(t, as.TokenEndpoint())
	res, err := x.Exchange(context.Background(), ExchangeRequest{
		SubjectToken: "user-tok", Audience: []string{"https://downstream"},
		Scope: []string{"read"},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if res.AccessToken != "down-tok" || res.TokenType != "Bearer" {
		t.Fatalf("result wrong: %+v", res)
	}
	f := as.LastForm()
	if f.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Fatalf("grant_type wrong: %s", f.Get("grant_type"))
	}
	if f.Get("subject_token") != "user-tok" || f.Get("subject_token_type") != string(TokenTypeAccessToken) {
		t.Fatalf("subject wrong: %v", f)
	}
	if f.Get("audience") != "https://downstream" || f.Get("scope") != "read" {
		t.Fatalf("downscope params wrong: %v", f)
	}
	if f.Get("actor_token") != "" {
		t.Fatal("impersonation must not send actor_token")
	}
}

func TestExchange_Delegation(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.Respond(jwktest.ExchangeResponse{AccessToken: "d", IssuedTokenType: string(TokenTypeAccessToken), TokenType: "Bearer"})
	x := newExchanger(t, as.TokenEndpoint())
	_, err := x.Exchange(context.Background(), ExchangeRequest{
		SubjectToken: "user-tok",
		ActorToken:   "svc-tok", ActorTokenType: TokenTypeAccessToken,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	f := as.LastForm()
	if f.Get("actor_token") != "svc-tok" || f.Get("actor_token_type") != string(TokenTypeAccessToken) {
		t.Fatalf("actor params wrong: %v", f)
	}
}

func TestExchange_ActorTokenWithoutTypeRejectedLocally(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	x := newExchanger(t, as.TokenEndpoint())
	_, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u", ActorToken: "a"})
	if err == nil {
		t.Fatal("actor_token without actor_token_type must error before the network call")
	}
}

func TestExchange_ServerErrorMapped(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.RespondError(400, `{"error":"invalid_target","error_description":"nope"}`)
	x := newExchanger(t, as.TokenEndpoint())
	_, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	ee, ok := err.(*ExchangeError)
	if !ok || ee.Code != "invalid_target" {
		t.Fatalf("want ExchangeError invalid_target, got %v", err)
	}
}

// TestExchange_Malformed2xx: a 200 response missing access_token must error.
func TestExchange_Malformed2xx(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	// ExchangeResponse with no AccessToken gives a 200 with empty access_token.
	as.Respond(jwktest.ExchangeResponse{TokenType: "Bearer"})
	x := newExchanger(t, as.TokenEndpoint())
	_, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	if err == nil {
		t.Fatal("malformed 200 (no access_token) must return an error")
	}
}

// TestExchange_DecodeRoundTrip: ExchangeResult.Decode reads extra fields; a
// zero-value ExchangeResult.Decode returns the "no response payload" error.
func TestExchange_DecodeRoundTrip(t *testing.T) {
	// stand up a raw httptest server that writes a success body with an extra field
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "tok-decode",
			"token_type":        "Bearer",
			"issued_token_type": string(TokenTypeAccessToken),
			"x_custom_field":    "hello",
		})
	}))
	defer srv.Close()

	x, err := NewTokenExchanger(ExchangeConfig{
		TokenEndpoint: srv.URL + "/token",
		ClientAuth:    ClientSecretAuth("cid", "s", false),
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	res, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	var full struct {
		AccessToken  string `json:"access_token"`
		XCustomField string `json:"x_custom_field"`
	}
	if err := res.Decode(&full); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if full.XCustomField != "hello" {
		t.Fatalf("x_custom_field = %q, want %q", full.XCustomField, "hello")
	}

	// zero-value ExchangeResult must return the "no response payload" error
	var empty ExchangeResult
	if err := empty.Decode(&full); err == nil {
		t.Fatal("Decode on zero-value ExchangeResult must error")
	}
}

// TestExchange_MultiValueResourceAudience: multi-value resource and audience
// are sent as repeated form fields.
func TestExchange_MultiValueResourceAudience(t *testing.T) {
	as := jwktest.NewExchangeAS(t)
	as.Respond(jwktest.ExchangeResponse{
		AccessToken: "multi-tok", IssuedTokenType: string(TokenTypeAccessToken), TokenType: "Bearer",
	})
	x := newExchanger(t, as.TokenEndpoint())
	_, err := x.Exchange(context.Background(), ExchangeRequest{
		SubjectToken: "u",
		Resource:     []string{"https://a", "https://b"},
		Audience:     []string{"https://x", "https://y"},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	f := as.LastForm()
	if got := f["resource"]; len(got) != 2 || got[0] != "https://a" || got[1] != "https://b" {
		t.Fatalf("resource = %v, want [https://a https://b]", got)
	}
	if got := f["audience"]; len(got) != 2 || got[0] != "https://x" || got[1] != "https://y" {
		t.Fatalf("audience = %v, want [https://x https://y]", got)
	}
}

// TestExchange_DiscoveryThroughExchange: when only Issuer is configured,
// Exchange discovers the token_endpoint and uses it.
func TestExchange_DiscoveryThroughExchange(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":         srvURL,
				"token_endpoint": srvURL + "/token",
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":      "discovery-tok",
				"token_type":        "Bearer",
				"issued_token_type": string(TokenTypeAccessToken),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	x, err := NewTokenExchanger(ExchangeConfig{
		Issuer:     srv.URL,
		ClientAuth: ClientSecretAuth("cid", "s", false),
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	res, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	if err != nil {
		t.Fatalf("exchange via discovery: %v", err)
	}
	if res.AccessToken != "discovery-tok" {
		t.Fatalf("access_token = %q, want discovery-tok", res.AccessToken)
	}
}

// TestNewTokenExchanger_RejectsBadIssuer: NewTokenExchanger must reject an
// Issuer that fails RFC 8414 validation (http scheme instead of https).
func TestNewTokenExchanger_RejectsBadIssuer(t *testing.T) {
	_, err := NewTokenExchanger(ExchangeConfig{
		Issuer:     "http://insecure.example.com",
		ClientAuth: ClientSecretAuth("cid", "s", false),
	})
	if err == nil {
		t.Fatal("expected error for http Issuer, got nil")
	}
}

// TestExchange_RedirectRejected: a 3xx from the token endpoint must produce a
// clear ExchangeError rather than being silently followed.
func TestExchange_RedirectRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/steal", http.StatusFound)
	}))
	defer srv.Close()

	x := newExchanger(t, srv.URL+"/token")
	_, err := x.Exchange(context.Background(), ExchangeRequest{SubjectToken: "u"})
	ee, ok := err.(*ExchangeError)
	if !ok {
		t.Fatalf("want *ExchangeError, got %T: %v", err, err)
	}
	if ee.HTTPStatus != http.StatusFound {
		t.Fatalf("HTTPStatus = %d, want %d", ee.HTTPStatus, http.StatusFound)
	}
	if ee.Code != "invalid_request" {
		t.Fatalf("Code = %q, want invalid_request", ee.Code)
	}
}
