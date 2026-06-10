package aoa

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// randomID returns a 128-bit base64url token identifier (jti / assertion id).
func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

const grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// ExchangeConfig configures a TokenExchanger.
type ExchangeConfig struct {
	TokenEndpoint string     // explicit AS token endpoint; OR
	Issuer        string     // RFC 8414 discovery to resolve the token endpoint
	ClientAuth    ClientAuth // required; how the client authenticates
	// HTTPClient is an optional HTTP client for mTLS, timeouts, and proxy
	// configuration. The default client does NOT follow redirects from the token
	// endpoint: credentials (subject_token, client_secret, client_assertion) must
	// not be replayed to a redirected host. A custom
	// client SHOULD set CheckRedirect to return http.ErrUseLastResponse to
	// preserve this security property.
	HTTPClient *http.Client
	DPoPKey    DPoPKey // optional; zero value ⇒ no DPoP
	Audit      Emitter // optional; default no-op
}

// ExchangeRequest is one RFC 8693 token-exchange request.
type ExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   TokenType // default access_token
	ActorToken         string    // optional ⇒ delegation
	ActorTokenType     TokenType // required iff ActorToken set
	Resource           []string
	Audience           []string
	Scope              []string
	RequestedTokenType TokenType
}

// ExchangeResult is the parsed RFC 8693 token-exchange response.
type ExchangeResult struct {
	AccessToken     string
	IssuedTokenType TokenType
	TokenType       string // "Bearer" | "DPoP" | "N_A"
	ExpiresIn       time.Duration
	Scope           []string
	RefreshToken    string
	raw             []byte
}

// Decode unmarshals the full token-endpoint response JSON into v for access to
// non-standard fields.
func (r *ExchangeResult) Decode(v any) error {
	if len(r.raw) == 0 {
		return errors.New("aoa: no response payload")
	}
	return json.Unmarshal(r.raw, v)
}

// TokenExchanger performs RFC 8693 token exchange against an AS token endpoint.
type TokenExchanger struct {
	endpoint  string
	issuer    string
	auth      ClientAuth
	client    *http.Client
	dpop      DPoPKey
	emitter   Emitter
	discovery *discovery
}

// NewTokenExchanger validates cfg and returns an exchanger.
func NewTokenExchanger(cfg ExchangeConfig) (*TokenExchanger, error) {
	if (cfg.TokenEndpoint == "") == (cfg.Issuer == "") {
		return nil, errors.New("aoa: ExchangeConfig requires exactly one of TokenEndpoint or Issuer")
	}
	if cfg.ClientAuth == nil {
		return nil, errors.New("aoa: ExchangeConfig.ClientAuth is required")
	}
	if cfg.Issuer != "" {
		if err := validateIssuerURL(cfg.Issuer); err != nil {
			return nil, fmt.Errorf("aoa: ExchangeConfig.Issuer: %w", err)
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	emitter := cfg.Audit
	if emitter == nil {
		emitter = noopEmitter{}
	}
	return &TokenExchanger{
		endpoint: cfg.TokenEndpoint, issuer: cfg.Issuer, auth: cfg.ClientAuth,
		client: client, dpop: cfg.DPoPKey, emitter: emitter, discovery: newDiscovery(client),
	}, nil
}

// Exchange runs one token exchange and returns the issued token.
func (x *TokenExchanger) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	if req.SubjectToken == "" {
		return nil, errors.New("aoa: ExchangeRequest.SubjectToken is required")
	}
	if req.ActorToken != "" && req.ActorTokenType == "" {
		return nil, errors.New("aoa: ActorTokenType is required when ActorToken is set")
	}
	endpoint, err := x.resolveEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	form := buildExchangeForm(req)
	res, err := x.exchangeWithNonceRetry(ctx, endpoint, form)
	if err != nil {
		x.emit(ctx, Event{Kind: EventTokenExchanged, Outcome: OutcomeDeny, Reason: err.Error()})
		return nil, err
	}
	x.emit(ctx, Event{Kind: EventTokenExchanged, Outcome: OutcomeAllow, Scope: res.Scope})
	return res, nil
}

func (x *TokenExchanger) resolveEndpoint(ctx context.Context) (string, error) {
	if x.endpoint != "" {
		return x.endpoint, nil
	}
	return x.discovery.tokenEndpoint(ctx, x.issuer)
}

// buildExchangeForm assembles the RFC 8693 form parameters. Client auth and DPoP
// are layered on in do, not here.
func buildExchangeForm(req ExchangeRequest) url.Values {
	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", req.SubjectToken)
	form.Set("subject_token_type", string(req.SubjectTokenType.orDefault()))
	if req.ActorToken != "" {
		form.Set("actor_token", req.ActorToken)
		form.Set("actor_token_type", string(req.ActorTokenType))
	}
	for _, r := range req.Resource {
		form.Add("resource", r)
	}
	for _, a := range req.Audience {
		form.Add("audience", a)
	}
	if len(req.Scope) > 0 {
		form.Set("scope", strings.Join(req.Scope, " "))
	}
	if req.RequestedTokenType != "" {
		form.Set("requested_token_type", string(req.RequestedTokenType))
	}
	return form
}

// exchangeWithNonceRetry performs the exchange, retrying exactly once if the AS
// answers a DPoP request with 400 use_dpop_nonce (RFC 9449 par.5/par.8). Without a
// DPoP key there is nothing to retry, so the first error is returned as-is.
func (x *TokenExchanger) exchangeWithNonceRetry(ctx context.Context, endpoint string, form url.Values) (*ExchangeResult, error) {
	res, nonce, err := x.do(ctx, endpoint, form, "")
	if err == nil {
		return res, nil
	}
	if x.dpop.isZero() || nonce == "" {
		return nil, err // not a nonce challenge we can satisfy
	}
	res, _, err = x.do(ctx, endpoint, form, nonce)
	return res, err
}

// do performs a single POST (client auth applied, optional DPoP proof with the
// given nonce). It returns the parsed result, OR (on a use_dpop_nonce 400) the
// server-supplied nonce so the caller can retry.
func (x *TokenExchanger) do(ctx context.Context, endpoint string, form url.Values, nonce string) (*ExchangeResult, string, error) {
	authForm := cloneValues(form)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	if err := x.auth.apply(ctx, httpReq, authForm); err != nil {
		return nil, "", err
	}
	if !x.dpop.isZero() {
		proof, err := x.dpop.proofFor(http.MethodPost, htuOf(endpoint), nonce)
		if err != nil {
			return nil, "", err
		}
		httpReq.Header.Set("DPoP", proof)
	}
	encoded := authForm.Encode()
	httpReq.Body = io.NopCloser(strings.NewReader(encoded))
	httpReq.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(encoded)), nil }
	httpReq.ContentLength = int64(len(encoded))

	resp, err := x.client.Do(httpReq)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, "", &ExchangeError{Code: "invalid_request",
			Description: "token endpoint returned a redirect, which is not followed", HTTPStatus: resp.StatusCode}
	}
	if resp.StatusCode/100 != 2 {
		ee := parseExchangeError(resp.StatusCode, respBody)
		if ee.Code == "use_dpop_nonce" {
			return nil, resp.Header.Get("DPoP-Nonce"), ee
		}
		return nil, "", ee
	}
	res, err := parseExchangeResult(respBody)
	return res, "", err
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

// htuOf strips query/fragment from a token endpoint URL for the DPoP htu claim.
func htuOf(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		u.RawQuery, u.Fragment = "", ""
		return u.String()
	}
	return endpoint
}

func parseExchangeResult(body []byte) (*ExchangeResult, error) {
	var p struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
		Scope           string `json:"scope"`
		RefreshToken    string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("aoa: parse exchange response: %w", err)
	}
	if p.AccessToken == "" {
		return nil, errors.New("aoa: exchange response missing access_token")
	}
	res := &ExchangeResult{
		AccessToken: p.AccessToken, IssuedTokenType: TokenType(p.IssuedTokenType),
		TokenType: p.TokenType, ExpiresIn: time.Duration(p.ExpiresIn) * time.Second,
		RefreshToken: p.RefreshToken, raw: body,
	}
	if p.Scope != "" {
		res.Scope = strings.Fields(p.Scope)
	}
	return res, nil
}

func (x *TokenExchanger) emit(ctx context.Context, ev Event) {
	ev.Timestamp = time.Now().UTC()
	x.emitter.Emit(ctx, ev)
}
