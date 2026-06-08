package aoa

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ExchangeError is an RFC 6749 par.5.2 / RFC 8693 token-endpoint error. The client
// returns it from Exchange on a non-2xx response; the server side renders it via
// WriteExchangeError.
type ExchangeError struct {
	Code        string // e.g. invalid_request, invalid_grant, invalid_target
	Description string
	URI         string
	HTTPStatus  int // status observed (client) or to write (server); 0 ⇒ derive from Code
}

func (e *ExchangeError) Error() string {
	if e.Description == "" {
		return "aoa: token exchange error: " + e.Code
	}
	return fmt.Sprintf("aoa: token exchange error: %s: %s", e.Code, e.Description)
}

// exchangeErrorStatus maps an RFC 6749/8693 error code to its HTTP status.
func exchangeErrorStatus(code string) int {
	if code == "invalid_client" {
		return http.StatusUnauthorized
	}
	return http.StatusBadRequest // invalid_request/grant/scope/target, unauthorized_client, unsupported_grant_type
}

// parseExchangeError decodes a token-endpoint error JSON body. A body that does
// not parse yields a generic invalid_request carrying the status.
func parseExchangeError(status int, body []byte) *ExchangeError {
	var p struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri"`
	}
	if err := json.Unmarshal(body, &p); err != nil || p.Error == "" {
		return &ExchangeError{Code: "invalid_request", Description: "unparseable error response", HTTPStatus: status}
	}
	return &ExchangeError{Code: p.Error, Description: p.ErrorDescription, URI: p.ErrorURI, HTTPStatus: status}
}

// WriteExchangeError writes a token-endpoint error JSON response. If err is an
// *ExchangeError its code/status are used; any other error becomes a generic
// 500 server_error (never leaking internals).
func WriteExchangeError(w http.ResponseWriter, err error) {
	ee, ok := err.(*ExchangeError)
	if !ok {
		ee = &ExchangeError{Code: "server_error", HTTPStatus: http.StatusInternalServerError}
	}
	status := ee.HTTPStatus
	if status == 0 {
		status = exchangeErrorStatus(ee.Code)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	out := map[string]string{"error": ee.Code}
	if ee.Description != "" {
		out["error_description"] = ee.Description
	}
	if ee.URI != "" {
		out["error_uri"] = ee.URI
	}
	_ = json.NewEncoder(w).Encode(out)
}
