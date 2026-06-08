package aoa

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseExchangeError(t *testing.T) {
	body := `{"error":"invalid_target","error_description":"unknown resource","error_uri":"https://e/x"}`
	ee := parseExchangeError(http.StatusBadRequest, []byte(body))
	if ee.Code != "invalid_target" || ee.Description != "unknown resource" || ee.URI != "https://e/x" {
		t.Fatalf("parsed wrong: %+v", ee)
	}
	if ee.Error() == "" {
		t.Fatal("Error() empty")
	}
}

func TestWriteExchangeError_MapsStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteExchangeError(rec, &ExchangeError{Code: "invalid_client"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid_client should be 401, got %d", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	WriteExchangeError(rec2, &ExchangeError{Code: "invalid_grant", Description: "bad subject"})
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("invalid_grant should be 400, got %d", rec2.Code)
	}
	var got map[string]string
	_ = json.Unmarshal(rec2.Body.Bytes(), &got)
	if got["error"] != "invalid_grant" || got["error_description"] != "bad subject" {
		t.Fatalf("body wrong: %v", got)
	}
}

func TestWriteExchangeError_NonExchangeDefaultsServerError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteExchangeError(rec, errInvalidToken("x"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("non-exchange error should be 500, got %d", rec.Code)
	}
}
