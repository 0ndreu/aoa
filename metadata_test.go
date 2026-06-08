package aoa

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProtectedResourceMetadata_MarshalJSON_MinimumValid(t *testing.T) {
	m := ProtectedResourceMetadata{
		Resource: "https://mcp.example.com",
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)
	want := `{"resource":"https://mcp.example.com"}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProtectedResourceMetadata_Validate(t *testing.T) {
	tests := []struct {
		name    string
		m       ProtectedResourceMetadata
		wantErr string // substring; empty = no error expected
	}{
		{
			name: "valid_minimum",
			m:    ProtectedResourceMetadata{Resource: "https://mcp.example.com"},
		},
		{
			name:    "missing_resource",
			m:       ProtectedResourceMetadata{},
			wantErr: "resource is required",
		},
		{
			name:    "resource_not_absolute",
			m:       ProtectedResourceMetadata{Resource: "/mcp"},
			wantErr: "resource must be an absolute URI",
		},
		{
			name:    "resource_not_https",
			m:       ProtectedResourceMetadata{Resource: "ftp://mcp.example.com"},
			wantErr: "resource scheme must be https",
		},
		{
			name:    "http_localhost_rejected_when_strict",
			m:       ProtectedResourceMetadata{Resource: "http://localhost:8080"},
			wantErr: "must be https",
		},
		{
			name:    "http_rejected_for_non_localhost",
			m:       ProtectedResourceMetadata{Resource: "http://mcp.example.com"},
			wantErr: "must be https",
		},
		{
			name: "valid_with_optional_fields",
			m: ProtectedResourceMetadata{
				Resource:             "https://mcp.example.com",
				AuthorizationServers: []string{"https://idp.example.com"},
				ScopesSupported:      []string{"mcp:read", "mcp:write"},
			},
		},
		{
			name: "invalid_authorization_server_uri",
			m: ProtectedResourceMetadata{
				Resource:             "https://mcp.example.com",
				AuthorizationServers: []string{"not-a-uri"},
			},
			wantErr: "authorization_servers[0]",
		},
		{
			name:    "http_empty_host",
			m:       ProtectedResourceMetadata{Resource: "http://"},
			wantErr: "must be https",
		},
		{
			name:    "resource_with_fragment",
			m:       ProtectedResourceMetadata{Resource: "https://mcp.example.com#frag"},
			wantErr: "fragment",
		},
		{
			name: "auth_server_non_https",
			m: ProtectedResourceMetadata{
				Resource:             "https://mcp.example.com",
				AuthorizationServers: []string{"http://idp.example.com"},
			},
			wantErr: "authorization_servers[0]: scheme must be https",
		},
		{
			name: "auth_server_with_fragment",
			m: ProtectedResourceMetadata{
				Resource:             "https://mcp.example.com",
				AuthorizationServers: []string{"https://idp.example.com#frag"},
			},
			wantErr: "authorization_servers[0]: must not contain fragment",
		},
		{
			name: "auth_server_with_query",
			m: ProtectedResourceMetadata{
				Resource:             "https://mcp.example.com",
				AuthorizationServers: []string{"https://idp.example.com?x=1"},
			},
			wantErr: "authorization_servers[0]: must not contain query",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && err != nil:
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestProtectedResourceMetadata_ValidateWithOptions(t *testing.T) {
	tests := []struct {
		name    string
		m       ProtectedResourceMetadata
		opts    ValidateOptions
		wantErr string
	}{
		{
			name: "localhost_http_allowed_when_opted_in",
			m:    ProtectedResourceMetadata{Resource: "http://localhost:8080"},
			opts: ValidateOptions{AllowInsecureLocalhost: true},
		},
		{
			name: "loopback_v4_http_allowed_when_opted_in",
			m:    ProtectedResourceMetadata{Resource: "http://127.0.0.1:8080"},
			opts: ValidateOptions{AllowInsecureLocalhost: true},
		},
		{
			name: "ipv6_loopback_with_port_http_allowed_when_opted_in",
			m:    ProtectedResourceMetadata{Resource: "http://[::1]:8080"},
			opts: ValidateOptions{AllowInsecureLocalhost: true},
		},
		{
			name: "ipv6_loopback_no_port_http_allowed_when_opted_in",
			m:    ProtectedResourceMetadata{Resource: "http://[::1]"},
			opts: ValidateOptions{AllowInsecureLocalhost: true},
		},
		{
			name:    "non_localhost_http_still_rejected_with_opt_in",
			m:       ProtectedResourceMetadata{Resource: "http://mcp.example.com"},
			opts:    ValidateOptions{AllowInsecureLocalhost: true},
			wantErr: "must be https",
		},
		{
			name:    "default_options_match_strict_validate",
			m:       ProtectedResourceMetadata{Resource: "http://localhost:8080"},
			opts:    ValidateOptions{},
			wantErr: "must be https",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m.ValidateWithOptions(tt.opts)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && err != nil:
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestProtectedResourceMetadata_MarshalJSON_ExtraFields(t *testing.T) {
	m := ProtectedResourceMetadata{
		Resource: "https://mcp.example.com",
		Extra: map[string]any{
			"x_custom_field":  "value",
			"x_numeric_field": 42,
		},
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if got["resource"] != "https://mcp.example.com" {
		t.Errorf("missing resource field: %v", got)
	}
	if got["x_custom_field"] != "value" {
		t.Errorf("missing x_custom_field: %v", got)
	}
	if got["x_numeric_field"] != float64(42) {
		t.Errorf("missing x_numeric_field: %v", got)
	}
}

func TestProtectedResourceMetadata_MarshalJSON_ExtraDoesNotOverrideTyped(t *testing.T) {
	// if a caller puts "resource" in Extra, the typed field wins
	m := ProtectedResourceMetadata{
		Resource: "https://mcp.example.com",
		Extra: map[string]any{
			"resource": "https://evil.example.com",
		},
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if got["resource"] != "https://mcp.example.com" {
		t.Errorf("typed Resource was overridden by Extra: %v", got["resource"])
	}
}
