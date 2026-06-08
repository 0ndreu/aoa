package aoa

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ProtectedResourceMetadata is the RFC 9728 Protected Resource Metadata document.
// Resource is required; all other fields are optional.
type ProtectedResourceMetadata struct {
	Resource string `json:"resource"`

	AuthorizationServers               []string `json:"authorization_servers,omitempty"`
	JWKSURI                            string   `json:"jwks_uri,omitempty"`
	ScopesSupported                    []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported             []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported  []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceName                       string   `json:"resource_name,omitempty"`
	ResourceDocumentation              string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI                  string   `json:"resource_policy_uri,omitempty"`
	ResourceTOSURI                     string   `json:"resource_tos_uri,omitempty"`
	TLSClientCertBoundAccessTokens     bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`
	DPoPSigningAlgValuesSupported      []string `json:"dpop_signing_alg_values_supported,omitempty"`
	DPoPBoundAccessTokensRequired      bool     `json:"dpop_bound_access_tokens_required,omitempty"`
	SignedMetadata                     string   `json:"signed_metadata,omitempty"`

	// Extra holds non-standard metadata values merged into the JSON output.
	// Typed fields take precedence over same-key entries in Extra.
	Extra map[string]any `json:"-"`
}

// ValidateOptions controls Validate behaviour. The zero value is strict-RFC.
type ValidateOptions struct {
	// AllowInsecureLocalhost permits http:// for localhost. Dev/test only.
	AllowInsecureLocalhost bool
}

// Validate checks the document against RFC 9728 par.1.2 / par.2. For localhost dev
// environments, use ValidateWithOptions(ValidateOptions{AllowInsecureLocalhost: true}).
func (m ProtectedResourceMetadata) Validate() error {
	return m.ValidateWithOptions(ValidateOptions{})
}

func (m ProtectedResourceMetadata) ValidateWithOptions(opts ValidateOptions) error {
	if m.Resource == "" {
		return errors.New("resource is required")
	}
	u, err := url.Parse(m.Resource)
	if err != nil || !u.IsAbs() {
		return errors.New("resource must be an absolute URI")
	}
	if u.Fragment != "" {
		return errors.New("resource must not contain a fragment per RFC 9728 par.1.2")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !opts.AllowInsecureLocalhost || !isLocalhost(u.Host) {
			return errors.New("resource scheme must be https per RFC 9728 par.1.2")
		}
	default:
		return errors.New("resource scheme must be https")
	}
	for i, as := range m.AuthorizationServers {
		if err := validateIssuerURL(as); err != nil {
			return fmt.Errorf("authorization_servers[%d]: %w", i, err)
		}
	}
	return nil
}

func isLocalhost(host string) bool {
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// bare bracketed IPv6 without port: "[::1]" -> "::1"
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// validateIssuerURL enforces RFC 8414 par.2: absolute https, no query, no fragment.
func validateIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return errors.New("must be an absolute URI")
	}
	if u.Scheme != "https" {
		return errors.New("scheme must be https")
	}
	if u.RawQuery != "" {
		return errors.New("must not contain query")
	}
	if u.Fragment != "" {
		return errors.New("must not contain fragment")
	}
	return nil
}

// MarshalJSON merges Extra into the typed JSON output. Typed fields win on collision.
func (m ProtectedResourceMetadata) MarshalJSON() ([]byte, error) {
	type alias ProtectedResourceMetadata
	base, err := json.Marshal(alias(m))
	if err != nil {
		return nil, err
	}
	if len(m.Extra) == 0 {
		return base, nil
	}
	var merged map[string]any
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, v := range m.Extra {
		if _, present := merged[k]; present {
			continue // typed fields win
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}
