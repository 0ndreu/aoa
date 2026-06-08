package aoa

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownSuffix is the RFC 9728 par.3.1 well-known URI path suffix.
const WellKnownSuffix = "/.well-known/oauth-protected-resource"

// MetadataPathFor returns the RFC 9728 par.3.1 path for a resource URI.
// The resource's path component (if any) is appended to WellKnownSuffix.
// resource must be an absolute URI.
func MetadataPathFor(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil || !u.IsAbs() {
		return "", errors.New("resource must be an absolute URI")
	}
	p := strings.TrimRight(u.Path, "/")
	if p == "" {
		return WellKnownSuffix, nil
	}
	return WellKnownSuffix + p, nil
}

// HandlerOptions configures NewMetadataHandler. The zero value is strict-RFC.
type HandlerOptions struct {
	// AllowInsecureLocalhost mirrors ValidateOptions.AllowInsecureLocalhost.
	AllowInsecureLocalhost bool

	// CacheControl overrides the default Cache-Control header ("public, max-age=3600").
	CacheControl string

	// EnableCORS enables permissive CORS headers on the discovery endpoint.
	EnableCORS bool
}

const defaultCacheControl = "public, max-age=3600"

// NewMetadataHandler returns an http.Handler serving the RFC 9728 Protected Resource
// Metadata document. Supports GET and HEAD; validates meta before constructing the handler.
func NewMetadataHandler(meta ProtectedResourceMetadata, opts HandlerOptions) (http.Handler, error) {
	if err := meta.ValidateWithOptions(ValidateOptions{
		AllowInsecureLocalhost: opts.AllowInsecureLocalhost,
	}); err != nil {
		return nil, err
	}
	body, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	cc := opts.CacheControl
	if cc == "" {
		cc = defaultCacheControl
	}
	return &metadataHandler{body: body, cacheControl: cc, cors: opts.EnableCORS}, nil
}

type metadataHandler struct {
	body         []byte
	cacheControl string
	cors         bool
}

func (h *metadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.setHeaders(w)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(h.body)
	case http.MethodHead:
		h.setHeaders(w)
		w.WriteHeader(http.StatusOK)
	case http.MethodOptions:
		if h.cors {
			h.setCORSHeaders(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fallthrough
	default:
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *metadataHandler) setHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", h.cacheControl)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h.cors {
		h.setCORSHeaders(w)
	}
}

func (h *metadataHandler) setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
}
