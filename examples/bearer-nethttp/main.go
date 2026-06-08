// Example: an MCP-style protected endpoint that advertises its PRM on 401 and
// validates Bearer tokens. Run, then curl with and without a token.
//
// go run ./examples/bearer-nethttp
// curl -i http://localhost:8080/mcp									 # 401 + resource_metadata
// curl -s http://localhost:8080/.well-known/oauth-protected-resource
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/0ndreu/aoa"
)

func main() {
	const resource = "http://localhost:8080"
	const issuer = "https://idp.example.com"

	meta := aoa.ProtectedResourceMetadata{
		Resource:             resource,
		AuthorizationServers: []string{issuer},
		ScopesSupported:      []string{"mcp:read"},
	}
	prm, err := aoa.NewMetadataHandler(meta, aoa.HandlerOptions{AllowInsecureLocalhost: true})
	if err != nil {
		slog.Error("metadata handler", "err", err)
		os.Exit(1)
	}
	path, _ := aoa.MetadataPathFor(resource)

	guard, err := aoa.RequireBearer(aoa.BearerOpts{
		Resource:       resource,
		Issuer:         issuer,
		JWKSURI:        issuer + "/.well-known/jwks.json",
		RequiredScopes: []string{"mcp:read"},
	})
	if err != nil {
		slog.Error("require bearer", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle(path, prm)
	mux.Handle("/mcp", guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := aoa.ClaimsFromContext(r.Context())
		_, _ = w.Write([]byte("authorized: " + claims.Subject))
	})))

	slog.Info("listening", "addr", ":8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
}
