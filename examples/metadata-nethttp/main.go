// Example: serving RFC 9728 Protected Resource Metadata with net/http.
//
//	go run ./examples/metadata-nethttp
//	curl -s http://localhost:8080/.well-known/oauth-protected-resource | jq
//
// Production deployments MUST use https. AllowInsecureLocalhost is enabled
// here only because this example binds to localhost for hands-on testing.
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/0ndreu/aoa"
)

func main() {
	meta := aoa.ProtectedResourceMetadata{
		Resource:               "http://localhost:8080",
		AuthorizationServers:   []string{"https://idp.example.com"},
		ScopesSupported:        []string{"mcp:read", "mcp:write"},
		BearerMethodsSupported: []string{"header"},
	}
	h, err := aoa.NewMetadataHandler(meta, aoa.HandlerOptions{
		AllowInsecureLocalhost: true, // dev only
		EnableCORS:             true, // for browser-side MCP clients
	})
	if err != nil {
		slog.Error("metadata handler", "err", err)
		os.Exit(1)
	}
	path, err := aoa.MetadataPathFor(meta.Resource)
	if err != nil {
		slog.Error("path", "err", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.Handle(path, h)
	slog.Info("listening", "addr", ":8080", "path", path)
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
}
