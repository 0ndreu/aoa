// Example: serving RFC 9728 Protected Resource Metadata with chi.
//
//	go run ./examples/metadata-chi
//	curl -s http://localhost:8080/.well-known/oauth-protected-resource | jq
//
// Production deployments MUST use https. AllowInsecureLocalhost is enabled
// here only because this example binds to localhost for hands-on testing.
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/0ndreu/aoa"
	chiadapter "github.com/0ndreu/aoa/adapters/chi"
)

func main() {
	r := chi.NewRouter()
	meta := aoa.ProtectedResourceMetadata{
		Resource:             "http://localhost:8080",
		AuthorizationServers: []string{"https://idp.example.com"},
		ScopesSupported:      []string{"mcp:read", "mcp:write"},
	}
	if err := chiadapter.Mount(r, meta, aoa.HandlerOptions{
		AllowInsecureLocalhost: true, // dev only
		EnableCORS:             true,
	}); err != nil {
		slog.Error("mount", "err", err)
		os.Exit(1)
	}
	path, err := aoa.MetadataPathFor(meta.Resource)
	if err != nil {
		slog.Error("path", "err", err)
		os.Exit(1)
	}
	slog.Info("listening", "addr", ":8080", "path", path)
	if err := http.ListenAndServe(":8080", r); err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
}
