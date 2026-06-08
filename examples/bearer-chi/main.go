// Example: the same protected endpoint mounted on a chi router. RequireBearer
// returns standard net/http middleware, so chi consumes it via r.Use / r.Group.
//
// go run ./examples/bearer-chi
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/0ndreu/aoa"
)

func main() {
	const resource = "http://localhost:8080"
	const issuer = "https://idp.example.com"

	guard, err := aoa.RequireBearer(aoa.BearerOpts{
		Resource: resource,
		Issuer:   issuer,
		JWKSURI:  issuer + "/.well-known/jwks.json",
	})
	if err != nil {
		slog.Error("require bearer", "err", err)
		os.Exit(1)
	}

	r := chi.NewRouter()
	r.Group(func(pr chi.Router) {
		pr.Use(guard)
		pr.Get("/mcp", func(w http.ResponseWriter, req *http.Request) {
			claims, _ := aoa.ClaimsFromContext(req.Context())
			_, _ = w.Write([]byte("authorized: " + claims.Subject))
		})
	})

	slog.Info("listening", "addr", ":8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
}
