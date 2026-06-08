// Package chiadapter mounts aoa handlers on a chi.Router.
package chiadapter

import (
	"github.com/go-chi/chi/v5"

	"github.com/0ndreu/aoa"
)

// Mount attaches the RFC 9728 Protected Resource Metadata handler to r at the
// path computed via aoa.MetadataPathFor (RFC 9728 par.3.1). The metadata is
// validated per opts; an invalid document returns a non-nil error and nothing
// is mounted.
//
// Note: only GET/HEAD (and OPTIONS when opts.EnableCORS is set) are registered,
// so chi answers any other method with its own 405 before the handler runs -
// the handler's internal 405 branch is therefore unreachable under chi (it
// still applies when the handler is mounted directly on net/http).
func Mount(r chi.Router, meta aoa.ProtectedResourceMetadata, opts aoa.HandlerOptions) error {
	h, err := aoa.NewMetadataHandler(meta, opts)
	if err != nil {
		return err
	}
	path, err := aoa.MetadataPathFor(meta.Resource)
	if err != nil {
		return err
	}
	r.Method("GET", path, h)
	r.Method("HEAD", path, h)
	if opts.EnableCORS {
		r.Method("OPTIONS", path, h)
	}
	return nil
}
