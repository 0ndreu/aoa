package aoa

import (
	"context"
	"log/slog"
	"time"
)

// Emitter receives audit events. Implementations must be non-blocking and safe
// for concurrent use; Emit is called on the hot request path.
type Emitter interface {
	Emit(ctx context.Context, e Event)
}

// Event is an audit record for a token-validation outcome.
type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	Kind      EventKind      `json:"kind"`
	Outcome   Outcome        `json:"outcome"`
	Subject   string         `json:"subject,omitempty"`
	Issuer    string         `json:"issuer,omitempty"`
	Audience  []string       `json:"audience,omitempty"`
	Scope     []string       `json:"scope,omitempty"`
	Resource  string         `json:"resource,omitempty"`
	Reason    string         `json:"reason,omitempty"`
	Error     string         `json:"error,omitempty"`
	HTTP      HTTPContext    `json:"http,omitempty"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// HTTPContext holds request metadata attached to an Event.
type HTTPContext struct {
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// EventKind identifies the kind of audit event. Consumers MUST tolerate unknown
// values (treat as informational) - new kinds may be added in minor versions.
type EventKind string

const (
	EventTokenValidated EventKind = "token_validated"
	EventTokenRejected  EventKind = "token_rejected"
	EventTokenExchanged EventKind = "token_exchanged" // RFC 8693
	EventDPoPVerified   EventKind = "dpop_verified"
	EventDPoPRejected   EventKind = "dpop_rejected"
	EventMetadataServed EventKind = "metadata_served" // RFC 9728
	EventJTIReplay      EventKind = "jti_replay"
)

// Outcome is the result of a validation attempt.
type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeDeny  Outcome = "deny"
	OutcomeError Outcome = "error" // infrastructure failure, e.g. JWKS unreachable
)

type noopEmitter struct{}

func (noopEmitter) Emit(context.Context, Event) {}

// FuncEmitter lets you pass a closure as an Emitter without defining a type.
type FuncEmitter func(ctx context.Context, e Event)

func (f FuncEmitter) Emit(ctx context.Context, e Event) { f(ctx, e) }

// LogEmitter returns an Emitter that writes each event to logger at Info level.
// A nil logger uses slog.Default().
func LogEmitter(logger *slog.Logger) Emitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &logEmitter{logger: logger}
}

type logEmitter struct{ logger *slog.Logger }

func (l *logEmitter) Emit(ctx context.Context, e Event) {
	l.logger.LogAttrs(ctx, slog.LevelInfo, "aoa.audit",
		slog.String("kind", string(e.Kind)),
		slog.String("outcome", string(e.Outcome)),
		slog.String("subject", e.Subject),
		slog.String("issuer", e.Issuer),
		slog.Any("audience", e.Audience),
		slog.Any("scope", e.Scope),
		slog.String("resource", e.Resource),
		slog.String("reason", e.Reason),
		slog.String("error", e.Error),
	)
}
