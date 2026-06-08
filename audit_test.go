package aoa

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestNoopEmitter_DoesNotPanic(t *testing.T) {
	var e Emitter = noopEmitter{}
	e.Emit(context.Background(), Event{Kind: EventTokenValidated, Outcome: OutcomeAllow})
}

func TestLogEmitter_LogsEventFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	em := LogEmitter(logger)

	em.Emit(context.Background(), Event{
		Timestamp: time.Unix(0, 0).UTC(),
		Kind:      EventTokenRejected,
		Outcome:   OutcomeDeny,
		Subject:   "user-123",
		Error:     "invalid_token",
		Reason:    "signature verification failed",
	})

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "token_rejected") {
		t.Errorf("log missing kind: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "user-123") {
		t.Errorf("log missing subject: %s", buf.String())
	}
}

func TestFuncEmitter_PassesEventThrough(t *testing.T) {
	var got Event
	var em Emitter = FuncEmitter(func(_ context.Context, e Event) { got = e })
	em.Emit(context.Background(), Event{Kind: EventTokenValidated, Outcome: OutcomeAllow, Subject: "u1"})
	if got.Kind != EventTokenValidated || got.Subject != "u1" {
		t.Errorf("FuncEmitter did not pass event through: %+v", got)
	}
}
