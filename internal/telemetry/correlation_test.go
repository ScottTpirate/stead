package telemetry

import (
	"context"
	"strings"
	"testing"
)

func TestCorrelationIDIsBoundedRequestMetadata(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	parent := WithCorrelationID(context.Background(), id)
	if got := CorrelationID(parent); got != id {
		t.Fatalf("correlation = %q", got)
	}
	ctx, counters := Begin(parent)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	AddSQL(ctx, 1, 0)
	if CorrelationID(ctx) != id || ctx.Err() != context.Canceled || counters.Snapshot().SQLQueries != 1 {
		t.Fatal("metadata changed cancellation or request counters")
	}
	for _, invalid := range []string{"", id[:31], id + "0", strings.ToUpper(id), "g" + id[1:], id[:31] + "\n", strings.Repeat("credential", 100), "é" + id[2:]} {
		if got := CorrelationID(WithCorrelationID(parent, invalid)); got != "" {
			t.Fatalf("invalid metadata inherited or retained a correlation: %q", got)
		}
	}
	if CorrelationID(parent) != id || CorrelationID(context.Background()) != "" || CorrelationID(nil) != "" || CorrelationID(WithCorrelationID(nil, id)) != "" {
		t.Fatal("absent metadata or child context changed a request correlation")
	}
	if CorrelationID(context.WithValue(context.Background(), "X-Correlation-ID", id)) != "" {
		t.Fatal("untyped external metadata became trusted correlation")
	}
	for _, value := range []any{123, "invalid", []byte(id)} {
		if CorrelationID(context.WithValue(parent, correlationKey{}, value)) != "" {
			t.Fatal("malformed context metadata became a correlation")
		}
	}
}
