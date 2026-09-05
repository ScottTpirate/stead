package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
)

func TestWithoutDecisionsPreservesRequestContext(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	ctx, counters := telemetry.Begin(ctx)
	decision := &Decision{valid: true}
	prior := decision.WithContext(ctx)
	fresh := WithoutDecisions(prior)
	if len(DecisionsFromContext(fresh)) != 0 || len(DecisionsFromContext(prior)) != 1 {
		t.Fatal("fresh logical set mutated or retained the previous decisions")
	}
	if actual, ok := fresh.Deadline(); !ok || !actual.Equal(deadline) {
		t.Fatal("request deadline discarded")
	}
	telemetry.AddOpenFGA(fresh, 1)
	if counters.Snapshot().OpenFGACalls != 1 {
		t.Fatal("request telemetry discarded")
	}
	cancel()
	if fresh.Err() != context.Canceled {
		t.Fatal("request cancellation discarded")
	}
}
