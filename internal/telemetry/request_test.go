package telemetry

import (
	"context"
	"sync"
	"testing"
)

func TestConcurrentCountsAreRequestIsolated(t *testing.T) {
	ctx, c := Begin(context.Background())
	_, other := Begin(context.Background())
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Go(func() {
			AddSQL(ctx, 2, 1)
			AddAudit(ctx, 1)
			AddOutbox(ctx, 1)
			AddOpenFGA(ctx, 3)
			AddProvider(ctx, 4)
		})
	}
	group.Wait()
	if got := c.Snapshot(); got != (Snapshot{40, 20, 20, 20, 60, 80}) {
		t.Fatalf("counts: %+v", got)
	}
	if other.Snapshot() != (Snapshot{}) {
		t.Fatal("cross-request counters")
	}
	AddSQL(context.Background(), 1, 1)
}
