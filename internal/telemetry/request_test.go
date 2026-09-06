package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"
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
	if got := c.Snapshot(); got != (Snapshot{SQLQueries: 40, SQLWrites: 20, AuditWrites: 20, OutboxWrites: 20, OpenFGACalls: 60, ProviderCalls: 80}) {
		t.Fatalf("counts: %+v", got)
	}
	if other.Snapshot() != (Snapshot{}) {
		t.Fatal("cross-request counters")
	}
	AddSQL(context.Background(), 1, 1)
}

func TestConcurrentTimingsAndFailuresAreIsolated(t *testing.T) {
	ctx, c := Begin(context.Background())
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Go(func() {
			RecordSQLClient(ctx, time.Millisecond, true)
			RecordPoolAcquire(ctx, 2*time.Millisecond, false)
			RecordAnchorLock(ctx, 3*time.Millisecond, 2, true)
			RecordAnchorHeld(ctx, 4*time.Millisecond)
			RecordAnchorSync(ctx, 5*time.Millisecond, true)
		})
	}
	group.Wait()
	want := Timings{SQLClientCalls: 20, SQLClientNS: uint64(20 * time.Millisecond), SQLClientFailures: 20, PoolAcquireCalls: 20, PoolAcquireNS: uint64(40 * time.Millisecond), AnchorLockAttempts: 20, AnchorLockWaitNS: uint64(60 * time.Millisecond), AnchorLockContentions: 40, AnchorLockFailures: 20, AnchorLockHeldNS: uint64(80 * time.Millisecond), AnchorSyncCalls: 20, AnchorSyncNS: uint64(100 * time.Millisecond), AnchorSyncFailures: 20}
	if c.Snapshot().Timing != want {
		t.Fatalf("timings: %+v", c.Snapshot().Timing)
	}
	RecordSQLClient(ctx, -1, true)
	RecordPoolAcquire(ctx, -1, true)
	RecordAnchorLock(ctx, -1, 100, true)
	RecordAnchorHeld(ctx, -1)
	RecordAnchorSync(ctx, -1, true)
	RecordSQLClient(nil, time.Second, true)
	RecordPoolAcquire(context.Background(), time.Second, true)
	if c.Snapshot().Timing != want {
		t.Fatal("invalid/foreign timing changed request")
	}
}
