// Package telemetry counts real work at request-scoped adapter call sites.
// It carries no resource identity, credentials, query text, or policy inputs.
package telemetry

import (
	"context"
	"sync/atomic"
	"time"
)

type key struct{}
type Counters struct {
	sql, writes, audit, outbox, openfga, provider                                 atomic.Uint64
	queryCalls, queryNS, queryFailures, acquireCalls, acquireNS, acquireFailures  atomic.Uint64
	anchorAttempts, anchorWaitNS, anchorContentions, anchorFailures, anchorHeldNS atomic.Uint64
	anchorSyncCalls, anchorSyncNS, anchorSyncFailures                             atomic.Uint64
}

// Timings measure adapter and OS call boundaries, not inferred wire round trips
// or server-only lock waits. Nested/overlapping durations must not be added to
// derive end-to-end latency. All fields are numeric and request scoped.
type Timings struct {
	SQLClientCalls        uint64 `json:"sql_client_calls"`
	SQLClientNS           uint64 `json:"sql_client_ns"`
	SQLClientFailures     uint64 `json:"sql_client_failures"`
	PoolAcquireCalls      uint64 `json:"pool_acquire_calls"`
	PoolAcquireNS         uint64 `json:"pool_acquire_ns"`
	PoolAcquireFailures   uint64 `json:"pool_acquire_failures"`
	AnchorLockAttempts    uint64 `json:"anchor_lock_attempts"`
	AnchorLockWaitNS      uint64 `json:"anchor_lock_wait_ns"`
	AnchorLockContentions uint64 `json:"anchor_lock_contentions"`
	AnchorLockFailures    uint64 `json:"anchor_lock_failures"`
	AnchorLockHeldNS      uint64 `json:"anchor_lock_held_ns"`
	AnchorSyncCalls       uint64 `json:"anchor_sync_calls"`
	AnchorSyncNS          uint64 `json:"anchor_sync_ns"`
	AnchorSyncFailures    uint64 `json:"anchor_sync_failures"`
}
type Snapshot struct {
	SQLQueries    uint64  `json:"sql_queries"`
	SQLWrites     uint64  `json:"sql_writes"`
	AuditWrites   uint64  `json:"audit_writes"`
	OutboxWrites  uint64  `json:"outbox_writes"`
	OpenFGACalls  uint64  `json:"openfga_calls"`
	ProviderCalls uint64  `json:"provider_calls"`
	Timing        Timings `json:"timing"`
}

func RecordSQLClient(ctx context.Context, duration time.Duration, failed bool) {
	if c := current(ctx); c != nil && duration >= 0 {
		c.queryCalls.Add(1)
		c.queryNS.Add(uint64(duration))
		if failed {
			c.queryFailures.Add(1)
		}
	}
}
func RecordPoolAcquire(ctx context.Context, duration time.Duration, failed bool) {
	if c := current(ctx); c != nil && duration >= 0 {
		c.acquireCalls.Add(1)
		c.acquireNS.Add(uint64(duration))
		if failed {
			c.acquireFailures.Add(1)
		}
	}
}
func RecordAnchorLock(ctx context.Context, duration time.Duration, contentions uint64, failed bool) {
	if c := current(ctx); c != nil && duration >= 0 {
		c.anchorAttempts.Add(1)
		c.anchorWaitNS.Add(uint64(duration))
		c.anchorContentions.Add(contentions)
		if failed {
			c.anchorFailures.Add(1)
		}
	}
}
func RecordAnchorHeld(ctx context.Context, duration time.Duration) {
	if c := current(ctx); c != nil && duration >= 0 {
		c.anchorHeldNS.Add(uint64(duration))
	}
}
func RecordAnchorSync(ctx context.Context, duration time.Duration, failed bool) {
	if c := current(ctx); c != nil && duration >= 0 {
		c.anchorSyncCalls.Add(1)
		c.anchorSyncNS.Add(uint64(duration))
		if failed {
			c.anchorSyncFailures.Add(1)
		}
	}
}

func Begin(ctx context.Context) (context.Context, *Counters) {
	counters := &Counters{}
	return context.WithValue(ctx, key{}, counters), counters
}
func current(ctx context.Context) *Counters {
	if ctx == nil {
		return nil
	}
	value, _ := ctx.Value(key{}).(*Counters)
	return value
}
func AddSQL(ctx context.Context, queries, writes uint64) {
	if c := current(ctx); c != nil {
		c.sql.Add(queries)
		c.writes.Add(writes)
	}
}
func AddAudit(ctx context.Context, n uint64) {
	if c := current(ctx); c != nil {
		c.audit.Add(n)
	}
}
func AddOutbox(ctx context.Context, n uint64) {
	if c := current(ctx); c != nil {
		c.outbox.Add(n)
	}
}
func AddOpenFGA(ctx context.Context, n uint64) {
	if c := current(ctx); c != nil {
		c.openfga.Add(n)
	}
}
func AddProvider(ctx context.Context, n uint64) {
	if c := current(ctx); c != nil {
		c.provider.Add(n)
	}
}
func (c *Counters) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	return Snapshot{SQLQueries: c.sql.Load(), SQLWrites: c.writes.Load(), AuditWrites: c.audit.Load(), OutboxWrites: c.outbox.Load(), OpenFGACalls: c.openfga.Load(), ProviderCalls: c.provider.Load(), Timing: Timings{
		SQLClientCalls: c.queryCalls.Load(), SQLClientNS: c.queryNS.Load(), SQLClientFailures: c.queryFailures.Load(), PoolAcquireCalls: c.acquireCalls.Load(), PoolAcquireNS: c.acquireNS.Load(), PoolAcquireFailures: c.acquireFailures.Load(),
		AnchorLockAttempts: c.anchorAttempts.Load(), AnchorLockWaitNS: c.anchorWaitNS.Load(), AnchorLockContentions: c.anchorContentions.Load(), AnchorLockFailures: c.anchorFailures.Load(), AnchorLockHeldNS: c.anchorHeldNS.Load(), AnchorSyncCalls: c.anchorSyncCalls.Load(), AnchorSyncNS: c.anchorSyncNS.Load(), AnchorSyncFailures: c.anchorSyncFailures.Load(),
	}}
}
