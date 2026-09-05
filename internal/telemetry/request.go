// Package telemetry counts real work at request-scoped adapter call sites.
// It carries no resource identity, credentials, query text, or policy inputs.
package telemetry

import (
	"context"
	"sync/atomic"
)

type key struct{}
type Counters struct{ sql, writes, audit, outbox, openfga, provider atomic.Uint64 }
type Snapshot struct {
	SQLQueries    uint64 `json:"sql_queries"`
	SQLWrites     uint64 `json:"sql_writes"`
	AuditWrites   uint64 `json:"audit_writes"`
	OutboxWrites  uint64 `json:"outbox_writes"`
	OpenFGACalls  uint64 `json:"openfga_calls"`
	ProviderCalls uint64 `json:"provider_calls"`
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
	return Snapshot{SQLQueries: c.sql.Load(), SQLWrites: c.writes.Load(), AuditWrites: c.audit.Load(), OutboxWrites: c.outbox.Load(), OpenFGACalls: c.openfga.Load(), ProviderCalls: c.provider.Load()}
}
