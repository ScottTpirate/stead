package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDriverTimingsStayRequestScopedAndDiscardDiagnosticContent(t *testing.T) {
	ctx, counters := telemetry.Begin(context.Background())
	_, other := telemetry.Begin(context.Background())
	trace := requestTrace{}
	acquiring := trace.TraceAcquireStart(ctx, nil, pgxpool.TraceAcquireStartData{})
	query := trace.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: "never-retain-query", Args: []any{"never-retain-argument"}})
	if counters.Snapshot().Timing.SQLClientCalls != 0 {
		t.Fatal("unfinished query measured")
	}
	query = context.WithValue(query, queryStarted{}, time.Now().Add(-time.Millisecond))
	trace.TraceQueryEnd(query, nil, pgx.TraceQueryEndData{Err: errors.New("never-retain-error")})
	trace.TraceAcquireEnd(acquiring, nil, pgxpool.TraceAcquireEndData{Err: context.Canceled})
	got := counters.Snapshot().Timing
	if got.SQLClientCalls != 1 || got.SQLClientFailures != 1 || got.SQLClientNS < uint64(time.Millisecond) || got.PoolAcquireCalls != 1 || got.PoolAcquireFailures != 1 {
		t.Fatalf("bad measurements: %+v", got)
	}
	if other.Snapshot() != (telemetry.Snapshot{}) {
		t.Fatal("cross-request timing")
	}
	data, err := json.Marshal(counters.Snapshot())
	if err != nil || strings.Contains(string(data), "never-retain") {
		t.Fatal("driver diagnostics retained")
	}
	trace.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})
	trace.TraceAcquireEnd(ctx, nil, pgxpool.TraceAcquireEndData{})
	if counters.Snapshot().Timing != got {
		t.Fatal("unmatched trace end manufactured timing")
	}
}
