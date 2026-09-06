package postgres

import (
	"context"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Never inspect or retain SQL, arguments, connections or error text. Query
// duration ends at the driver's Rows.Close/Scan boundary. Acquire duration
// includes pool wait, connection construction and health checks; it is not
// labelled pure queue wait. Driver calls are not physical wire round trips.
type requestTrace struct{}
type queryStarted struct{}
type acquireStarted struct{}

func (requestTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, queryStarted{}, time.Now())
}
func (requestTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if started, ok := ctx.Value(queryStarted{}).(time.Time); ok {
		telemetry.RecordSQLClient(ctx, time.Since(started), data.Err != nil)
	}
}
func (requestTrace) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return context.WithValue(ctx, acquireStarted{}, time.Now())
}
func (requestTrace) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, data pgxpool.TraceAcquireEndData) {
	if started, ok := ctx.Value(acquireStarted{}).(time.Time); ok {
		telemetry.RecordPoolAcquire(ctx, time.Since(started), data.Err != nil)
	}
}
