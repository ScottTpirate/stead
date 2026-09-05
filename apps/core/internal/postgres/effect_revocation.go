package postgres

import (
	"context"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/jackc/pgx/v5"
)

// guardSessionEffectDrain commits pending before considering acknowledgment.
// Issue/consume hold a shared lock on this same session fence until COMMIT, so
// a winner is either counted here or sees pending and cannot acquire authority.
// The global revision vector is retained; no resource-wide pending is invented.
// A local execution map, cancellation, timeout or reconciling row is never drain
// proof. The caller may update canonical identity only after the DB has no open
// effects. Pending intentionally remains set if progress is unavailable.
func (store *Store) guardSessionEffectDrain(ctx context.Context, sessionID string) error {
	if ctx == nil {
		return authorization.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// The fence COMMIT precedes inspection. A malformed row, connection error
	// or inspection timeout must not roll pending back and reopen issuance.
	if err := store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE "authorization".session_fences SET pending=true WHERE session_id=$1`, sessionID)
		count(ctx, 1, uint64(tag.RowsAffected()), 0, 0)
		if err != nil || tag.RowsAffected() != 1 {
			return authorization.ErrDenied
		}
		return nil
	}); err != nil {
		return authorization.ErrDenied
	}
	err := store.owned(ctx, "authorization", false, func(tx pgx.Tx) error {
		// One set-oriented query, bounded JSON projections, one row at a time
		// and the deadline above: no per-effect query or unbounded collection.
		rows, err := tx.Query(ctx, `SELECT `+effectRowProjection+` FROM "authorization".effects WHERE session_id=$1`, sessionID)
		count(ctx, 1, 0, 0, 0)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, _, err := scanEffectRow(rows)
			// Only the existing fully validated issued cancellation is supported.
			// Complete shape is necessary, not itself new provider-outcome proof.
			if err != nil || ctx.Err() != nil || record.Authorization.SessionID != sessionID || record.Authorization.InstanceID != store.config.InstanceID || record.Authorization.SecurityDomain != store.config.SecurityDomain || record.State != authorization.EffectTerminal || record.TerminalOutcome != authorization.EffectCanceledBeforeEffect || record.TerminalProofDigest != "" {
				return authorization.ErrDenied
			}
		}
		return rows.Err()
	})
	if err != nil || ctx.Err() != nil {
		return authorization.ErrDenied
	}
	return nil
}

// No cancellation/recovery job is supplied here. The root must signal the
// registered WS06 executions, cancel issued rows through their exact WS06 CAS,
// and obtain real terminal proof for consumed/reconciling rows before this
// guard can permit identity revocation. No active provider path is hooked up.
