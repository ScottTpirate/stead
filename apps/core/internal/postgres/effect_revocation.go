package postgres

import (
	"context"

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
	var open bool
	err := store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE "authorization".session_fences SET pending=true WHERE session_id=$1`, sessionID)
		count(ctx, 1, uint64(tag.RowsAffected()), 0, 0)
		if err != nil || tag.RowsAffected() != 1 {
			return authorization.ErrDenied
		}
		// Only issued-before-effect cancellation is a supported terminal in
		// this slice. A bare terminal index value or future proof class is not
		// enough to acknowledge drain; its reviewed consumer must come first.
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM "authorization".effects WHERE session_id=$1 AND (
		 state<>'terminal' OR record->>'State' IS DISTINCT FROM 'terminal'
		 OR record->>'TerminalOutcome' IS DISTINCT FROM 'canceled_before_effect'
		 OR record->>'TerminalProofDigest' IS DISTINCT FROM ''
		 OR record->'Authorization'->>'SessionID' IS DISTINCT FROM session_id::text
		 OR record->'Binding'->>'EffectID' IS DISTINCT FROM id::text
		 OR record->'Binding'->>'OperationID' IS DISTINCT FROM operation_id::text
		 OR record->'Binding'->'Project'->>'id' IS DISTINCT FROM project_id::text
		 OR record->>'Version' IS DISTINCT FROM version::text))`, sessionID).Scan(&open)
		count(ctx, 1, 0, 0, 0)
		return err
	})
	if err != nil || open {
		return authorization.ErrDenied
	}
	return nil
}

// No cancellation/recovery job is supplied here. The root must signal the
// registered WS06 executions, cancel issued rows through their exact WS06 CAS,
// and obtain real terminal proof for consumed/reconciling rows before this
// guard can permit identity revocation. No active provider path is hooked up.
