package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/modules/audit"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/jackc/pgx/v5"
)

// Opt-in real storage test only, called inside the existing fresh isolated PG
// fixture. It deliberately does NOT fabricate a Decision or enable the rejected
// provider ABI. Its test-owned plan exercises actual owner roles, row CAS,
// audit/outbox atomicity and denial/drain SQL, not successful EffectStore auth.
func testEffectStorage(t *testing.T, store *Store, user identity.SessionRecord) {
	ctx := context.Background()
	t.Run("atomic_effect_audit_outbox", func(t *testing.T) {
		for _, failure := range []string{"", "audit", "outbox"} {
			r, label := effectStorageFixture(t)
			event, _ := NewID()
			err := runEffectStoragePlan(t, store, authorization.EffectRecord{}, r, label, event, failure)
			if (err != nil) != (failure != "") {
				t.Fatal("unexpected storage plan result", err)
			}
			want := 1
			if failure != "" {
				want = 0
			}
			assertEffectStorageCounts(t, store, r.Binding.EffectID, event, want)
		}
	})
	t.Run("exact_cas_one_concurrent_winner", func(t *testing.T) {
		before, label := effectStorageFixture(t)
		event, _ := NewID()
		if err := runEffectStoragePlan(t, store, authorization.EffectRecord{}, before, label, event, ""); err != nil {
			t.Fatal(err)
		}
		after := before
		after.State = authorization.EffectConsumed
		after.Version++
		var wins atomic.Int32
		var group sync.WaitGroup
		ids := []string{}
		for range 2 {
			id, _ := NewID()
			ids = append(ids, id)
		}
		for _, id := range ids {
			group.Add(1)
			go func() {
				defer group.Done()
				if runEffectStoragePlan(t, store, before, after, label, id, "") == nil {
					wins.Add(1)
				}
			}()
		}
		group.Wait()
		if wins.Load() != 1 {
			t.Fatal("CAS did not have exactly one winner", wins.Load())
		}
		var stored authorization.EffectRecord
		if err := store.owned(ctx, "authorization", false, func(tx pgx.Tx) error {
			var err error
			stored, _, err = readEffectRowUnlocked(ctx, tx, before.Binding.EffectID)
			return err
		}); err != nil || stored.State != authorization.EffectConsumed || stored.Version != 2 {
			t.Fatal("CAS state mismatch", err)
		}
		staleEvent, _ := NewID()
		if err := runEffectStoragePlan(t, store, before, after, label, staleEvent, ""); err == nil {
			t.Fatal("stale full row CAS accepted")
		}
		assertEffectStorageCounts(t, store, "", staleEvent, 0)
		// A changed immutable binding with the correct version cannot match.
		foreign := stored
		foreign.Binding.PlanDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		next := foreign
		next.State = authorization.EffectReconciling
		next.Version++
		foreignEvent, _ := NewID()
		if err := runEffectStoragePlan(t, store, foreign, next, label, foreignEvent, ""); err == nil {
			t.Fatal("foreign plan won CAS")
		}
		assertEffectStorageCounts(t, store, "", foreignEvent, 0)
	})
	t.Run("one_original_project_operation", func(t *testing.T) {
		first, label := effectStorageFixture(t)
		event, _ := NewID()
		if err := runEffectStoragePlan(t, store, authorization.EffectRecord{}, first, label, event, ""); err != nil {
			t.Fatal(err)
		}
		second := first
		second.Binding.EffectID, _ = NewID()
		second.Binding.OperationID, _ = NewID()
		second.Binding.PlanID, _ = NewID()
		duplicateEvent, _ := NewID()
		if err := runEffectStoragePlan(t, store, authorization.EffectRecord{}, second, label, duplicateEvent, ""); err == nil {
			t.Fatal("second Project backing operation admitted")
		}
		assertEffectStorageCounts(t, store, second.Binding.EffectID, duplicateEvent, 0)
	})
	t.Run("session_pending_never_acknowledges_open_effect", func(t *testing.T) {
		r, label := effectStorageFixture(t)
		r.Authorization.InstanceID = store.config.InstanceID
		r.Authorization.SecurityDomain = store.config.SecurityDomain
		r.Authorization.SessionID = user.ID
		r.Authorization.Actor = user.Principal
		event, _ := NewID()
		if err := runEffectStoragePlan(t, store, authorization.EffectRecord{}, r, label, event, ""); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeSession(ctx, user.ID); err == nil {
			t.Fatal("issued effect treated as drained")
		}
		var pending, active bool
		if err := store.owned(ctx, "authorization", false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT pending FROM "authorization".session_fences WHERE session_id=$1`, user.ID).Scan(&pending)
		}); err != nil || !pending {
			t.Fatal("pending did not commit", err)
		}
		if err := store.owned(ctx, "identity", false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT active FROM identity.sessions WHERE id=$1`, user.ID).Scan(&active)
		}); err != nil || !active {
			t.Fatal("identity was revoked before drain", err)
		}
		for _, state := range []authorization.EffectState{authorization.EffectConsumed, authorization.EffectReconciling} {
			next := r
			next.State = state
			next.Version++
			id, _ := NewID()
			if err := runEffectStoragePlan(t, store, r, next, label, id, ""); err != nil {
				t.Fatal(err)
			}
			r = next
			if err := store.RevokeSession(ctx, user.ID); err == nil {
				t.Fatal("nonterminal effect acknowledged revocation", state)
			}
		}
		// Actual owner-table corruption fixture: a terminal index alone must
		// not hide a still-reconciling record from the acknowledgment guard.
		if err := store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE "authorization".effects SET state='terminal' WHERE id=$1`, r.Binding.EffectID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeSession(ctx, user.ID); err == nil {
			t.Fatal("terminal index without matching terminal evidence acknowledged drain")
		}
		terminal := r
		terminal.State, terminal.TerminalOutcome = authorization.EffectTerminal, authorization.EffectCanceledBeforeEffect
		for _, corruption := range []struct {
			name      string
			record    []byte
			labelJSON []byte
		}{
			{"truncated_terminal", truncatedTerminalRecord(terminal), encode(label)},
			{"case_aliased_terminal", caseAliasedTerminalRecord(r), encode(label)},
			{"truncated_terminal_label", encode(terminal), []byte(`{"version":1}`)},
			{"oversize_terminal_record", encode(map[string]any{"State": terminal.State, "Padding": strings.Repeat("x", 65<<10)}), encode(label)},
		} {
			t.Run(corruption.name, func(t *testing.T) {
				// Deliberate corruption in this fresh test-only database. Resetting
				// pending here proves the failing inspection leaves a NEW fence
				// commit, rather than relying on a preceding denial's state.
				if err := store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, `UPDATE "authorization".session_fences SET pending=false WHERE session_id=$1`, user.ID); err != nil {
						return err
					}
					_, err := tx.Exec(ctx, `UPDATE "authorization".effects SET state='terminal',record=$2,label=$3 WHERE id=$1`, r.Binding.EffectID, corruption.record, corruption.labelJSON)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if err := store.RevokeSession(ctx, user.ID); err == nil {
					t.Fatal("malformed terminal evidence acknowledged drain")
				}
				if err := store.owned(ctx, "authorization", false, func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, `SELECT pending FROM "authorization".session_fences WHERE session_id=$1`, user.ID).Scan(&pending)
				}); err != nil || !pending {
					t.Fatal("malformed inspection rolled pending back", err)
				}
				if err := store.owned(ctx, "identity", false, func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, `SELECT active FROM identity.sessions WHERE id=$1`, user.ID).Scan(&active)
				}); err != nil || !active {
					t.Fatal("malformed terminal evidence revoked identity", err)
				}
			})
		}
		if err := store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE "authorization".effects SET state='reconciling',record=$2,label=$3 WHERE id=$1`, r.Binding.EffectID, encode(r), encode(label))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		t.Run("inspection_timeout_preserves_pending", func(t *testing.T) {
			if err := store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE "authorization".session_fences SET pending=false WHERE session_id=$1`, user.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// This fresh fixture lock blocks only the inspection, not the fence.
			// It is released when this test-owned transaction returns.
			if err := store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `LOCK TABLE "authorization".effects IN ACCESS EXCLUSIVE MODE`); err != nil {
					return err
				}
				bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
				if err := store.RevokeSession(bounded, user.ID); err == nil || bounded.Err() != context.DeadlineExceeded {
					return errors.New("inspection did not deny at the caller deadline")
				}
				return tx.QueryRow(ctx, `SELECT pending FROM "authorization".session_fences WHERE session_id=$1`, user.ID).Scan(&pending)
			}); err != nil || !pending {
				t.Fatal("inspection timeout lost committed pending", err)
			}
			if err := store.owned(ctx, "identity", false, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT active FROM identity.sessions WHERE id=$1`, user.ID).Scan(&active)
			}); err != nil || !active {
				t.Fatal("inspection timeout acknowledged revocation", err)
			}
		})
		// This helper's private writes did not become local process provenance.
		if len(store.effectOrigins) != 0 {
			t.Fatal("storage fixture minted execution provenance")
		}
	})
	t.Log("real PG effect storage fixture: owner roles, immutable event route, rollback, exact competing CAS, Project reservation and pending/nonterminal drain denial; no sealed provider authorization or effect dispatch")
}

func runEffectStoragePlan(t *testing.T, store *Store, before, after authorization.EffectRecord, label classification.Label, eventID, failure string) error {
	t.Helper()
	ctx := context.Background()
	contract, err := transaction.NewBackendContract(store)
	if err != nil {
		return err
	}
	type input struct{ Value bool }
	parts := []transaction.TypedParticipant[input]{}
	for _, owner := range []string{"authorization", "audit"} {
		operation, err := transaction.NewBackendOperation(contract, owner, func(ctx context.Context, binding transaction.ExecutorBinding, _ input) error {
			session, err := store.session(binding)
			if err != nil {
				return err
			}
			if err = session.role(ctx, owner); err != nil {
				return err
			}
			if owner == "authorization" {
				session.result.ID = after.Binding.Project.ID
				return writeEffectRow(ctx, session.tx, before, after, label)
			}
			if err = appendEffectAudit(ctx, session.tx, eventID, before, after, before.State != ""); err != nil {
				return err
			}
			if failure == "audit" {
				return errors.New("unit injected failure after real audit INSERT")
			}
			return nil
		})
		if err != nil {
			return err
		}
		registered, err := transaction.NewRegisteredOperation(operation, func(ctx context.Context, port transaction.OperationPort[input], _ input) error {
			return port.Execute(ctx)
		})
		if err != nil {
			return err
		}
		afterKeys := []string{}
		if len(parts) > 0 {
			afterKeys = []string{parts[len(parts)-1].Key}
		}
		parts = append(parts, transaction.TypedParticipant[input]{Key: owner, After: afterKeys, DeclaresWrite: true, Operation: registered})
	}
	template, planContract, err := transaction.NewPlanContract(transaction.ContractVersionV1, "postgres.effect.storage_test.v1", parts, transaction.OutboxRequired)
	if err != nil {
		return err
	}
	registry, err := transaction.NewRegistry([]transaction.PlanTemplate{template})
	if err != nil {
		return err
	}
	appender, err := transaction.NewStorageOutbox(contract, func(ctx context.Context, binding transaction.ExecutorBinding, intent outbox.ValidatedIntent) error {
		if err := store.appendOutbox(ctx, binding, intent); err != nil {
			return err
		}
		if failure == "outbox" {
			return errors.New("unit injected failure after real outbox INSERT")
		}
		return nil
	})
	if err != nil {
		return err
	}
	coordinator, err := transaction.NewCoordinator(transaction.Configuration{Backend: contract, Registry: registry, Outbox: appender})
	if err != nil {
		return err
	}
	encoded, err := audit.EffectEvent(eventID, after, label)
	if err != nil {
		return err
	}
	intent, err := outbox.NewValidationAuthority().WrapValidated(outbox.ValidatedIntentHandoffV1, encoded)
	if err != nil {
		return err
	}
	plan, err := planContract.Bind(registry, input{}, &intent)
	if err != nil {
		return err
	}
	_, err = coordinator.Execute(ctx, plan)
	return err
}

func assertEffectStorageCounts(t *testing.T, store *Store, effectID, eventID string, want int) {
	t.Helper()
	ctx := context.Background()
	for _, owner := range []string{"authorization", "audit", "core_outbox"} {
		id, query := eventID, `SELECT count(*) FROM audit.records WHERE id=$1`
		if owner == "authorization" {
			if effectID == "" {
				continue
			}
			id, query = effectID, `SELECT count(*) FROM "authorization".effects WHERE id=$1`
		}
		if owner == "core_outbox" {
			query = `SELECT count(*) FROM core_outbox.intents WHERE id=$1 AND subject='stead.authorization.changed.v1'`
		}
		var count int
		if err := store.owned(ctx, owner, false, func(tx pgx.Tx) error { return tx.QueryRow(ctx, query, id).Scan(&count) }); err != nil || count != want {
			t.Fatal("effect transaction atomicity mismatch", owner, count, err)
		}
	}
}

// readEffectRow deliberately takes a write lock; this read-only test helper
// observes final persisted state without pretending to validate a transition.
func readEffectRowUnlocked(ctx context.Context, tx pgx.Tx, id string) (authorization.EffectRecord, classification.Label, error) {
	var raw, labelRaw []byte
	err := tx.QueryRow(ctx, `SELECT record,label FROM "authorization".effects WHERE id=$1`, id).Scan(&raw, &labelRaw)
	var r authorization.EffectRecord
	var label classification.Label
	if err != nil {
		return r, label, err
	}
	if err = strictEffectJSON(raw, &r); err != nil {
		return r, label, err
	}
	err = strictEffectJSON(labelRaw, &label)
	return r, label, err
}
