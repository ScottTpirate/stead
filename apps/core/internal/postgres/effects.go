package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/modules/audit"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/project"
	"github.com/jackc/pgx/v5"
)

type effectOperationKey struct{}
type effectRequest struct {
	issue            *authorization.EffectIssue
	consume          *authorization.EffectConsume
	transition       *authorization.EffectTransition
	expected, result authorization.EffectRecord
	label            classification.Label
	intent           outbox.ValidatedIntent
}

var _ authorization.EffectStore = (*Store)(nil)

func (store *Store) IssueEffect(ctx context.Context, issue *authorization.EffectIssue) error {
	if issue == nil {
		return authorization.ErrDenied
	}
	return store.executeEffect(ctx, &effectRequest{issue: issue, expected: issue.Expected()})
}
func (store *Store) ConsumeEffect(ctx context.Context, consume *authorization.EffectConsume) error {
	if consume == nil {
		return authorization.ErrDenied
	}
	return store.executeEffect(ctx, &effectRequest{consume: consume, expected: consume.Expected()})
}
func (store *Store) TransitionEffect(ctx context.Context, transition *authorization.EffectTransition) error {
	if transition == nil {
		return authorization.ErrDenied
	}
	return store.executeEffect(ctx, &effectRequest{transition: transition, expected: transition.Expected()})
}

func (store *Store) executeEffect(ctx context.Context, request *effectRequest) error {
	if store == nil || store.coordinator == nil || ctx == nil || ctx.Err() != nil || request.expected.Validate() != nil ||
		request.expected.Authorization.InstanceID != store.config.InstanceID || request.expected.Authorization.SecurityDomain != store.config.SecurityDomain {
		return authorization.ErrDenied
	}
	if request.transition != nil {
		// Only bookkeeping for an operation issued by this live Store is in
		// scope. This is historical causal User evidence, not a new recovery
		// principal, fresh User authority, terminal proof or dispatch grant.
		store.mutex.Lock()
		origin, ok := store.effectOrigins[request.expected.Binding.EffectID]
		store.mutex.Unlock()
		if !ok || !sameEffectOrigin(origin, request.expected) {
			return authorization.ErrDenied
		}
	} else {
		decisions := authorization.DecisionsFromContext(ctx)
		if len(decisions) != 1 || !reflect.DeepEqual(decisions[0].Evidence(), request.expected.Authorization) {
			return authorization.ErrDenied
		}
	}
	_, _, err := store.coordinator.PrepareDurableEffect(context.WithValue(ctx, effectOperationKey{}, request))
	if err != nil {
		return authorization.ErrDenied
	}
	store.mutex.Lock()
	if store.effectOrigins == nil {
		store.effectOrigins = map[string]authorization.EffectRecord{}
	}
	if request.result.State == authorization.EffectTerminal {
		delete(store.effectOrigins, request.result.Binding.EffectID)
	} else if request.issue != nil {
		store.effectOrigins[request.result.Binding.EffectID] = request.result
	}
	store.mutex.Unlock()
	return nil // Only after the coordinator's actual COMMIT acknowledgment.
}

func sameEffectOrigin(origin, record authorization.EffectRecord) bool {
	origin.State, origin.Version, origin.UpdatedAt = record.State, record.Version, record.UpdatedAt
	origin.TerminalOutcome, origin.TerminalProofDigest = record.TerminalOutcome, record.TerminalProofDigest
	return reflect.DeepEqual(origin, record)
}

// Prepare returns only the WS06-owned result plus WS07-validated immutable
// intent. The core issuer/receipt grants no permission to call a provider.
func (store *Store) Prepare(ctx context.Context, port transaction.OperationPort[*transaction.DurableEffectOperation], issuer transaction.DurableEffectIssuer) (transaction.DurableEffectPreparation, error) {
	request, ok := ctx.Value(effectOperationKey{}).(*effectRequest)
	if !ok || request == nil {
		return transaction.DurableEffectPreparation{}, authorization.ErrDenied
	}
	if err := port.Execute(ctx); err != nil {
		return transaction.DurableEffectPreparation{}, err
	}
	receipt, err := issuer.BindValidated(transaction.DurableEffectHandoffV1, encode(request.result))
	return transaction.DurableEffectPreparation{Receipt: receipt, Intent: request.intent}, err
}

func (store *Store) effectOperation(ctx context.Context, binding transaction.ExecutorBinding, _ *transaction.DurableEffectOperation) error {
	request, ok := ctx.Value(effectOperationKey{}).(*effectRequest)
	if !ok || request == nil {
		return authorization.ErrDenied
	}
	session, err := store.session(binding)
	if err != nil {
		return err
	}
	e := request.expected.Authorization
	// Fixed root-owned reads: identity, authorization, classification, Project.
	// Each typed owner callback runs under only its own execution role.
	states, err := store.readStates(ctx, e.Actor, e.SessionID, []authorization.ResourceRef{e.Target}, true, func(owner string, read func(pgx.Tx) error) error {
		if err := session.role(ctx, owner); err != nil {
			return err
		}
		return read(session.tx)
	})
	if err != nil || len(states) != 1 || states[0].Resource != e.Target || states[0].OrganizationID != e.OrganizationID {
		return authorization.ErrDenied
	}
	state := states[0]
	if request.issue != nil {
		if err = store.effectProjectSnapshot(ctx, session, request.expected); err != nil {
			return err
		}
	}
	if err = session.role(ctx, "authorization"); err != nil {
		return err
	}
	var before authorization.EffectRecord
	if request.issue == nil {
		before, request.label, err = readEffectRow(ctx, session.tx, request.expected.Binding.EffectID)
		if err != nil || !reflect.DeepEqual(before, request.expected) || !reflect.DeepEqual(state.Label, request.label) {
			// Do not relabel historical evidence downward or impersonate the
			// old User after a classification change. It remains nonterminal
			// for the separately authorized recovery path, which is inactive.
			return authorization.ErrDenied
		}
	} else {
		request.label = state.Label.Copy()
	}
	if request.transition == nil {
		decision, _ := authorization.DecisionFromContext(ctx)
		anchor, err := store.config.Anchor.CompareMax(ctx, decision.Binding(), time.Now().UTC())
		if err != nil {
			return authorization.ErrDenied
		}
		state.PolicyTimeHighWater, state.PolicyTimeRevision = anchor.PolicyTimeHighWater, anchor.PolicyTimeRevision
		now := time.Now().UTC() // Include lock acquisition and anchor fsync.
		if request.issue != nil {
			request.result, err = request.issue.Validate(state, now)
		} else {
			request.result, err = request.consume.Validate(before, state, now)
		}
		if err != nil {
			return authorization.ErrDenied
		}
		_, err = session.tx.Exec(ctx, `UPDATE "authorization".namespace SET policy_time=GREATEST(policy_time,$1),policy_revision=GREATEST(policy_revision,$2) WHERE id`, anchor.PolicyTimeHighWater, anchor.PolicyTimeRevision)
		count(ctx, 1, 1, 0, 0)
		if err != nil {
			return err
		}
	} else {
		request.result, err = request.transition.Validate(before)
		if err != nil {
			return authorization.ErrDenied
		}
		if request.result.State != authorization.EffectReconciling && !(before.State == authorization.EffectIssued && request.result.State == authorization.EffectTerminal && request.result.TerminalOutcome == authorization.EffectCanceledBeforeEffect) {
			return authorization.ErrDenied // No provider-proof terminalizer yet.
		}
	}
	if err = writeEffectRow(ctx, session.tx, before, request.result, request.label); err != nil {
		return err
	}
	eventID, err := NewID()
	if err != nil {
		return err
	}
	payload, err := audit.EffectEvent(eventID, request.result, request.label)
	if err != nil {
		return err
	}
	request.intent, err = outbox.NewValidationAuthority().WrapValidated(outbox.ValidatedIntentHandoffV1, payload)
	if err != nil {
		return err
	}
	if err = session.role(ctx, "audit"); err != nil {
		return err
	}
	if err = appendEffectAudit(ctx, session.tx, eventID, before, request.result, request.transition != nil); err != nil {
		return err
	}
	session.result.ID = e.Target.ID // Final core_outbox append binds this Project.
	return nil
}

func (store *Store) effectProjectSnapshot(ctx context.Context, session *runtimeSession, expected authorization.EffectRecord) error {
	if err := session.role(ctx, "project"); err != nil {
		return err
	}
	var org string
	var raw []byte
	err := session.tx.QueryRow(ctx, `SELECT organization_id::text,record FROM project.projects WHERE id=$1 AND active FOR UPDATE`, expected.Binding.Project.ID).Scan(&org, &raw)
	count(ctx, 1, 0, 0, 0)
	var value project.Project
	if err != nil || json.Unmarshal(raw, &value) != nil || value.ID != expected.Binding.Project.ID || value.OrganizationID != org || org != expected.Authorization.OrganizationID || value.InstanceID != store.config.InstanceID || value.Version != 1 || value.LifecycleState != "active" || value.Capabilities.Preset != "general" || !reflect.DeepEqual(value.Capabilities.Active, []string{"work", "docs"}) {
		return authorization.ErrDenied
	}
	// This first provision plan reserves one original operation per Project.
	// No retry, second backing or reassignment is inferred from a terminal row.
	// Future WS03 canonical backing acceptance remains a separate owned port.
	return nil
}

func readEffectRow(ctx context.Context, tx pgx.Tx, id string) (authorization.EffectRecord, classification.Label, error) {
	record, label, err := scanEffectRow(tx.QueryRow(ctx, `SELECT `+effectRowProjection+` FROM "authorization".effects WHERE id=$1 FOR UPDATE`, id))
	count(ctx, 1, 0, 0, 0)
	if err != nil || record.Binding.EffectID != id {
		return authorization.EffectRecord{}, classification.Label{}, authorization.ErrDenied
	}
	return record, label, nil
}

// Bound each JSON value before it crosses the database connection. The extra
// byte makes oversize values fail closed, rather than accepting a truncated
// prefix. The same complete row decoder serves locked CAS and streaming drain.
const effectRowProjection = `id::text,operation_id::text,project_id::text,session_id::text,state,version,
 substring(convert_to(record::text,'UTF8') from 1 for 65537),
 substring(convert_to(label::text,'UTF8') from 1 for 65537)`

func scanEffectRow(row pgx.Row) (authorization.EffectRecord, classification.Label, error) {
	var stored storedEffectRow
	if err := row.Scan(&stored.id, &stored.operationID, &stored.projectID, &stored.sessionID, &stored.state, &stored.version, &stored.raw, &stored.labelRaw); err != nil {
		return authorization.EffectRecord{}, classification.Label{}, authorization.ErrDenied
	}
	return stored.decode()
}

type storedEffectRow struct {
	id, operationID, projectID, sessionID, state string
	version                                      uint64
	raw, labelRaw                                []byte
}

func (stored storedEffectRow) decode() (authorization.EffectRecord, classification.Label, error) {
	var record authorization.EffectRecord
	var label classification.Label
	if strictEffectJSON(stored.raw, &record) != nil || strictEffectJSON(stored.labelRaw, &label) != nil || record.Validate() != nil || record.Binding.EffectID != stored.id || record.Binding.OperationID != stored.operationID || record.Binding.Project.ID != stored.projectID || record.Authorization.SessionID != stored.sessionID || string(record.State) != stored.state || record.Version != stored.version || label.Version != record.Authorization.Revisions.Label {
		return authorization.EffectRecord{}, classification.Label{}, authorization.ErrDenied
	}
	// Reuse the WS07-owned label/envelope validation for this fixed native
	// lifecycle. No event is appended and this shape check grants no authority.
	if _, err := audit.EffectEvent(stored.id, record, label); err != nil {
		return authorization.EffectRecord{}, classification.Label{}, authorization.ErrDenied
	}
	return record, label, nil
}

func strictEffectJSON(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) {
		return authorization.ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return authorization.ErrDenied
	}
	if decoder.Decode(new(any)) != io.EOF {
		return authorization.ErrDenied
	}
	// JSONB preserves case-distinct keys, while the Go struct decoder aliases
	// them. Require exactly the current writer's recursive keys/types/values.
	// Compare parsed values, not bytes: JSONB may reorder keys and whitespace.
	// UseNumber preserves integer identity above float64's exact range.
	parse := func(data []byte) (any, error) {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		err := decoder.Decode(&value)
		return value, err
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return authorization.ErrDenied
	}
	actual, err := parse(raw)
	if err != nil {
		return authorization.ErrDenied
	}
	expected, err := parse(canonical)
	if err != nil || !reflect.DeepEqual(actual, expected) {
		return authorization.ErrDenied
	}
	return nil
}

func writeEffectRow(ctx context.Context, tx pgx.Tx, before, after authorization.EffectRecord, label classification.Label) error {
	if after.Validate() != nil || label.Version != after.Authorization.Revisions.Label {
		return authorization.ErrDenied
	}
	if before.State == "" {
		if after.State != authorization.EffectIssued || after.Version != 1 {
			return authorization.ErrDenied
		}
		_, err := tx.Exec(ctx, `INSERT INTO "authorization".effects(id,operation_id,project_id,session_id,state,version,record,label) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, after.Binding.EffectID, after.Binding.OperationID, after.Binding.Project.ID, after.Authorization.SessionID, string(after.State), after.Version, encode(after), encode(label))
		count(ctx, 1, 1, 0, 0)
		return err
	}
	if before.Validate() != nil || before.Version == ^uint64(0) || after.Version != before.Version+1 || !sameEffectOrigin(before, after) {
		return authorization.ErrDenied
	}
	allowed := (before.State == authorization.EffectIssued && after.State == authorization.EffectConsumed) ||
		(before.State == authorization.EffectConsumed && after.State == authorization.EffectReconciling) ||
		(before.State == authorization.EffectIssued && after.State == authorization.EffectTerminal && after.TerminalOutcome == authorization.EffectCanceledBeforeEffect)
	if !allowed || after.UpdatedAt.Before(before.UpdatedAt) {
		return authorization.ErrDenied
	}
	tag, err := tx.Exec(ctx, `UPDATE "authorization".effects SET state=$1,version=$2,record=$3 WHERE id=$4 AND state=$5 AND version=$6 AND record=$7::jsonb AND label=$8::jsonb`, string(after.State), after.Version, encode(after), before.Binding.EffectID, string(before.State), before.Version, encode(before), encode(label))
	count(ctx, 1, uint64(tag.RowsAffected()), 0, 0)
	if err != nil || tag.RowsAffected() != 1 {
		return authorization.ErrDenied
	}
	return nil
}

func appendEffectAudit(ctx context.Context, tx pgx.Tx, id string, before, after authorization.EffectRecord, bookkeeping bool) error {
	// Full protected evidence is not copied to the minimized CloudEvent. In
	// particular a reconciled bookkeeping write establishes no fresh authority.
	evidence := struct {
		Before, After                authorization.EffectRecord
		OriginalOperationBookkeeping bool
		FreshUserAuthorization       bool
	}{before, after, bookkeeping, !bookkeeping}
	_, err := tx.Exec(ctx, `INSERT INTO audit.records(id,resource_id,actor,action,decision,evidence,occurred_at) VALUES($1,$2,$3,'authorization.effect.change','allow',$4,$5)`, id, after.Binding.Project.ID, after.Authorization.Actor.Type+":"+after.Authorization.Actor.ID, encode(evidence), after.UpdatedAt)
	count(ctx, 1, 1, 1, 0)
	return err
}
