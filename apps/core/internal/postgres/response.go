package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/jackc/pgx/v5"
)

type responseKey struct{}
type responseOperation struct {
	decisions []*authorization.Decision
	proof     responseProof
}
type responseProof struct {
	States    []authorization.State
	Binding   authorization.ActivationBinding
	ExpiresAt time.Time
}

// boundedPolicyTime rejects excessive rollback before clamping permitted clock
// skew. Callers must sample again after database work; neither clamping nor a
// fresh sample may extend the already-sealed disclosure expiry.
func boundedPolicyTime(now, highWater, expires time.Time) (time.Time, error) {
	if now.IsZero() || highWater.IsZero() || expires.IsZero() || highWater.Sub(now) > authorization.MaxPolicyClockSkew {
		return time.Time{}, authorization.ErrDenied
	}
	if now.Before(highWater) {
		now = highWater
	}
	if !now.Before(expires) {
		return time.Time{}, authorization.ErrDenied
	}
	return now, nil
}

// FinalizeResponse is called once, after the complete finite payload has been
// buffered. A list includes its authorized instance/container plus every row.
// It cannot grant access to any row that lacks a fresh sealed central decision.
func (store *Store) FinalizeResponse(ctx context.Context, decisions []*authorization.Decision) (transaction.BoundRevision, error) {
	if len(decisions) == 0 || len(decisions) > 101 {
		return transaction.BoundRevision{}, authorization.ErrDenied
	}
	operation := &responseOperation{decisions: append([]*authorization.Decision(nil), decisions...)}
	first := decisions[0].Evidence()
	if first.Actor.ID == "" {
		return transaction.BoundRevision{}, authorization.ErrDenied
	}
	seen := map[authorization.ResourceRef]bool{}
	for _, decision := range decisions {
		e := decision.Evidence()
		if e.Actor != first.Actor || e.SessionID != first.SessionID || e.ActivationDigest != first.ActivationDigest || e.InstanceID != store.config.InstanceID || seen[e.Target] || (len(decisions) > 1 && (e.DecisionID != first.DecisionID || e.EvaluatedAt != first.EvaluatedAt || e.ExpiresAt != first.ExpiresAt)) {
			return transaction.BoundRevision{}, authorization.ErrDenied
		}
		seen[e.Target] = true
		switch e.Action {
		case authorization.OrganizationRead, authorization.TeamRead, authorization.ProjectRead:
		case authorization.Action("organization.list"):
			if e.Target.Kind != "instance" {
				return transaction.BoundRevision{}, authorization.ErrDenied
			}
		case authorization.OrganizationCreate:
			if e.Target.Kind != "instance" {
				return transaction.BoundRevision{}, authorization.ErrDenied
			}
		default:
			return transaction.BoundRevision{}, authorization.ErrDenied
		}
	}
	revision, _, err := store.coordinator.FinalizeRead(context.WithValue(ctx, responseKey{}, operation))
	if err != nil {
		return transaction.BoundRevision{}, authorization.ErrDenied
	}
	return revision, nil
}

// Finalize is the fixed aggregate WS-06/WS-07 handoff. There is one audit row
// regardless of the number of already-buffered resources, and no provider I/O.
func (store *Store) Finalize(ctx context.Context, port transaction.OperationPort[*transaction.FinalAuthorizationAuditOperation], issuer transaction.BoundRevisionIssuer) (transaction.FinalAuthorizationAuditResult, error) {
	operation, ok := ctx.Value(responseKey{}).(*responseOperation)
	if !ok || operation == nil {
		return transaction.FinalAuthorizationAuditResult{}, authorization.ErrDenied
	}
	if err := port.Execute(ctx); err != nil {
		return transaction.FinalAuthorizationAuditResult{}, err
	}
	revision, err := issuer.BindValidated(transaction.BoundRevisionHandoffV1, encode(operation.proof))
	return transaction.FinalAuthorizationAuditResult{Revision: revision}, err
}
func (store *Store) finalResponseOperation(ctx context.Context, binding transaction.ExecutorBinding, _ *transaction.FinalAuthorizationAuditOperation) error {
	operation, ok := ctx.Value(responseKey{}).(*responseOperation)
	if !ok || operation == nil {
		return authorization.ErrDenied
	}
	session, err := store.session(binding)
	if err != nil {
		return err
	}
	decisions := operation.decisions
	if len(decisions) == 0 || len(decisions) > 101 {
		return authorization.ErrDenied
	}
	primary := decisions[0].Evidence()
	refs := make([]authorization.ResourceRef, len(decisions))
	for index, decision := range decisions {
		refs[index] = decision.Evidence().Target
	}
	states, err := store.readStates(ctx, primary.Actor, primary.SessionID, refs, true, func(owner string, read func(pgx.Tx) error) error {
		if err := session.role(ctx, owner); err != nil {
			return err
		}
		return read(session.tx)
	})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	anchor, err := store.config.Anchor.CompareMax(ctx, decisions[0].Binding(), now)
	if err != nil {
		return authorization.ErrDenied
	}
	expires := primary.ExpiresAt
	for index, decision := range decisions {
		states[index].PolicyTimeHighWater = anchor.PolicyTimeHighWater
		states[index].PolicyTimeRevision = anchor.PolicyTimeRevision
		if err = decision.ValidateFinal(states[index], now); err != nil {
			return err
		}
		if decision.Evidence().ExpiresAt.Before(expires) {
			expires = decision.Evidence().ExpiresAt
		}
	}
	if err = session.role(ctx, "authorization"); err != nil {
		return err
	}
	_, err = session.tx.Exec(ctx, `UPDATE "authorization".namespace SET policy_time=GREATEST(policy_time,$1),policy_revision=GREATEST(policy_revision,$2) WHERE id`, anchor.PolicyTimeHighWater, anchor.PolicyTimeRevision)
	count(ctx, 1, 1, 0, 0)
	if err != nil {
		return err
	}
	operation.proof = responseProof{States: states, Binding: decisions[0].Binding(), ExpiresAt: expires}
	if err = session.role(ctx, "audit"); err != nil {
		return err
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	evidence := make([]authorization.Evidence, len(decisions))
	for index, decision := range decisions {
		evidence[index] = decision.Evidence()
	}
	_, err = session.tx.Exec(ctx, `INSERT INTO audit.records(id,actor,action,decision,evidence,occurred_at) VALUES($1,$2,'response.read','allow',$3,$4)`, id, primary.Actor.Type+":"+primary.Actor.ID, encode(evidence), now)
	count(ctx, 1, 1, 1, 0)
	return err
}

// Recheck uses owner reads immediately before ReleaseProtected. The immutable
// proof came only from the committed FinalizeRead issuer; opaque bytes supplied
// by request JSON never reach this path or acquire a valid bound revision.
func (store *Store) Recheck(ctx context.Context, revision transaction.BoundRevision, issuer transaction.RecheckIssuer) (transaction.RecheckReceipt, error) {
	var proof responseProof
	if len(revision.OpaqueCopy()) > 1<<20 || json.Unmarshal(revision.OpaqueCopy(), &proof) != nil || len(proof.States) == 0 || len(proof.States) > 101 {
		return transaction.RecheckReceipt{}, authorization.ErrDenied
	}
	now := time.Now().UTC()
	anchor, err := store.config.Anchor.Read(ctx)
	if err != nil || anchor.Binding != proof.Binding {
		return transaction.RecheckReceipt{}, authorization.ErrDenied
	}
	if _, err = boundedPolicyTime(now, anchor.PolicyTimeHighWater, proof.ExpiresAt); err != nil {
		return transaction.RecheckReceipt{}, authorization.ErrDenied
	}
	refs := make([]authorization.ResourceRef, len(proof.States))
	for index, prior := range proof.States {
		if prior.Principal != proof.States[0].Principal || prior.SessionID != proof.States[0].SessionID {
			return transaction.RecheckReceipt{}, authorization.ErrDenied
		}
		refs[index] = prior.Resource
	}
	currents, err := store.ReadStates(ctx, proof.States[0].Principal, proof.States[0].SessionID, refs)
	if err != nil {
		return transaction.RecheckReceipt{}, authorization.ErrDenied
	}
	for index, prior := range proof.States {
		current := currents[index]
		if current.PolicyTimeHighWater.After(anchor.PolicyTimeHighWater) || current.PolicyTimeRevision > anchor.PolicyTimeRevision || anchor.PolicyTimeHighWater.Before(prior.PolicyTimeHighWater) || anchor.PolicyTimeRevision < prior.PolicyTimeRevision {
			return transaction.RecheckReceipt{}, authorization.ErrDenied
		}
		current.PolicyTimeHighWater = prior.PolicyTimeHighWater
		current.PolicyTimeRevision = prior.PolicyTimeRevision
		if !reflect.DeepEqual(current, prior) {
			return transaction.RecheckReceipt{}, authorization.ErrDenied
		}
	}
	// A bounded list can take longer to recheck than one resource. The proof
	// must still be current at the end, not merely when the loop started.
	latest, err := store.config.Anchor.Read(ctx)
	if err != nil || latest.Binding != proof.Binding || latest.PolicyTimeRevision < anchor.PolicyTimeRevision || latest.PolicyTimeHighWater.Before(anchor.PolicyTimeHighWater) {
		return transaction.RecheckReceipt{}, authorization.ErrDenied
	}
	finished := time.Now().UTC()
	if _, err = boundedPolicyTime(finished, latest.PolicyTimeHighWater, proof.ExpiresAt); err != nil {
		return transaction.RecheckReceipt{}, authorization.ErrDenied
	}
	return issuer.Confirm(revision)
}
