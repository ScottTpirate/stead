package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/modules/authorization"
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
		if e.Actor != first.Actor || e.SessionID != first.SessionID || e.ActivationDigest != first.ActivationDigest || e.InstanceID != store.config.InstanceID || seen[e.Target] {
			return transaction.BoundRevision{}, authorization.ErrDenied
		}
		seen[e.Target] = true
		switch e.Action {
		case authorization.OrganizationRead, authorization.TeamRead, authorization.ProjectRead:
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
	if err = session.role(ctx, "identity"); err != nil {
		return err
	}
	identityState, err := loadSession(ctx, session.tx, "s.id=$1", primary.SessionID, true)
	if err != nil || identityState.Principal != primary.Actor {
		return authorization.ErrDenied
	}
	states := make([]authorization.State, 0, len(decisions))
	for _, decision := range decisions {
		e := decision.Evidence()
		if err = session.role(ctx, "authorization"); err != nil {
			return err
		}
		security, err := loadSecurity(ctx, session.tx, e.Actor, e.SessionID, e.Target, true)
		if err != nil {
			return err
		}
		applyIdentity(&security.state, identityState)
		if err = session.role(ctx, "classification"); err != nil {
			return err
		}
		security.state.Label, err = loadLabel(ctx, session.tx, security.labelID, true)
		if err != nil {
			return err
		}
		security.state.Revisions.Label = security.state.Label.Version
		if e.Target.Kind != "instance" {
			owner, query := canonicalQuery(e.Target.Kind)
			if owner == "" {
				return authorization.ErrDenied
			}
			if err = session.role(ctx, owner); err != nil {
				return err
			}
			var organization string
			err = session.tx.QueryRow(ctx, query+` FOR SHARE`, e.Target.ID).Scan(&organization)
			count(ctx, 1, 0, 0, 0)
			if err != nil || organization != security.state.OrganizationID {
				return authorization.ErrDenied
			}
		}
		states = append(states, security.state)
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
	if now.Before(anchor.PolicyTimeHighWater) {
		now = anchor.PolicyTimeHighWater
	}
	if !now.Before(proof.ExpiresAt) {
		return transaction.RecheckReceipt{}, authorization.ErrDenied
	}
	for _, prior := range proof.States {
		current, err := store.ReadState(ctx, prior.Principal, prior.SessionID, prior.Resource)
		if err != nil || current.PolicyTimeHighWater.After(anchor.PolicyTimeHighWater) || current.PolicyTimeRevision > anchor.PolicyTimeRevision || anchor.PolicyTimeHighWater.Before(prior.PolicyTimeHighWater) || anchor.PolicyTimeRevision < prior.PolicyTimeRevision {
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
	if finished.Before(latest.PolicyTimeHighWater) {
		finished = latest.PolicyTimeHighWater
	}
	if !finished.Before(proof.ExpiresAt) {
		return transaction.RecheckReceipt{}, authorization.ErrDenied
	}
	return issuer.Confirm(revision)
}
