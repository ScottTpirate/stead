package authorization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

const MaxReadSet = 101

// AuthorizeSet is one fresh, bounded logical metadata read, not a collection
// of durable permits. It never falls back to per-row repository/network calls.
// Denied/missing rows are aligned nil slots, never existence disclosures. A
// malformed input, repository failure or incomplete provider result denies the
// entire set. The caller must still run the final response fence on all seals.
func (coordinator *Coordinator) AuthorizeSet(ctx context.Context, session identity.Authenticated, reads []ReadAuthorization) ([]*Decision, error) {
	return coordinator.authorizeSet(ctx, session, reads, 0)
}

// AuthorizeCollection distinguishes a denied collection request from filtered
// candidates. The first read is the containing scope; requireRows also requires
// every supplied cursor/response row. Only a denied required read emits one
// aggregate denial, never an audit per hidden candidate. Aligned nil results and
// final-fence obligations are unchanged; this method grants no new permission.
func (coordinator *Coordinator) AuthorizeCollection(ctx context.Context, session identity.Authenticated, reads []ReadAuthorization, requireRows bool) ([]*Decision, error) {
	required := 1
	if requireRows && len(reads) > 0 {
		required = len(reads)
	}
	return coordinator.authorizeSet(ctx, session, reads, required)
}

func collectionShape(reads []ReadAuthorization) bool {
	parent := reads[0]
	if parent.Action == OrganizationsList && parent.Target.Kind == "instance" {
		for _, row := range reads[1:] {
			if row.Action != OrganizationRead || row.Target.Kind != "organization" {
				return false
			}
		}
		return true
	}
	if parent.Action != OrganizationRead || parent.Target.Kind != "organization" {
		return false
	}
	for i, row := range reads[1:] {
		if (row.Action != TeamRead || row.Target.Kind != "team") && (row.Action != ProjectRead || row.Target.Kind != "project") {
			return false
		}
		if i > 0 && row.Action != reads[1].Action {
			return false
		}
	}
	return true
}

func (coordinator *Coordinator) authorizeSet(ctx context.Context, session identity.Authenticated, reads []ReadAuthorization, required int) ([]*Decision, error) {
	if coordinator == nil || ctx == nil || len(reads) == 0 || len(reads) > MaxReadSet {
		return nil, ErrDenied
	}
	now := coordinator.config.Clock().UTC()
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return nil, ErrDenied
	}
	id := hex.EncodeToString(material[:])
	deny := func(reason string) ([]*Decision, error) {
		_ = coordinator.config.Denials.RecordDenial(ctx, Denial{DecisionID: id, RequestID: telemetry.CorrelationID(ctx), Actor: session.Principal(), Action: reads[0].Action, Reason: reason, OccurredAt: now})
		return nil, ErrDenied
	}
	if required > 0 && !collectionShape(reads) {
		return deny("context_denied")
	}
	complete := func(decisions []*Decision) ([]*Decision, error) {
		for _, decision := range decisions[:required] {
			if decision == nil {
				// Retain the evaluated set's identity and one request correlation.
				// No target, cursor, hidden count or per-row reason enters the record.
				_ = coordinator.config.Denials.RecordDenial(ctx, Denial{DecisionID: id, RequestID: telemetry.CorrelationID(ctx), Actor: session.Principal(), Action: reads[0].Action, Reason: "context_denied", OccurredAt: now})
				break
			}
		}
		return decisions, nil
	}
	repository, ok := coordinator.config.Repository.(SetRepository)
	if !ok || ctx.Err() != nil || !session.ValidAt(now) || session.Principal().Type != "user" {
		return deny("context_denied")
	}
	refs := make([]ResourceRef, len(reads))
	relations := make([]string, len(reads))
	seen := map[ResourceRef]bool{}
	for i, read := range reads {
		switch read.Action {
		case OrganizationsList, OrganizationRead, TeamRead, ProjectRead:
		default:
			return deny("context_denied")
		}
		relation, known := actionRelation(read.Action, read.Target)
		if !known || seen[read.Target] {
			return deny("context_denied")
		}
		seen[read.Target] = true
		refs[i], relations[i] = read.Target, relation
	}
	anchor, err := coordinator.config.Anchor.Read(ctx)
	activation := coordinator.config.Activation
	if err != nil || anchor.Binding != activation.binding || anchor.PolicyTimeRevision == 0 || anchor.PolicyTimeHighWater.IsZero() {
		return deny("stale_authorization_input")
	}
	if anchor.PolicyTimeHighWater.Sub(now) > MaxPolicyClockSkew {
		return deny("context_denied")
	}
	if now.Before(anchor.PolicyTimeHighWater) {
		now = anchor.PolicyTimeHighWater
	}
	if !session.ValidAt(now) || now.Before(activation.issuedAt) || !now.Before(activation.expiresAt) {
		return deny("context_denied")
	}
	expires := now.Add(2 * time.Second)
	for _, bound := range []time.Time{session.ExpiresAt(), activation.expiresAt} {
		if bound.Before(expires) {
			expires = bound
		}
	}
	states, err := repository.ReadStates(ctx, session.Principal(), session.SessionID(), refs)
	if err != nil || len(states) != len(refs) {
		return deny("stale_authorization_input")
	}
	anchor, err = coordinator.readCurrentAnchor(ctx, anchor)
	if err != nil {
		return deny("stale_authorization_input")
	}
	fresh := coordinator.config.Clock().UTC()
	if anchor.PolicyTimeHighWater.Sub(fresh) > MaxPolicyClockSkew {
		return deny("context_denied")
	}
	if fresh.After(now) {
		now = fresh
	}
	if now.Before(anchor.PolicyTimeHighWater) {
		now = anchor.PolicyTimeHighWater
	}
	if !session.ValidAt(now) || now.Before(activation.issuedAt) || !now.Before(activation.expiresAt) || !now.Before(expires) {
		return deny("context_denied")
	}
	results := make([]classification.Result, len(reads))
	indexes := []int{}
	tuples := []Tuple{}
	for i := range states {
		state := &states[i]
		if state.Resource != refs[i] {
			return deny("stale_authorization_input")
		}
		if required > 0 && i > 0 && refs[0].Kind == "organization" && state.OrganizationID != refs[0].ID {
			continue
		}
		if !validState(*state, session.Context(), refs[i], activation.binding, now) || state.PolicyTimeHighWater.After(anchor.PolicyTimeHighWater) || state.PolicyTimeRevision > anchor.PolicyTimeRevision {
			continue
		}
		state.PolicyTimeHighWater, state.PolicyTimeRevision = anchor.PolicyTimeHighWater, anchor.PolicyTimeRevision
		result, err := activation.evaluator.Evaluate(state.Label, session.Context())
		if err != nil && result.DenialReason == "" {
			continue
		}
		policy := NativePolicyDecision(NativePolicyFacts{PrincipalType: session.Principal().Type, Operation: "metadata", RelationshipAllowed: true, ProviderPathAllowed: state.ProviderPathAllowed, FenceCurrent: true, ExplicitDeny: state.ExplicitDeny, TrustedAttributesValid: true, CapabilityActive: state.CapabilityActive, ContextValid: true, ClassificationReason: result.DenialReason})
		if !policy.Allowed {
			continue
		}
		results[i] = result
		indexes = append(indexes, i)
		tuples = append(tuples, Tuple{User: session.Principal().Type + ":" + session.Principal().ID, Relation: relations[i], Object: refs[i].Kind + ":" + refs[i].ID})
		if state.ContextExpiresAt.Before(expires) {
			expires = state.ContextExpiresAt
		}
	}
	decisions := make([]*Decision, len(reads))
	if len(tuples) == 0 {
		return complete(decisions)
	}
	allowed, err := coordinator.config.OpenFGA.BatchCheck(ctx, tuples)
	if err != nil || len(allowed) != len(tuples) {
		return deny("relationship_denied")
	}
	finished := coordinator.config.Clock().UTC()
	if anchor.PolicyTimeHighWater.Sub(finished) > MaxPolicyClockSkew {
		return deny("context_denied")
	}
	if finished.Before(now) {
		finished = now
	}
	if ctx.Err() != nil || !finished.Before(expires) {
		return deny("context_denied")
	}
	// Calls describe this shared DecisionID, not one call per row. Request
	// telemetry independently counts the actual HTTP calls at the client.
	calls := uint64((len(tuples) + maxBatchChecks - 1) / maxBatchChecks)
	for j, i := range indexes {
		if allowed[j] {
			decisions[i] = sealDecision(states[i], results[i], session, reads[i].Action, refs[i], relations[i], activation.binding, anchor, id, now, expires, calls)
		}
	}
	return complete(decisions)
}
