package authorization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

type Config struct {
	Repository Repository
	Denials    DenialRecorder
	OpenFGA    *OpenFGA
	Activation *VerifiedActivation
	Anchor     AnchorReader
	Clock      func() time.Time
}
type Coordinator struct{ config Config }

// MaxPolicyClockSkew is part of the signed local evaluator ABI. A host clock
// rollback beyond this bound denies, even though compare-max never decreases.
const MaxPolicyClockSkew = 5 * time.Second

// VerifiedActivation is sealed by VerifyActivation after archive, both
// signatures, trust, model read-back, runtime policy and anchor verification.
type VerifiedActivation struct {
	binding             ActivationBinding
	evaluator           *classification.Evaluator
	issuedAt, expiresAt time.Time
	valid               bool
}

func (activation *VerifiedActivation) Binding() ActivationBinding {
	if activation == nil {
		return ActivationBinding{}
	}
	return activation.binding
}

func NewCoordinator(config Config) (*Coordinator, error) {
	if config.Repository == nil || config.Denials == nil || config.OpenFGA == nil || config.Activation == nil || !config.Activation.valid || config.Anchor == nil || config.Clock == nil || config.OpenFGA.ModelID() != config.Activation.binding.OpenFGAModelID || config.OpenFGA.StoreID() != config.Activation.binding.OpenFGAStoreID {
		return nil, ErrDenied
	}
	return &Coordinator{config: config}, nil
}

// Decision is one immutable bounded logical decision, never a durable permit
// for provider mutations, credentials, content, streams, or later jobs.
type Decision struct {
	state        State
	evidence     Evidence
	binding      ActivationBinding
	marking      string
	presentation classification.SecurityPresentation
	valid        bool
}

func (decision *Decision) Evidence() Evidence {
	if decision == nil {
		return Evidence{}
	}
	return decision.evidence
}
func (decision *Decision) Marking() string {
	if decision == nil {
		return ""
	}
	return decision.marking
}
func (decision *Decision) Presentation() classification.SecurityPresentation {
	if decision == nil {
		return classification.SecurityPresentation{}
	}
	return decision.presentation.Copy()
}
func (decision *Decision) Binding() ActivationBinding {
	if decision == nil {
		return ActivationBinding{}
	}
	return decision.binding
}

type decisionContextKey struct{}

func (decision *Decision) WithContext(ctx context.Context) context.Context {
	prior := DecisionsFromContext(ctx)
	if decision == nil || !decision.valid || len(prior) >= 2 {
		return context.WithValue(ctx, decisionContextKey{}, []*Decision(nil))
	}
	return context.WithValue(ctx, decisionContextKey{}, append(prior, decision))
}
func DecisionsFromContext(ctx context.Context) []*Decision {
	if ctx == nil {
		return nil
	}
	value, _ := ctx.Value(decisionContextKey{}).([]*Decision)
	return append([]*Decision(nil), value...)
}
func DecisionFromContext(ctx context.Context) (*Decision, bool) {
	values := DecisionsFromContext(ctx)
	if len(values) == 0 {
		return nil, false
	}
	return values[0], true
}

func actionRelation(action Action, target ResourceRef) (string, bool) {
	want, relation := "", ""
	switch action {
	case OrganizationCreate:
		want, relation = "instance", "organization_creator"
	case OrganizationRead:
		want, relation = "organization", "viewer"
	case TeamCreate, ProjectCreate:
		want, relation = "organization", "editor"
	case TeamRead:
		want, relation = "team", "viewer"
	case ProjectRead:
		want, relation = "project", "viewer"
	case TeamProfileManage:
		want, relation = "team", "profile_manager"
	case TeamRoleManage:
		want, relation = "team", "role_manager"
	case TeamHierarchyManage:
		want, relation = "team", "hierarchy_manager"
	}
	return relation, want != "" && target.Kind == want && identity.ValidID(target.ID)
}

func validRevisions(revisions Revisions) bool {
	value := reflect.ValueOf(revisions)
	for i := 0; i < value.NumField(); i++ {
		if value.Field(i).Uint() == 0 {
			return false
		}
	}
	return true
}
func validState(state State, session identity.SessionRecord, target ResourceRef, binding ActivationBinding, now time.Time) bool {
	if session.InstanceID != binding.InstallationID {
		return false
	}
	if state.Resource != target || state.InstanceID != session.InstanceID || state.SecurityDomain != session.SecurityDomain || state.SecurityDomain != binding.DeploymentPolicyID || state.Principal != session.Principal || state.SessionID != session.ID || !state.PrincipalActive || !state.SessionActive || state.TuplePending || !validRevisions(state.Revisions) || state.Revisions.Principal != session.PrincipalRevision || state.Revisions.Session != session.Revision || state.ActivationDigest != binding.Digest() || state.ActivationSetID != binding.ActivationSetID || state.ActivationSequence != binding.ActivationSequence || state.OpenFGAModelID != binding.OpenFGAModelID || state.PolicyTimeHighWater.IsZero() || state.PolicyTimeRevision == 0 || !now.Before(state.ContextExpiresAt) {
		return false
	}
	if target.Kind == "instance" {
		return target.ID == state.InstanceID && state.OrganizationID == ""
	}
	if !identity.ValidID(state.OrganizationID) {
		return false
	}
	return target.Kind != "organization" || state.OrganizationID == target.ID
}

func (coordinator *Coordinator) Authorize(ctx context.Context, session identity.Authenticated, action Action, target ResourceRef) (*Decision, error) {
	if coordinator == nil {
		return nil, ErrDenied
	}
	now := coordinator.config.Clock().UTC()
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return nil, ErrDenied
	}
	id := hex.EncodeToString(material[:])
	deny := func(reason string) (*Decision, error) {
		_ = coordinator.config.Denials.RecordDenial(ctx, Denial{DecisionID: id, Actor: session.Principal(), Action: action, Reason: reason, OccurredAt: now})
		return nil, ErrDenied
	}
	relation, known := actionRelation(action, target)
	if ctx.Err() != nil || !known || !session.ValidAt(now) || session.Principal().Type != "user" {
		return deny("context_denied")
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
	state, err := coordinator.config.Repository.ReadState(ctx, session.Principal(), session.SessionID(), target)
	if err != nil || !validState(state, session.Context(), target, activation.binding, now) {
		return deny("stale_authorization_input")
	}
	// A DB observed time copy may lag its independent anchor, never lead it.
	if state.PolicyTimeHighWater.After(anchor.PolicyTimeHighWater) || state.PolicyTimeRevision > anchor.PolicyTimeRevision {
		return deny("stale_authorization_input")
	}
	state.PolicyTimeHighWater = anchor.PolicyTimeHighWater
	state.PolicyTimeRevision = anchor.PolicyTimeRevision
	allowed, err := coordinator.config.OpenFGA.Check(ctx, Tuple{User: session.Principal().Type + ":" + session.Principal().ID, Relation: relation, Object: target.Kind + ":" + target.ID})
	if err != nil {
		return deny("relationship_denied")
	}
	result, err := activation.evaluator.Evaluate(state.Label, session.Context())
	if err != nil && result.DenialReason == "" {
		return deny("context_denied")
	}
	policy := NativePolicyDecision(NativePolicyFacts{
		PrincipalType: session.Principal().Type, Operation: "metadata",
		RelationshipAllowed: allowed, ProviderPathAllowed: state.ProviderPathAllowed,
		FenceCurrent: true, ExplicitDeny: state.ExplicitDeny,
		TrustedAttributesValid: true, CapabilityActive: state.CapabilityActive,
		ContextValid: true, ClassificationReason: result.DenialReason,
	})
	if !policy.Allowed {
		return deny(policy.Reason)
	}
	finished := coordinator.config.Clock().UTC()
	if finished.Before(now) {
		finished = now
	}
	expires := now.Add(2 * time.Second)
	for _, bound := range []time.Time{session.ExpiresAt(), state.ContextExpiresAt, activation.expiresAt} {
		if bound.Before(expires) {
			expires = bound
		}
	}
	if ctx.Err() != nil || !finished.Before(expires) {
		return deny("context_denied")
	}
	b := activation.binding
	evidence := Evidence{DecisionID: id, Actor: session.Principal(), SessionID: session.SessionID(), Action: action, Target: target, InstanceID: state.InstanceID, OrganizationID: state.OrganizationID, SecurityDomain: state.SecurityDomain, Relation: relation, OpenFGAModelID: b.OpenFGAModelID, PolicyBundleID: b.PolicyBundleID, ActivationSetID: b.ActivationSetID, ActivationSequence: b.ActivationSequence, ActivationDigest: b.Digest(), ActivationEpoch: b.ActivationEpoch, TrustEpoch: b.TrustEpoch, DeploymentPolicyID: b.DeploymentPolicyID, DeploymentPolicyVersion: b.DeploymentPolicyVersion, DeploymentPolicyDigest: b.DeploymentPolicyDigest, SignedEnvelopeDigest: b.SignedEnvelopeDigest, ArchiveDigest: b.ArchiveDigest, ReleaseAttestationID: b.ReleaseAttestationID, ReleaseAttestationEnvelopeDigest: b.ReleaseAttestationEnvelopeDigest, TrustSetID: b.TrustSetID, TrustEnvelopeDigest: b.TrustEnvelopeDigest, ModelSourceDigest: b.ModelSourceDigest, EvaluatorContractVersion: b.EvaluatorContractVersion, Revisions: state.Revisions, PolicyTimeHighWater: anchor.PolicyTimeHighWater, PolicyTimeRevision: anchor.PolicyTimeRevision, EvaluatedAt: now, ExpiresAt: expires, DisclosureMode: b.DisclosureMode, OpenFGACalls: 1}
	state.Label = state.Label.Copy()
	result.Presentation.PolicyBundleID = b.PolicyBundleID
	return &Decision{state: state, evidence: evidence, binding: b, marking: result.Marking, presentation: result.Presentation.Copy(), valid: true}, nil
}

// ValidateFinal performs no network or repository I/O. The registered root
// participant must load every canonical revision while holding its SQL fence,
// compare-max the independent time anchor, then supply that latest time here.
// A time-only advance is normal; activation/revocation/resource changes deny.
func (decision *Decision) ValidateFinal(current State, now time.Time) error {
	if current.PolicyTimeHighWater.Sub(now) > MaxPolicyClockSkew {
		return ErrDenied
	}
	if decision == nil || !decision.valid || current.PolicyTimeHighWater.Before(decision.state.PolicyTimeHighWater) || current.PolicyTimeRevision < decision.state.PolicyTimeRevision {
		return ErrDenied
	}
	if now.Before(current.PolicyTimeHighWater) {
		now = current.PolicyTimeHighWater
	}
	if now.Before(decision.evidence.EvaluatedAt) || !now.Before(decision.evidence.ExpiresAt) {
		return ErrDenied
	}
	current.PolicyTimeHighWater = decision.state.PolicyTimeHighWater
	current.PolicyTimeRevision = decision.state.PolicyTimeRevision
	if !reflect.DeepEqual(current, decision.state) {
		return ErrDenied
	}
	return nil
}
