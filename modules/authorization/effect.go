package authorization

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/identity"
)

// ProviderMutationEvaluatorContractVersion is an inactive successor capability.
// No current activation consumer or reviewed metadata template admits it.
const ProviderMutationEvaluatorContractVersion = "stead-native-local-provider-mutation-v1"

type EffectState string
type EffectTerminalOutcome string

const (
	EffectIssued      EffectState = "issued"
	EffectConsumed    EffectState = "consumed"
	EffectReconciling EffectState = "reconciling"
	EffectTerminal    EffectState = "terminal"

	EffectCompletedBeforeBoundary    EffectTerminalOutcome = "completed_before_boundary"
	EffectCanceledBeforeEffect       EffectTerminalOutcome = "canceled_before_effect"
	EffectSuppressedBeforeDisclosure EffectTerminalOutcome = "suppressed_before_disclosure"
	EffectRevokedOrFenced            EffectTerminalOutcome = "revoked_or_fenced"
	EffectFailedWithoutEffect        EffectTerminalOutcome = "failed_without_effect"

	CreateHiddenTracker = "create_hidden_tracker"
)

// EffectBinding is constructed from the canonical Project and protected WS-03
// plan by the composition root, never decoded from a client request. The plan
// digest covers the exact fixed operation, provider target and serialized input.
// It contains no provider path, token, request body or returned content.
type EffectBinding struct {
	EffectID, OperationID, PlanID                      string
	RequestID                                          string
	Project                                            ResourceRef
	ProviderInstallationID                             string
	CompatibilityProfileID, CompatibilityProfileDigest string
	PlanDigest                                         string
	ProviderRevision                                   uint64
	OriginalDeadline, ProviderNotAfter                 time.Time
}

func (EffectBinding) String() string           { return "authorization.effect-binding[private]" }
func (binding EffectBinding) GoString() string { return binding.String() }

// EffectRecord is private owner persistence/evidence, never execution authority
// or an event/log DTO. A restored record cannot reconstruct an issued handle.
type EffectRecord struct {
	Binding                        EffectBinding
	Authorization                  Evidence
	Operation                      string
	State                          EffectState
	Version                        uint64
	Process                        EffectProcess
	IssuedAt, ExpiresAt, UpdatedAt time.Time
	TerminalOutcome                EffectTerminalOutcome
	TerminalProofDigest            string
}

func (EffectRecord) String() string          { return "authorization.effect-record[private]" }
func (record EffectRecord) GoString() string { return record.String() }

func effectHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, c := range []byte(value) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func effectDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && effectHex(strings.TrimPrefix(value, "sha256:"), 64)
}
func effectProfile(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range []byte(value) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}
func (binding EffectBinding) valid(evidence Evidence) bool {
	return identity.ValidID(binding.EffectID) && identity.ValidID(binding.OperationID) && identity.ValidID(binding.PlanID) &&
		effectHex(binding.RequestID, 32) && binding.Project.Kind == "project" && identity.ValidID(binding.Project.ID) &&
		binding.Project == evidence.Target && identity.ValidID(binding.ProviderInstallationID) && effectProfile(binding.CompatibilityProfileID) &&
		effectDigest(binding.CompatibilityProfileDigest) && effectDigest(binding.PlanDigest) && binding.ProviderRevision > 0 &&
		binding.ProviderRevision == evidence.Revisions.Provider && !binding.OriginalDeadline.IsZero() && !binding.ProviderNotAfter.IsZero()
}

// Validate checks stored shape only. It never authorizes execution or proves an
// outcome. Owner transactions must additionally compare the entire expected row.
func (record EffectRecord) Validate() error {
	e := record.Authorization
	if !record.Binding.valid(e) || record.Operation != CreateHiddenTracker || record.Version == 0 ||
		e.Action != ProjectBackingProvision || e.Relation != "manager" || e.Actor.Type != "user" || !e.Actor.Valid() ||
		!identity.ValidID(e.SessionID) || !identity.ValidID(e.InstanceID) || !identity.ValidID(e.OrganizationID) ||
		!effectHex(e.DecisionID, 32) || e.SecurityDomain == "" || !validRevisions(e.Revisions) ||
		e.EvaluatorContractVersion != ProviderMutationEvaluatorContractVersion || e.DisclosureMode != "request_boundary" ||
		!record.Process.valid() || record.IssuedAt.IsZero() || record.UpdatedAt.Before(record.IssuedAt) ||
		record.IssuedAt.Before(e.EvaluatedAt) || !record.IssuedAt.Before(record.ExpiresAt) ||
		record.ExpiresAt.After(e.ExpiresAt) || record.ExpiresAt.After(record.Binding.OriginalDeadline) ||
		record.ExpiresAt.After(record.Binding.ProviderNotAfter) || record.ExpiresAt.After(record.IssuedAt.Add(5*time.Second)) {
		return ErrDenied
	}
	switch record.State {
	case EffectIssued, EffectConsumed, EffectReconciling:
		if record.TerminalOutcome != "" || record.TerminalProofDigest != "" {
			return ErrDenied
		}
	case EffectTerminal:
		switch record.TerminalOutcome {
		case EffectCanceledBeforeEffect:
			if record.TerminalProofDigest != "" {
				return ErrDenied
			}
		case EffectCompletedBeforeBoundary, EffectSuppressedBeforeDisclosure, EffectRevokedOrFenced, EffectFailedWithoutEffect:
			if !effectDigest(record.TerminalProofDigest) {
				return ErrDenied
			}
		default:
			return ErrDenied
		}
	default:
		return ErrDenied
	}
	return nil
}

// EffectStore is implemented only by the trusted WS-02 composition root. Each
// method invokes Validate under its owner-scoped SQL locks and persists exactly
// the returned row plus the required immutable audit/outbox intent atomically.
// Nil means COMMIT succeeded, not that validation or a write merely succeeded.
// Issue also verifies the owned Project and absence of a conflicting backing.
// Consume serializes with session-pending changes; no network I/O occurs in SQL.
// The root's existing PrepareDurableEffect handoff remains non-authorizing.
type EffectStore interface {
	IssueEffect(context.Context, *EffectIssue) error
	ConsumeEffect(context.Context, *EffectConsume) error
	TransitionEffect(context.Context, *EffectTransition) error
}

type effectDecisionUse struct{ claimed atomic.Bool }

type EffectIssue struct {
	mu                sync.Mutex
	called, validated bool
	decision          *Decision
	record            EffectRecord
}

func (issue *EffectIssue) Expected() EffectRecord {
	if issue == nil {
		return EffectRecord{}
	}
	return issue.record
}
func (issue *EffectIssue) Validate(current State, now time.Time) (EffectRecord, error) {
	if issue == nil {
		return EffectRecord{}, ErrDenied
	}
	issue.mu.Lock()
	defer issue.mu.Unlock()
	if issue.called {
		return EffectRecord{}, ErrDenied
	}
	issue.called = true
	if current.SessionPending || issue.decision.ValidateFinal(current, now) != nil || issue.record.Validate() != nil || now.Before(issue.record.IssuedAt) ||
		!now.Before(issue.record.ExpiresAt) || !current.PolicyTimeHighWater.Before(issue.record.ExpiresAt) {
		return EffectRecord{}, ErrDenied
	}
	issue.validated = true
	return issue.record, nil
}

type EffectConsume struct {
	mu                sync.Mutex
	called, validated bool
	decision          *Decision
	record, next      EffectRecord
}

func (consume *EffectConsume) Expected() EffectRecord {
	if consume == nil {
		return EffectRecord{}
	}
	return consume.record
}
func (consume *EffectConsume) Validate(stored EffectRecord, current State, now time.Time) (EffectRecord, error) {
	if consume == nil {
		return EffectRecord{}, ErrDenied
	}
	consume.mu.Lock()
	defer consume.mu.Unlock()
	if consume.called {
		return EffectRecord{}, ErrDenied
	}
	consume.called = true
	if stored.State != EffectIssued || stored.Validate() != nil || !reflect.DeepEqual(stored, consume.record) ||
		current.SessionPending || consume.decision.ValidateFinal(current, now) != nil ||
		!now.Before(stored.ExpiresAt) || !current.PolicyTimeHighWater.Before(stored.ExpiresAt) {
		return EffectRecord{}, ErrDenied
	}
	if now.Before(current.PolicyTimeHighWater) {
		now = current.PolicyTimeHighWater
	}
	if now.Before(stored.UpdatedAt) || stored.Version == ^uint64(0) {
		return EffectRecord{}, ErrDenied
	}
	consume.next = stored
	consume.next.State, consume.next.Version, consume.next.UpdatedAt = EffectConsumed, stored.Version+1, now
	consume.validated = true
	return consume.next, nil
}

type EffectTransition struct {
	mu                sync.Mutex
	called, validated bool
	before, after     EffectRecord
}

func (transition *EffectTransition) Expected() EffectRecord {
	if transition == nil {
		return EffectRecord{}
	}
	return transition.before
}
func (transition *EffectTransition) Validate(stored EffectRecord) (EffectRecord, error) {
	if transition == nil {
		return EffectRecord{}, ErrDenied
	}
	transition.mu.Lock()
	defer transition.mu.Unlock()
	if transition.called {
		return EffectRecord{}, ErrDenied
	}
	transition.called = true
	if stored.Validate() != nil || transition.after.Validate() != nil || !reflect.DeepEqual(stored, transition.before) {
		return EffectRecord{}, ErrDenied
	}
	transition.validated = true
	return transition.after, nil
}

type Effects struct {
	store       EffectStore
	clock       func() time.Time
	process     EffectProcess
	readProcess func() (EffectProcess, error)
	mu          sync.Mutex
	executions  map[string]*EffectExecution
}

func NewEffects(store EffectStore, clock func() time.Time) (*Effects, error) {
	if store == nil || (reflect.ValueOf(store).Kind() == reflect.Pointer && reflect.ValueOf(store).IsNil()) || clock == nil {
		return nil, ErrDenied
	}
	process, err := newEffectProcess()
	if err != nil {
		return nil, ErrDenied
	}
	return &Effects{store: store, clock: clock, process: process, readProcess: readEffectProcess, executions: map[string]*EffectExecution{}}, nil
}
func (effects *Effects) currentProcess() bool {
	if effects == nil || effects.readProcess == nil || effects.clock == nil || effects.store == nil {
		return false
	}
	current, err := effects.readProcess()
	return err == nil && current.BootID == effects.process.BootID && current.PID == effects.process.PID && current.StartTicks == effects.process.StartTicks
}

// Copies retain the same one-use state; copying the public value cannot create
// a second consumption opportunity.
type IssuedEffect struct{ *issuedEffectState }
type issuedEffectState struct {
	effects  *Effects
	decision *Decision
	request  context.Context
	record   EffectRecord
	used     atomic.Bool
}

func (issued *IssuedEffect) Record() EffectRecord {
	if issued == nil || issued.issuedEffectState == nil {
		return EffectRecord{}
	}
	return issued.record
}

func (effects *Effects) Prepare(ctx context.Context, decision *Decision, binding EffectBinding) (*IssuedEffect, error) {
	if ctx == nil || ctx.Err() != nil || !effects.currentProcess() || decision == nil || !decision.valid || decision.effectUse == nil ||
		decision.evidence.Action != ProjectBackingProvision || decision.evidence.EvaluatorContractVersion != ProviderMutationEvaluatorContractVersion ||
		decision.evidence.DisclosureMode != "request_boundary" || binding.RequestID != telemetry.CorrelationID(ctx) || !binding.valid(decision.evidence) {
		return nil, ErrDenied
	}
	bound, ok := DecisionFromContext(ctx)
	deadline, hasDeadline := ctx.Deadline()
	if !ok || bound != decision || !hasDeadline || !deadline.Equal(binding.OriginalDeadline) {
		return nil, ErrDenied
	}
	binding.OriginalDeadline = binding.OriginalDeadline.UTC()
	binding.ProviderNotAfter = binding.ProviderNotAfter.UTC()
	now := effects.clock().UTC()
	if now.Before(decision.evidence.PolicyTimeHighWater) {
		now = decision.evidence.PolicyTimeHighWater
	}
	expires := now.Add(5 * time.Second)
	for _, limit := range []time.Time{decision.evidence.ExpiresAt, deadline, binding.ProviderNotAfter} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	record := EffectRecord{Binding: binding, Authorization: decision.evidence, Operation: CreateHiddenTracker, State: EffectIssued, Version: 1,
		Process: effects.process, IssuedAt: now, ExpiresAt: expires, UpdatedAt: now}
	if record.Validate() != nil || !decision.effectUse.claimed.CompareAndSwap(false, true) {
		return nil, ErrDenied
	}
	issue := &EffectIssue{decision: decision, record: record}
	err := effects.store.IssueEffect(ctx, issue)
	issue.mu.Lock()
	validated := issue.validated
	issue.mu.Unlock()
	if err != nil || !validated || ctx.Err() != nil || !effects.currentProcess() {
		return nil, ErrDenied
	}
	return &IssuedEffect{&issuedEffectState{effects: effects, decision: decision, request: ctx, record: record}}, nil
}

func (effects *Effects) Consume(ctx context.Context, issued *IssuedEffect) (*EffectExecution, error) {
	if ctx == nil || ctx.Err() != nil || issued == nil || issued.issuedEffectState == nil || issued.effects != effects || !effects.currentProcess() ||
		issued.request.Err() != nil || telemetry.CorrelationID(ctx) != issued.record.Binding.RequestID || !issued.used.CompareAndSwap(false, true) {
		return nil, ErrDenied
	}
	execution := newEffectExecution(effects, issued)
	effects.mu.Lock()
	if len(effects.executions) >= 128 || effects.executions[issued.record.Binding.EffectID] != nil {
		effects.mu.Unlock()
		execution.Suppress()
		return nil, ErrDenied
	}
	// Register before the consume transaction can win its race with revocation.
	effects.executions[issued.record.Binding.EffectID] = execution
	effects.mu.Unlock()
	consume := &EffectConsume{decision: issued.decision, record: issued.record}
	err := effects.store.ConsumeEffect(ctx, consume)
	consume.mu.Lock()
	validated, next := consume.validated, consume.next
	consume.mu.Unlock()
	if err != nil || !validated {
		execution.Suppress()
		// A failed/ambiguous commit never grants dispatch. The authoritative row
		// remains recovery-owned even if COMMIT's response was lost.
		effects.mu.Lock()
		delete(effects.executions, issued.record.Binding.EffectID)
		effects.mu.Unlock()
		return nil, ErrDenied
	}
	execution.mu.Lock()
	execution.record = next
	execution.committed = true
	execution.mu.Unlock()
	if ctx.Err() != nil || issued.request.Err() != nil || !effects.currentProcess() {
		execution.Suppress()
		return nil, ErrDenied
	}
	return execution, nil
}

// CancelSession signals registered old executions after the root durably marks
// that session pending. It is NOT a drain acknowledgment or terminal proof.
func (effects *Effects) CancelSession(sessionID string) {
	if effects == nil || !identity.ValidID(sessionID) {
		return
	}
	effects.mu.Lock()
	defer effects.mu.Unlock()
	for _, execution := range effects.executions {
		if execution.sessionID == sessionID {
			execution.Suppress()
		}
	}
}

func (effects *Effects) transition(ctx context.Context, before EffectRecord, state EffectState, outcome EffectTerminalOutcome, proof string) error {
	if effects == nil || effects.store == nil || effects.clock == nil || ctx == nil || ctx.Err() != nil || before.Validate() != nil || before.Version == ^uint64(0) {
		return ErrDenied
	}
	now := effects.clock().UTC()
	if now.Before(before.UpdatedAt) {
		return ErrDenied
	}
	allowed := (before.State == EffectIssued && state == EffectTerminal && outcome == EffectCanceledBeforeEffect && proof == "") ||
		(before.State == EffectConsumed && state == EffectReconciling && outcome == "" && proof == "")
	// Proof-backed terminalization is deliberately not an exported assertion.
	// The exact provider/transport verifier must own its future caller; a
	// successful callback, cancellation or snapshot can never reach this branch.
	if (before.State == EffectConsumed || before.State == EffectReconciling) && state == EffectTerminal && effectDigest(proof) {
		allowed = outcome == EffectCompletedBeforeBoundary || outcome == EffectSuppressedBeforeDisclosure || outcome == EffectRevokedOrFenced || outcome == EffectFailedWithoutEffect
	}
	if !allowed {
		return ErrDenied
	}
	after := before
	after.State, after.Version, after.UpdatedAt, after.TerminalOutcome, after.TerminalProofDigest = state, before.Version+1, now, outcome, proof
	transition := &EffectTransition{before: before, after: after}
	err := effects.store.TransitionEffect(ctx, transition)
	transition.mu.Lock()
	validated := transition.validated
	transition.mu.Unlock()
	if err != nil || !validated {
		return ErrDenied
	}
	effects.mu.Lock()
	if execution := effects.executions[before.Binding.EffectID]; execution != nil {
		execution.mu.Lock()
		if reflect.DeepEqual(execution.record, before) {
			execution.record = after
		}
		execution.mu.Unlock()
		if state == EffectTerminal {
			execution.Suppress()
			delete(effects.executions, before.Binding.EffectID)
		}
	}
	effects.mu.Unlock()
	return nil
}

// CancelIssued is safe only through exact issued-row CAS; it cannot cancel a
// consumed row or infer that an attempted provider call had no effect.
func (effects *Effects) CancelIssued(ctx context.Context, record EffectRecord) error {
	return effects.transition(ctx, record, EffectTerminal, EffectCanceledBeforeEffect, "")
}

// ReconcileLost preserves ambiguity after process loss; the supplied durable
// owner row is evidence for exact CAS, never permission to resume execution.
func (effects *Effects) ReconcileLost(ctx context.Context, record EffectRecord) error {
	return effects.transition(ctx, record, EffectReconciling, "", "")
}
