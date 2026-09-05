package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
)

// This fake verifies owner-port orchestration only. It is NOT PostgreSQL,
// durable outbox, provider enforcement, a signed successor activation, or a
// product-path proof. The real root/adapter consumers are separate requirements.
type effectUnitStore struct {
	mu                                        sync.Mutex
	state                                     State
	now                                       *time.Time
	record                                    EffectRecord
	issueCalls, consumeCalls, transitionCalls int
	skipValidation, failCommit                bool
	beforeConsume                             func()
}

func (store *effectUnitStore) IssueEffect(_ context.Context, issue *EffectIssue) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.issueCalls++
	if store.skipValidation {
		return nil
	}
	record, err := issue.Validate(store.state, *store.now)
	if err != nil {
		return err
	}
	if store.failCommit {
		return errors.New("unit commit failure")
	}
	store.record = record
	return nil
}
func (store *effectUnitStore) ConsumeEffect(_ context.Context, consume *EffectConsume) error {
	if store.beforeConsume != nil {
		store.beforeConsume()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.consumeCalls++
	if store.skipValidation {
		return nil
	}
	record, err := consume.Validate(store.record, store.state, *store.now)
	if err != nil {
		return err
	}
	if store.failCommit {
		return errors.New("unit commit failure")
	}
	store.record = record
	return nil
}
func (store *effectUnitStore) TransitionEffect(_ context.Context, transition *EffectTransition) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.transitionCalls++
	if store.skipValidation {
		return nil
	}
	record, err := transition.Validate(store.record)
	if err != nil {
		return err
	}
	if store.failCommit {
		return errors.New("unit commit failure")
	}
	store.record = record
	return nil
}
func (store *effectUnitStore) snapshot() EffectRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.record
}

type effectUnitFixture struct {
	effects  *Effects
	store    *effectUnitStore
	decision *Decision
	ctx      context.Context
	cancel   context.CancelFunc
	binding  EffectBinding
	now      *time.Time
}

func newEffectUnitFixture(t *testing.T) effectUnitFixture {
	t.Helper()
	coordinator, repo, _, now := coordinatorFixture(t, true)
	// Explicit unit-only construction: the production activation verifier still
	// rejects this successor ABI. No existing metadata template is upgraded.
	*now = time.Now().UTC()
	coordinator.config.Activation.binding.EvaluatorContractVersion = ProviderMutationEvaluatorContractVersion
	coordinator.config.Activation.issuedAt, coordinator.config.Activation.expiresAt = now.Add(-time.Minute), now.Add(time.Hour)
	b := coordinator.config.Activation.binding
	repo.state.ActivationDigest = b.Digest()
	repo.state.Resource = ResourceRef{"project", "019ec4e0-0000-7000-8000-000000000005"}
	repo.state.PolicyTimeHighWater, repo.state.ContextExpiresAt = *now, now.Add(time.Hour)
	repo.session.IssuedAt, repo.session.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
	coordinator.config.Anchor.(*testAnchor).state = AnchorState{Binding: b, PolicyTimeHighWater: *now, PolicyTimeRevision: 1}
	session := refreshedGuardSession(t, repo, now)
	ctx := telemetry.WithCorrelationID(context.Background(), strings.Repeat("a", 32))
	ctx, cancel := context.WithDeadline(ctx, now.Add(5*time.Second))
	t.Cleanup(cancel)
	decision, err := coordinator.Authorize(ctx, session, ProjectBackingProvision, repo.state.Resource)
	if err != nil {
		t.Fatal(err)
	}
	ctx = decision.WithContext(ctx)
	store := &effectUnitStore{state: repo.state, now: now}
	effects, err := NewEffects(store, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	binding := EffectBinding{EffectID: "019ec4e0-0000-7000-8000-000000000006", OperationID: "019ec4e0-0000-7000-8000-000000000007",
		PlanID: "019ec4e0-0000-7000-8000-000000000008", RequestID: telemetry.CorrelationID(ctx), Project: repo.state.Resource,
		ProviderInstallationID: "019ec4e0-0000-7000-8000-000000000009", CompatibilityProfileID: "unit-only-not-activated",
		CompatibilityProfileDigest: "sha256:" + strings.Repeat("b", 64), PlanDigest: "sha256:" + strings.Repeat("c", 64), ProviderRevision: 1,
		OriginalDeadline: deadline, ProviderNotAfter: now.Add(4 * time.Second)}
	return effectUnitFixture{effects, store, decision, ctx, cancel, binding, now}
}
func (fixture effectUnitFixture) issued(t *testing.T) *IssuedEffect {
	t.Helper()
	issued, err := fixture.effects.Prepare(fixture.ctx, fixture.decision, fixture.binding)
	if err != nil {
		t.Fatal(err)
	}
	return issued
}
func (fixture effectUnitFixture) execution(t *testing.T) *EffectExecution {
	t.Helper()
	execution, err := fixture.effects.Consume(fixture.ctx, fixture.issued(t))
	if err != nil {
		t.Fatal(err)
	}
	return execution
}

func TestProviderEffectUnitSealedIssueConsumeAndSingleDispatch(t *testing.T) {
	f := newEffectUnitFixture(t)
	issued := f.issued(t)
	if f.store.snapshot().State != EffectIssued || !issued.Record().ExpiresAt.Equal(f.decision.Evidence().ExpiresAt) {
		t.Fatal("missing bounded issue")
	}
	// Persistence round-trip must not depend on time.Location or monotonic
	// process-local Time internals surviving JSON storage.
	raw, _ := json.Marshal(f.store.record)
	if err := json.Unmarshal(raw, &f.store.record); err != nil {
		t.Fatal(err)
	}
	execution, err := f.effects.Consume(f.ctx, issued)
	if err != nil {
		t.Fatal(err)
	}
	if f.store.snapshot().State != EffectConsumed || f.store.consumeCalls != 1 {
		t.Fatal("consume not recorded")
	}
	if _, err := f.effects.Consume(f.ctx, issued); err != ErrDenied {
		t.Fatal("issued token reused")
	}
	issuedCopy := *issued
	if _, err := f.effects.Consume(f.ctx, &issuedCopy); err != ErrDenied {
		t.Fatal("copied issued token reused")
	}
	executionCopy := *execution
	var calls atomic.Int32
	var winners atomic.Int32
	var group sync.WaitGroup
	for i := range 16 {
		group.Add(1)
		handle := execution
		if i%2 == 0 {
			handle = &executionCopy
		}
		go func() {
			defer group.Done()
			if handle.Run(f.binding, func(context.Context) error { calls.Add(1); return nil }) == nil {
				winners.Add(1)
			}
		}()
	}
	group.Wait()
	if calls.Load() != 1 || winners.Load() != 1 || f.store.snapshot().State != EffectConsumed || f.store.transitionCalls != 0 {
		t.Fatal("callback reuse or callback result falsely terminalized")
	}
}

func TestProviderEffectUnitOldActivationAndReadDecisionDenied(t *testing.T) {
	coordinator, repo, session, _ := coordinatorFixture(t, true)
	repo.state.Resource.Kind = "project"
	if d, err := coordinator.Authorize(context.Background(), session, ProjectBackingProvision, repo.state.Resource); err != ErrDenied || d != nil || repo.reads != 0 {
		t.Fatal("metadata ABI admitted provider action")
	}
	f := newEffectUnitFixture(t)
	for _, mutate := range []func(*Decision){func(d *Decision) { d.evidence.Action = ProjectRead }, func(d *Decision) { d.evidence.EvaluatorContractVersion = EvaluatorContractVersion }, func(d *Decision) { d.effectUse = nil }, func(d *Decision) { d.valid = false }} {
		d := *f.decision
		mutate(&d)
		if issued, err := f.effects.Prepare(d.WithContext(f.ctx), &d, f.binding); err != ErrDenied || issued != nil {
			t.Fatal("non-authority minted effect")
		}
	}
	if f.store.issueCalls != 0 {
		t.Fatal("invalid authority reached storage")
	}
}

func TestProviderEffectUnitBindingsAndEarliestExpiry(t *testing.T) {
	for name, mutate := range map[string]func(*EffectBinding){
		"effect-id": func(b *EffectBinding) { b.EffectID = "invalid" }, "operation-id": func(b *EffectBinding) { b.OperationID = "" },
		"plan-id": func(b *EffectBinding) { b.PlanID = "" }, "request": func(b *EffectBinding) { b.RequestID = strings.Repeat("d", 32) },
		"project": func(b *EffectBinding) { b.Project.ID = orgID }, "provider": func(b *EffectBinding) { b.ProviderInstallationID = "" },
		"profile": func(b *EffectBinding) { b.CompatibilityProfileID = "foreign/path" }, "profile-digest": func(b *EffectBinding) { b.CompatibilityProfileDigest = "bad" },
		"plan-digest": func(b *EffectBinding) { b.PlanDigest = "bad" }, "revision": func(b *EffectBinding) { b.ProviderRevision++ },
		"deadline": func(b *EffectBinding) { b.OriginalDeadline = b.OriginalDeadline.Add(time.Second) }, "expired-provider": func(b *EffectBinding) { b.ProviderNotAfter = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newEffectUnitFixture(t)
			mutate(&f.binding)
			if p, e := f.effects.Prepare(f.ctx, f.decision, f.binding); e != ErrDenied || p != nil || f.store.issueCalls != 0 {
				t.Fatal("bad binding reached issue")
			}
		})
	}
	f := newEffectUnitFixture(t)
	f.binding.ProviderNotAfter = f.now.Add(time.Second)
	issued := f.issued(t)
	if !issued.Record().ExpiresAt.Equal(f.binding.ProviderNotAfter) {
		t.Fatal("provider expiry extended")
	}
	if p, e := f.effects.Prepare(f.ctx, f.decision, f.binding); e != ErrDenied || p != nil {
		t.Fatal("decision reused for new issue")
	}
}

func TestProviderEffectUnitStoreAndFenceFailuresNeverGrant(t *testing.T) {
	for _, stage := range []string{"issue", "consume"} {
		for _, failure := range []string{"pending", "changed-revision", "expired", "skip-validation", "commit"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				f := newEffectUnitFixture(t)
				var issued *IssuedEffect
				if stage == "consume" {
					issued = f.issued(t)
				}
				switch failure {
				case "pending":
					f.store.state.SessionPending = true
				case "changed-revision":
					f.store.state.Revisions.Provider++
				case "expired":
					*f.now = f.now.Add(3 * time.Second)
				case "skip-validation":
					f.store.skipValidation = true
				case "commit":
					f.store.failCommit = true
				}
				if stage == "issue" {
					if p, e := f.effects.Prepare(f.ctx, f.decision, f.binding); e != ErrDenied || p != nil {
						t.Fatal("issue failure granted token")
					}
				} else {
					if h, e := f.effects.Consume(f.ctx, issued); e != ErrDenied || h != nil {
						t.Fatal("consume failure granted execution")
					}
				}
				if f.store.snapshot().State == EffectConsumed || f.store.snapshot().State == EffectTerminal {
					t.Fatal("failed store transitioned")
				}
			})
		}
	}
}

func TestProviderEffectUnitRecordCASAndOneUseValidation(t *testing.T) {
	f := newEffectUnitFixture(t)
	issued := f.issued(t)
	for _, mutate := range []func(*EffectRecord){func(r *EffectRecord) { r.Binding.PlanDigest = "sha256:" + strings.Repeat("d", 64) }, func(r *EffectRecord) { r.Authorization.SessionID = orgID }, func(r *EffectRecord) { r.Version++ }, func(r *EffectRecord) { r.Process.Nonce = strings.Repeat("e", 32) }, func(r *EffectRecord) { r.State = EffectConsumed }} {
		stored := issued.Record()
		mutate(&stored)
		consume := &EffectConsume{decision: f.decision, record: issued.Record()}
		if _, err := consume.Validate(stored, f.store.state, *f.now); err != ErrDenied {
			t.Fatal("mismatched persisted record consumed")
		}
		if _, err := consume.Validate(issued.Record(), f.store.state, *f.now); err != ErrDenied {
			t.Fatal("failed invocation reused")
		}
	}
	consume := &EffectConsume{decision: f.decision, record: issued.Record()}
	if _, e := consume.Validate(issued.Record(), f.store.state, *f.now); e != nil {
		t.Fatal(e)
	}
	if _, e := consume.Validate(issued.Record(), f.store.state, *f.now); e != ErrDenied {
		t.Fatal("successful invocation reused")
	}
}

func TestProviderEffectUnitCancellationAndAmbiguityNeverTerminal(t *testing.T) {
	for _, failure := range []string{"timeout", "panic", "cancel-session", "cancel-request", "process-loss"} {
		t.Run(failure, func(t *testing.T) {
			f := newEffectUnitFixture(t)
			execution := f.execution(t)
			err := execution.Run(f.binding, func(ctx context.Context) error {
				switch failure {
				case "timeout":
					return context.DeadlineExceeded
				case "panic":
					panic("unit private diagnostic")
				case "cancel-session":
					f.effects.CancelSession(sessionID)
				case "cancel-request":
					f.cancel()
				case "process-loss":
					f.effects.readProcess = func() (EffectProcess, error) { return EffectProcess{}, ErrDenied }
				}
				return nil
			})
			if err != ErrDenied || f.store.snapshot().State != EffectReconciling || !execution.SuppressionRequired() {
				t.Fatal("uncertain execution was not suppressed/reconciliation owned")
			}
			if f.effects.CancelIssued(context.Background(), f.store.snapshot()) != ErrDenied {
				t.Fatal("consumed effect canceled as unconsumed")
			}
		})
	}
}

func TestProviderEffectUnitCancellationRegistrationPrecedesConsume(t *testing.T) {
	f := newEffectUnitFixture(t)
	issued := f.issued(t)
	f.store.beforeConsume = func() { f.effects.CancelSession(sessionID) }
	execution, err := f.effects.Consume(f.ctx, issued)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if execution.Run(f.binding, func(context.Context) error { calls++; return nil }) != ErrDenied || calls != 0 || !execution.SuppressionRequired() {
		t.Fatal("revocation missed precommit handle")
	}
	if f.store.snapshot().State != EffectConsumed {
		t.Fatal("suppression signal became false terminal proof")
	}
}

func TestProviderEffectUnitClosedTransitionsAndNoResume(t *testing.T) {
	f := newEffectUnitFixture(t)
	issued := f.issued(t)
	if err := f.effects.CancelIssued(context.Background(), issued.Record()); err != nil {
		t.Fatal(err)
	}
	if r := f.store.snapshot(); r.State != EffectTerminal || r.TerminalOutcome != EffectCanceledBeforeEffect {
		t.Fatal("issued cancellation missing")
	}
	if _, e := f.effects.Consume(f.ctx, issued); e != ErrDenied {
		t.Fatal("canceled permit consumed")
	}
	if e := f.effects.ReconcileLost(context.Background(), f.store.snapshot()); e != ErrDenied {
		t.Fatal("terminal state resumed")
	}
	g := newEffectUnitFixture(t)
	execution := g.execution(t)
	if err := g.effects.ReconcileLost(context.Background(), execution.Record()); err != nil {
		t.Fatal(err)
	}
	if g.store.snapshot().State != EffectReconciling {
		t.Fatal("process loss not owned")
	}
	if execution.Run(g.binding, func(context.Context) error { t.Fatal("reconciling handle dispatched"); return nil }) != ErrDenied {
		t.Fatal("reconciling handle resumed")
	}
	if e := g.effects.transition(context.Background(), g.store.snapshot(), EffectTerminal, EffectCompletedBeforeBoundary, ""); e != ErrDenied {
		t.Fatal("missing proof accepted")
	}
	if e := g.effects.transition(context.Background(), g.store.snapshot(), EffectConsumed, "", ""); e != ErrDenied {
		t.Fatal("reconciliation resumed mutation")
	}
	// Package-private unit state-machine fixture only: digest shape is not a
	// verified provider receipt. No production caller can assert this outcome.
	if e := g.effects.transition(context.Background(), g.store.snapshot(), EffectTerminal, EffectCompletedBeforeBoundary, "sha256:"+strings.Repeat("f", 64)); e != nil {
		t.Fatal(e)
	}
	if g.store.snapshot().TerminalOutcome != EffectCompletedBeforeBoundary {
		t.Fatal("terminal state lost")
	}
}

func TestProviderEffectUnitSessionPendingAlsoDeniesOrdinaryDecision(t *testing.T) {
	coordinator, repo, session, now := coordinatorFixture(t, true)
	decision, err := coordinator.Authorize(context.Background(), session, OrganizationRead, repo.state.Resource)
	if err != nil {
		t.Fatal(err)
	}
	repo.state.SessionPending = true
	if decision.ValidateFinal(repo.state, *now) != ErrDenied {
		t.Fatal("pending session passed final fence")
	}
	if next, e := coordinator.Authorize(context.Background(), session, OrganizationRead, repo.state.Resource); e != ErrDenied || next != nil {
		t.Fatal("pending session obtained new decision")
	}
}

func TestProviderEffectUnitUnknownShapesAndZeroHandlesDeny(t *testing.T) {
	f := newEffectUnitFixture(t)
	record := f.issued(t).Record()
	for _, mutate := range []func(*EffectRecord){func(r *EffectRecord) { r.State = "unknown" }, func(r *EffectRecord) { r.Operation = "snapshot_read" }, func(r *EffectRecord) { r.TerminalOutcome = EffectCompletedBeforeBoundary }, func(r *EffectRecord) { r.State = EffectTerminal }, func(r *EffectRecord) { r.Process.Nonce = "" }, func(r *EffectRecord) { r.ExpiresAt = r.ExpiresAt.Add(time.Hour) }} {
		r := record
		mutate(&r)
		if r.Validate() != ErrDenied {
			t.Fatal("unknown unsafe record accepted")
		}
	}
	var zero *EffectExecution
	if zero.Run(f.binding, func(context.Context) error { return nil }) != ErrDenied || !zero.SuppressionRequired() {
		t.Fatal("zero execution allowed")
	}
	if (&Effects{}).currentProcess() {
		t.Fatal("zero process allowed")
	}
	if !reflect.DeepEqual(record, f.store.snapshot()) {
		t.Fatal("validation mutated durable evidence")
	}
}
