package transaction

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

type fakeFinalizer struct {
	backend     *fakeBackend
	intent      *outbox.ValidatedIntent
	rows        int
	calls       int
	fail        bool
	panic       bool
	zero        bool
	zeroBinding bool
	version     string
	opaque      []byte
}

func (finalizer *fakeFinalizer) Finalize(_ context.Context, binding SessionBinding, issuer BoundRevisionIssuer) (FinalAuthorizationAuditResult, error) {
	finalizer.calls++
	if finalizer.panic {
		panic("injected finalization panic")
	}
	if finalizer.fail {
		return FinalAuthorizationAuditResult{}, errInjected
	}
	receipt, err := finalizer.backend.stage(binding, FinalAuthorizationOwner, "final_authorization_audit")
	if err != nil {
		return FinalAuthorizationAuditResult{}, err
	}
	if finalizer.zeroBinding {
		receipt = BindingReceipt{}
	}
	if finalizer.zero {
		return FinalAuthorizationAuditResult{Intent: finalizer.intent, Binding: receipt}, nil
	}
	version := finalizer.version
	if version == "" {
		version = BoundRevisionHandoffV1
	}
	opaque := finalizer.opaque
	if opaque == nil {
		opaque = []byte("opaque-bound-revision")
	}
	revision, err := issuer.BindValidated(version, opaque)
	if err != nil {
		return FinalAuthorizationAuditResult{}, err
	}
	return FinalAuthorizationAuditResult{Revision: revision, Intent: finalizer.intent, Binding: receipt}, nil
}

func minimalRegistry(t testing.TB, backend *fakeBackend) Registry {
	t.Helper()
	template, _ := registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestFinalLogicalAuthorizationAuditCommitsBeforeReceiptEscapes(t *testing.T) {
	backend := &fakeBackend{}
	intent := testIntent()
	finalizer := &fakeFinalizer{backend: backend, intent: &intent, rows: 1000}
	appender := &fakeAppender{backend: backend}
	coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), appender, finalizer, nil)
	revision, report, err := coordinator.FinalizeRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !revision.verify() || finalizer.calls != 1 || appender.callCount() != 1 {
		t.Fatalf("finalization counts = final:%d append:%d revision-valid:%t", finalizer.calls, appender.callCount(), revision.verify())
	}
	calls, committed, _, _, _, _ := backend.snapshot()
	wantCalls := []string{"begin", "final_authorization_audit", "outbox", "commit"}
	wantCommitted := []string{"final_authorization_audit", "outbox"}
	if !reflect.DeepEqual(calls, wantCalls) || !reflect.DeepEqual(committed, wantCommitted) {
		t.Fatalf("finalization order drifted: calls=%v committed=%v", calls, committed)
	}
	wantReport := Report{BeginCalls: 1, ParticipantCalls: 1, DeclaredWriteParticipantCalls: 1, OutboxParticipantCalls: 1, OutboxAppendCalls: 1, CommitCalls: 1, LogicalAuthorizationAudits: 1}
	if report != wantReport {
		t.Fatalf("report = %#v, want %#v", report, wantReport)
	}
}

func TestFinalLogicalOperationCountsDoNotGrowWithReturnedRows(t *testing.T) {
	var baseline Report
	for index, rows := range []int{0, 1, 1000, 1_000_000} {
		backend := &fakeBackend{}
		finalizer := &fakeFinalizer{backend: backend, rows: rows}
		appender := &fakeAppender{backend: backend}
		coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), appender, finalizer, nil)
		_, report, err := coordinator.FinalizeRead(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if finalizer.calls != 1 || report.LogicalAuthorizationAudits != 1 || report.OutboxParticipantCalls != 1 || report.OutboxAppendCalls != 0 || report.OpenFGACalls != 0 || report.ProviderCalls != 0 || report.NATSWaits != 0 {
			t.Fatalf("rows=%d report=%#v calls=%d", rows, report, finalizer.calls)
		}
		if index == 0 {
			baseline = report
		} else if report != baseline {
			t.Fatalf("row count changed seam counters: rows=%d report=%#v baseline=%#v", rows, report, baseline)
		}
	}
}

func TestFinalizationFailuresReturnNoRevisionAndRollback(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeFinalizer, *fakeAppender, *fakeBackend)
		wantCode  ErrorCode
	}{
		{"owner error", func(finalizer *fakeFinalizer, _ *fakeAppender, _ *fakeBackend) { finalizer.fail = true }, CodeParticipantFailed},
		{"owner panic", func(finalizer *fakeFinalizer, _ *fakeAppender, _ *fakeBackend) { finalizer.panic = true }, CodeParticipantFailed},
		{"zero revision", func(finalizer *fakeFinalizer, _ *fakeAppender, _ *fakeBackend) { finalizer.zero = true }, CodeParticipantFailed},
		{"missing binding receipt", func(finalizer *fakeFinalizer, _ *fakeAppender, _ *fakeBackend) { finalizer.zeroBinding = true }, CodeParticipantFailed},
		{"wrong revision version", func(finalizer *fakeFinalizer, _ *fakeAppender, _ *fakeBackend) {
			finalizer.version = BoundRevisionHandoffV1 + ".unknown"
		}, CodeParticipantFailed},
		{"empty revision", func(finalizer *fakeFinalizer, _ *fakeAppender, _ *fakeBackend) { finalizer.opaque = []byte{} }, CodeParticipantFailed},
		{"outbox error", func(finalizer *fakeFinalizer, appender *fakeAppender, _ *fakeBackend) {
			intent := testIntent()
			finalizer.intent = &intent
			appender.fail = true
		}, CodeOutboxFailed},
		{"commit error", func(_ *fakeFinalizer, _ *fakeAppender, backend *fakeBackend) { backend.failCommit = true }, CodeCommitFailed},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{}
			finalizer := &fakeFinalizer{backend: backend}
			appender := &fakeAppender{backend: backend}
			testCase.configure(finalizer, appender, backend)
			coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), appender, finalizer, nil)
			revision, _, err := coordinator.FinalizeRead(context.Background())
			if ErrorCodeOf(err) != testCase.wantCode || revision.verify() {
				t.Fatalf("error=%v code=%s revision-valid=%t", err, ErrorCodeOf(err), revision.verify())
			}
			_, committed, beginCalls, _, rollbackCalls, _ := backend.snapshot()
			if beginCalls != 1 || rollbackCalls != 1 || len(committed) != 0 {
				t.Fatalf("begin=%d rollback=%d committed=%v", beginCalls, rollbackCalls, committed)
			}
		})
	}
	backend := &fakeBackend{}
	var typedNil *fakeFinalizer
	coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), &fakeAppender{backend: backend}, typedNil, nil)
	if revision, _, err := coordinator.FinalizeRead(context.Background()); ErrorCodeOf(err) != CodeBoundaryDenied || revision.verify() {
		t.Fatalf("typed-nil finalizer result = %#v, %v", revision, err)
	}
	_, _, beginCalls, _, _, _ := backend.snapshot()
	if beginCalls != 0 {
		t.Fatal("typed-nil finalizer reached Begin")
	}
}

type recheckBehavior string

const (
	recheckConfirm recheckBehavior = "confirm"
	recheckError   recheckBehavior = "error"
	recheckZero    recheckBehavior = "zero"
	recheckPanic   recheckBehavior = "panic"
	recheckForeign recheckBehavior = "foreign"
)

type fakeRechecker struct {
	behavior recheckBehavior
	allowed  atomic.Bool
	calls    atomic.Int64
	events   *[]string
	eventMu  *sync.Mutex
	signal   chan struct{}
	proceed  chan struct{}
}

func (rechecker *fakeRechecker) Recheck(_ context.Context, revision BoundRevision, issuer RecheckIssuer) (RecheckReceipt, error) {
	rechecker.calls.Add(1)
	if rechecker.events != nil {
		rechecker.eventMu.Lock()
		*rechecker.events = append(*rechecker.events, "recheck")
		rechecker.eventMu.Unlock()
	}
	if rechecker.signal != nil {
		close(rechecker.signal)
	}
	if rechecker.proceed != nil {
		<-rechecker.proceed
	}
	switch rechecker.behavior {
	case recheckPanic:
		panic("injected recheck panic")
	case recheckError:
		return RecheckReceipt{}, errInjected
	case recheckZero:
		return RecheckReceipt{}, nil
	case recheckForeign:
		foreign := newRecheckIssuer(revision)
		receipt, err := foreign.Confirm(revision)
		foreign.close()
		return receipt, err
	default:
		if !rechecker.allowed.Load() {
			return RecheckReceipt{}, errInjected
		}
		return issuer.Confirm(revision)
	}
}

type fakeBufferedResponse struct {
	mu         sync.Mutex
	released   int
	suppressed int
	fail       bool
	panic      bool
	events     *[]string
	eventMu    *sync.Mutex
	signal     chan struct{}
	proceed    chan struct{}
}

func (response *fakeBufferedResponse) Release(context.Context) error {
	response.mu.Lock()
	response.released++
	response.mu.Unlock()
	if response.events != nil {
		response.eventMu.Lock()
		*response.events = append(*response.events, "release")
		response.eventMu.Unlock()
	}
	if response.signal != nil {
		close(response.signal)
	}
	if response.proceed != nil {
		<-response.proceed
	}
	if response.panic {
		panic("injected release panic")
	}
	if response.fail {
		return errInjected
	}
	return nil
}

func (response *fakeBufferedResponse) Suppress() {
	response.mu.Lock()
	response.suppressed++
	response.mu.Unlock()
}

func (response *fakeBufferedResponse) counts() (released, suppressed int) {
	response.mu.Lock()
	defer response.mu.Unlock()
	return response.released, response.suppressed
}

func testBoundRevision(t testing.TB) BoundRevision {
	t.Helper()
	issuer := newBoundRevisionIssuer()
	revision, err := issuer.BindValidated(BoundRevisionHandoffV1, []byte("opaque-bound-revision"))
	issuer.close()
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestRequestBoundaryRechecksImmediatelyBeforeFirstRelease(t *testing.T) {
	events := []string{}
	eventMu := &sync.Mutex{}
	rechecker := &fakeRechecker{behavior: recheckConfirm, events: &events, eventMu: eventMu}
	rechecker.allowed.Store(true)
	adapter, err := NewRequestBoundaryAdapter(rechecker)
	if err != nil {
		t.Fatal(err)
	}
	response := &fakeBufferedResponse{events: &events, eventMu: eventMu}
	report, err := adapter.ReleaseProtected(context.Background(), testBoundRevision(t), response)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"recheck", "release"}) {
		t.Fatalf("boundary order = %v", events)
	}
	released, suppressed := response.counts()
	if released != 1 || suppressed != 0 || report != (BoundaryReport{RecheckCalls: 1, ReleaseCalls: 1}) {
		t.Fatalf("response=%d/%d report=%#v", released, suppressed, report)
	}
}

func TestEveryMissingStaleMalformedOrUnverifiableRecheckSuppresses(t *testing.T) {
	tests := []struct {
		name     string
		behavior recheckBehavior
		mutate   func(BoundRevision)
		cancel   bool
	}{
		{"changed", recheckError, nil, false},
		{"pending", recheckError, nil, false},
		{"missing", recheckZero, nil, false},
		{"malformed", recheckForeign, nil, false},
		{"stale", recheckError, nil, false},
		{"unverifiable", recheckPanic, nil, false},
		{"cancelled", recheckConfirm, nil, true},
		{"modified opaque", recheckConfirm, func(revision BoundRevision) { revision.state.opaque[0] ^= 0xff }, false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			rechecker := &fakeRechecker{behavior: testCase.behavior}
			rechecker.allowed.Store(true)
			adapter, err := NewRequestBoundaryAdapter(rechecker)
			if err != nil {
				t.Fatal(err)
			}
			revision := testBoundRevision(t)
			if testCase.mutate != nil {
				testCase.mutate(revision)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if testCase.cancel {
				cancel()
			} else {
				defer cancel()
			}
			response := &fakeBufferedResponse{}
			report, err := adapter.ReleaseProtected(ctx, revision, response)
			if ErrorCodeOf(err) != CodeBoundaryDenied {
				t.Fatalf("error=%v report=%#v", err, report)
			}
			released, suppressed := response.counts()
			if released != 0 || suppressed != 1 || report.Retries != 0 {
				t.Fatalf("response=%d/%d report=%#v", released, suppressed, report)
			}
		})
	}
}

func TestRequestBoundaryReceiptIsSingleUseUnderConcurrency(t *testing.T) {
	rechecker := &fakeRechecker{behavior: recheckConfirm}
	rechecker.allowed.Store(true)
	adapter, err := NewRequestBoundaryAdapter(rechecker)
	if err != nil {
		t.Fatal(err)
	}
	revision := testBoundRevision(t)
	responses := []*fakeBufferedResponse{{}, {}}
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for _, response := range responses {
		response := response
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := adapter.ReleaseProtected(context.Background(), revision, response)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	successes, denials := 0, 0
	for err := range errorsSeen {
		if err == nil {
			successes++
		} else if ErrorCodeOf(err) == CodeBoundaryDenied {
			denials++
		}
	}
	totalReleased, totalSuppressed := 0, 0
	for _, response := range responses {
		released, suppressed := response.counts()
		totalReleased += released
		totalSuppressed += suppressed
	}
	if successes != 1 || denials != 1 || rechecker.calls.Load() != 1 || totalReleased != 1 || totalSuppressed != 1 || revision.state.boundary.Load() != boundaryReleased {
		t.Fatalf("success=%d denial=%d rechecks=%d released=%d suppressed=%d state=%d", successes, denials, rechecker.calls.Load(), totalReleased, totalSuppressed, revision.state.boundary.Load())
	}
}

func TestConcurrentLoserCannotPoisonClaimedRevision(t *testing.T) {
	recheckStarted := make(chan struct{})
	finishRecheck := make(chan struct{})
	rechecker := &fakeRechecker{
		behavior: recheckConfirm,
		signal:   recheckStarted,
		proceed:  finishRecheck,
	}
	rechecker.allowed.Store(true)
	adapter, err := NewRequestBoundaryAdapter(rechecker)
	if err != nil {
		t.Fatal(err)
	}
	revision := testBoundRevision(t)
	winnerResponse := &fakeBufferedResponse{}
	winnerResult := make(chan error, 1)
	go func() {
		_, err := adapter.ReleaseProtected(context.Background(), revision, winnerResponse)
		winnerResult <- err
	}()
	<-recheckStarted

	loserResponse := &fakeBufferedResponse{}
	if _, err := adapter.ReleaseProtected(context.Background(), revision, loserResponse); ErrorCodeOf(err) != CodeBoundaryDenied {
		t.Fatalf("concurrent loser error = %v", err)
	}
	if revision.state.boundary.Load() != boundaryChecking {
		t.Fatalf("concurrent loser poisoned claimed revision: state=%d", revision.state.boundary.Load())
	}
	close(finishRecheck)
	if err := <-winnerResult; err != nil {
		t.Fatalf("claimed boundary failed after concurrent denial: %v", err)
	}
	winnerReleased, winnerSuppressed := winnerResponse.counts()
	loserReleased, loserSuppressed := loserResponse.counts()
	if winnerReleased != 1 || winnerSuppressed != 0 || loserReleased != 0 || loserSuppressed != 1 ||
		rechecker.calls.Load() != 1 || revision.state.boundary.Load() != boundaryReleased {
		t.Fatalf("winner=%d/%d loser=%d/%d rechecks=%d state=%d", winnerReleased, winnerSuppressed,
			loserReleased, loserSuppressed, rechecker.calls.Load(), revision.state.boundary.Load())
	}
}

func TestRequestBoundaryRaceOrdering(t *testing.T) {
	t.Run("mutation first suppresses", func(t *testing.T) {
		rechecker := &fakeRechecker{behavior: recheckConfirm}
		rechecker.allowed.Store(false)
		adapter, _ := NewRequestBoundaryAdapter(rechecker)
		response := &fakeBufferedResponse{}
		if _, err := adapter.ReleaseProtected(context.Background(), testBoundRevision(t), response); ErrorCodeOf(err) != CodeBoundaryDenied {
			t.Fatalf("error=%v", err)
		}
		released, _ := response.counts()
		if released != 0 {
			t.Fatal("mutation-first response released")
		}
	})

	t.Run("boundary first finite release may finish", func(t *testing.T) {
		rechecker := &fakeRechecker{behavior: recheckConfirm}
		rechecker.allowed.Store(true)
		adapter, _ := NewRequestBoundaryAdapter(rechecker)
		releaseStarted := make(chan struct{})
		finishRelease := make(chan struct{})
		response := &fakeBufferedResponse{signal: releaseStarted, proceed: finishRelease}
		result := make(chan error, 1)
		go func() {
			_, err := adapter.ReleaseProtected(context.Background(), testBoundRevision(t), response)
			result <- err
		}()
		<-releaseStarted
		rechecker.allowed.Store(false)
		close(finishRelease)
		if err := <-result; err != nil {
			t.Fatalf("boundary-first finite response failed: %v", err)
		}
		if rechecker.calls.Load() != 1 {
			t.Fatal("finite response rechecked per byte or after boundary")
		}
	})
}

func TestReleaseFailureAndPanicDoNotRetry(t *testing.T) {
	for _, panicRelease := range []bool{false, true} {
		name := map[bool]string{false: "error", true: "panic"}[panicRelease]
		t.Run(name, func(t *testing.T) {
			rechecker := &fakeRechecker{behavior: recheckConfirm}
			rechecker.allowed.Store(true)
			adapter, _ := NewRequestBoundaryAdapter(rechecker)
			response := &fakeBufferedResponse{fail: !panicRelease, panic: panicRelease}
			report, err := adapter.ReleaseProtected(context.Background(), testBoundRevision(t), response)
			if ErrorCodeOf(err) != CodeBoundaryDenied || report.ReleaseCalls != 1 || report.Retries != 0 || rechecker.calls.Load() != 1 {
				t.Fatalf("error=%v report=%#v rechecks=%d", err, report, rechecker.calls.Load())
			}
			released, suppressed := response.counts()
			if released != 1 || suppressed != 1 {
				t.Fatalf("release=%d suppress=%d", released, suppressed)
			}
		})
	}
}

func TestRequestBoundaryRejectsNilRecheckerAndResponse(t *testing.T) {
	var typedNil *fakeRechecker
	if _, err := NewRequestBoundaryAdapter(typedNil); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("typed-nil rechecker error=%v", err)
	}
	rechecker := &fakeRechecker{behavior: recheckConfirm}
	rechecker.allowed.Store(true)
	adapter, _ := NewRequestBoundaryAdapter(rechecker)
	var response *fakeBufferedResponse
	if _, err := adapter.ReleaseProtected(context.Background(), testBoundRevision(t), response); ErrorCodeOf(err) != CodeBoundaryDenied {
		t.Fatalf("typed-nil response error=%v", err)
	}
	if rechecker.calls.Load() != 0 {
		t.Fatal("nil response still reached recheck")
	}
}

func TestBoundRevisionCopiesAreDefensiveAndZeroDenies(t *testing.T) {
	revision := testBoundRevision(t)
	digest := revision.Digest()
	copy := revision.OpaqueCopy()
	copy[0] ^= 0xff
	if revision.Digest() != digest || !revision.verify() {
		t.Fatal("opaque copy mutated bound revision")
	}
	if (BoundRevision{}).verify() {
		t.Fatal("zero bound revision verified")
	}
	issuer := newBoundRevisionIssuer()
	if _, err := issuer.BindValidated(BoundRevisionHandoffV1+".unknown", []byte("opaque")); err == nil {
		t.Fatal("unknown handoff version accepted")
	}
	if _, err := issuer.BindValidated(BoundRevisionHandoffV1, nil); err == nil {
		t.Fatal("empty bound revision accepted")
	}
	issuer.close()
	if _, err := issuer.BindValidated(BoundRevisionHandoffV1, []byte("late")); err == nil {
		t.Fatal("expired issuer accepted revision")
	}
}

func TestRecheckErrorsAreNonDisclosing(t *testing.T) {
	rechecker := &fakeRechecker{behavior: recheckError}
	adapter, _ := NewRequestBoundaryAdapter(rechecker)
	response := &fakeBufferedResponse{}
	_, err := adapter.ReleaseProtected(context.Background(), testBoundRevision(t), response)
	if ErrorCodeOf(err) != CodeBoundaryDenied || errors.Is(err, errInjected) || err.Error() != "core transaction contract failed: boundary_denied" {
		t.Fatalf("unsafe boundary error=%v", err)
	}
}
