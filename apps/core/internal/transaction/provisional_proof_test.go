package transaction

import (
	"context"
	"sync"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

type proofGateAppender struct {
	delegate *fakeAppender
	entered  chan struct{}
	proceed  chan struct{}
}

func (appender *proofGateAppender) Append(ctx context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	close(appender.entered)
	select {
	case <-appender.proceed:
	case <-ctx.Done():
		return outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}, BindingReceipt{}, ctx.Err()
	}
	return appender.delegate.Append(ctx, scope, intent)
}

type proofCapturingFinalizer struct {
	intent      *outbox.ValidatedIntent
	returnError bool
	panicAfter  bool
	leaked      BoundRevision
	retained    BoundRevisionIssuer
	secondError error
}

func (finalizer *proofCapturingFinalizer) Finalize(ctx context.Context, port OperationPort[*FinalAuthorizationAuditOperation], issuer BoundRevisionIssuer) (FinalAuthorizationAuditResult, error) {
	if err := port.Execute(ctx); err != nil {
		return FinalAuthorizationAuditResult{}, err
	}
	revision, err := issuer.BindValidated(BoundRevisionHandoffV1, []byte("captured-bound-revision"))
	if err != nil {
		return FinalAuthorizationAuditResult{}, err
	}
	finalizer.leaked = revision
	finalizer.retained = issuer
	_, finalizer.secondError = issuer.BindValidated(BoundRevisionHandoffV1, []byte("second-bound-revision"))
	if finalizer.panicAfter {
		panic("panic after bound revision issuance")
	}
	result := FinalAuthorizationAuditResult{Revision: revision, Intent: finalizer.intent}
	if finalizer.returnError {
		return result, errInjected
	}
	return result, nil
}

type proofCapturingPreparation struct {
	intent      outbox.ValidatedIntent
	returnError bool
	panicAfter  bool
	leaked      DurableEffectReceipt
	retained    DurableEffectIssuer
	secondError error
}

func (preparation *proofCapturingPreparation) Prepare(ctx context.Context, port OperationPort[*DurableEffectOperation], issuer DurableEffectIssuer) (DurableEffectPreparation, error) {
	if err := port.Execute(ctx); err != nil {
		return DurableEffectPreparation{}, err
	}
	receipt, err := issuer.BindValidated(DurableEffectHandoffV1, []byte("captured-durable-receipt"))
	if err != nil {
		return DurableEffectPreparation{}, err
	}
	preparation.leaked = receipt
	preparation.retained = issuer
	_, preparation.secondError = issuer.BindValidated(DurableEffectHandoffV1, []byte("second-durable-receipt"))
	if preparation.panicAfter {
		panic("panic after durable receipt issuance")
	}
	result := DurableEffectPreparation{Receipt: receipt, Intent: preparation.intent}
	if preparation.returnError {
		return result, errInjected
	}
	return result, nil
}

func TestBoundRevisionIssuerIsConcurrentSingleIssuanceAndSharedLifecycle(t *testing.T) {
	issuer := newBoundRevisionIssuer()
	const attempts = 64
	results := make(chan BoundRevision, attempts)
	errorsSeen := make(chan error, attempts)
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			revision, err := issuer.BindValidated(BoundRevisionHandoffV1, []byte{byte(index + 1)})
			results <- revision
			errorsSeen <- err
		}(index)
	}
	wait.Wait()
	close(results)
	close(errorsSeen)

	var revision BoundRevision
	issued := 0
	for candidate := range results {
		if candidate.state != nil {
			issued++
			revision = candidate
		}
	}
	denied := 0
	for err := range errorsSeen {
		if err != nil {
			denied++
		}
	}
	if issued != 1 || denied != attempts-1 || revision.verify() {
		t.Fatalf("issuance=%d denied=%d provisional-valid=%t", issued, denied, revision.verify())
	}
	copy := revision
	if !issuer.accept(copy) || issuer.accept(revision) {
		t.Fatal("bound revision was not accepted exactly once")
	}
	issuer.close()
	if revision.verify() || !copy.activate() || !revision.verify() || copy.activate() || copy.state != revision.state {
		t.Fatal("bound revision copies did not share one post-commit activation")
	}
	if _, err := issuer.BindValidated(BoundRevisionHandoffV1, []byte("late")); err == nil {
		t.Fatal("closed bound revision issuer minted another proof")
	}

	abandoned := newBoundRevisionIssuer()
	abandonedRevision, err := abandoned.BindValidated(BoundRevisionHandoffV1, []byte("abandoned"))
	if err != nil {
		t.Fatal(err)
	}
	abandonedCopy := abandoned
	abandoned.close()
	if abandonedRevision.verify() || abandonedRevision.activate() {
		t.Fatal("unaccepted bound revision survived issuer close")
	}
	if _, err := abandonedCopy.BindValidated(BoundRevisionHandoffV1, []byte("after-close")); err == nil {
		t.Fatal("retained bound revision issuer survived close")
	}
}

func TestDurableEffectIssuerIsConcurrentSingleIssuanceAndSharedLifecycle(t *testing.T) {
	issuer := newDurableEffectIssuer()
	seal := issuer.state.seal
	const attempts = 64
	results := make(chan DurableEffectReceipt, attempts)
	errorsSeen := make(chan error, attempts)
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			receipt, err := issuer.BindValidated(DurableEffectHandoffV1, []byte{byte(index + 1)})
			results <- receipt
			errorsSeen <- err
		}(index)
	}
	wait.Wait()
	close(results)
	close(errorsSeen)

	var receipt DurableEffectReceipt
	issued := 0
	for candidate := range results {
		if candidate.state != nil {
			issued++
			receipt = candidate
		}
	}
	denied := 0
	for err := range errorsSeen {
		if err != nil {
			denied++
		}
	}
	if issued != 1 || denied != attempts-1 || receipt.validFor(seal) {
		t.Fatalf("issuance=%d denied=%d provisional-valid=%t", issued, denied, receipt.validFor(seal))
	}
	copy := receipt
	if !issuer.accept(copy) || issuer.accept(receipt) {
		t.Fatal("durable receipt was not accepted exactly once")
	}
	issuer.close()
	if receipt.validFor(seal) || !copy.activate(seal) || !receipt.validFor(seal) || copy.activate(seal) || copy.state != receipt.state {
		t.Fatal("durable receipt copies did not share one post-commit activation")
	}
	if _, err := issuer.BindValidated(DurableEffectHandoffV1, []byte("late")); err == nil {
		t.Fatal("closed durable issuer minted another proof")
	}

	abandoned := newDurableEffectIssuer()
	abandonedSeal := abandoned.state.seal
	abandonedReceipt, err := abandoned.BindValidated(DurableEffectHandoffV1, []byte("abandoned"))
	if err != nil {
		t.Fatal(err)
	}
	abandonedCopy := abandoned
	abandoned.close()
	if abandonedReceipt.validFor(abandonedSeal) || abandonedReceipt.activate(abandonedSeal) {
		t.Fatal("unaccepted durable receipt survived issuer close")
	}
	if _, err := abandonedCopy.BindValidated(DurableEffectHandoffV1, []byte("after-close")); err == nil {
		t.Fatal("retained durable issuer survived close")
	}
}

func TestLeakedBoundRevisionInvalidatesOnEveryFailureAfterIssuance(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*proofCapturingFinalizer, *fakeAppender, *fakeBackend)
	}{
		{name: "owner error", configure: func(finalizer *proofCapturingFinalizer, _ *fakeAppender, _ *fakeBackend) {
			finalizer.returnError = true
		}},
		{name: "owner panic", configure: func(finalizer *proofCapturingFinalizer, _ *fakeAppender, _ *fakeBackend) { finalizer.panicAfter = true }},
		{name: "invalid intent", configure: func(finalizer *proofCapturingFinalizer, _ *fakeAppender, _ *fakeBackend) {
			intent := outbox.ValidatedIntent{}
			finalizer.intent = &intent
		}},
		{name: "outbox error", configure: func(finalizer *proofCapturingFinalizer, appender *fakeAppender, _ *fakeBackend) {
			intent := testIntent()
			finalizer.intent = &intent
			appender.fail = true
		}},
		{name: "outbox panic", configure: func(finalizer *proofCapturingFinalizer, appender *fakeAppender, _ *fakeBackend) {
			intent := testIntent()
			finalizer.intent = &intent
			appender.panic = true
		}},
		{name: "ambiguous commit error", configure: func(finalizer *proofCapturingFinalizer, _ *fakeAppender, backend *fakeBackend) {
			backend.failCommit = true
		}},
		{name: "ambiguous commit panic", configure: func(finalizer *proofCapturingFinalizer, _ *fakeAppender, backend *fakeBackend) {
			backend.panicCommit = true
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{}
			appender := &fakeAppender{backend: backend}
			finalizer := &proofCapturingFinalizer{}
			testCase.configure(finalizer, appender, backend)
			coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), appender, finalizer, nil)
			returned, report, err := coordinator.FinalizeRead(context.Background())
			if err == nil || returned.state != nil || report.Retries != 0 {
				t.Fatalf("failure escaped result: revision=%#v report=%#v err=%v", returned, report, err)
			}
			if finalizer.leaked.state == nil || finalizer.secondError == nil || finalizer.leaked.verify() ||
				finalizer.leaked.state.proof.state.Load() != proofInvalid || finalizer.leaked.activate() {
				t.Fatalf("leaked revision was not permanently invalidated: %#v", finalizer.leaked)
			}
			if _, err := finalizer.retained.BindValidated(BoundRevisionHandoffV1, []byte("post-return")); err == nil {
				t.Fatal("retained revision issuer remained open")
			}
			rechecker := &fakeRechecker{behavior: recheckConfirm}
			rechecker.allowed.Store(true)
			adapter, adapterErr := NewRequestBoundaryAdapter(rechecker)
			if adapterErr != nil {
				t.Fatal(adapterErr)
			}
			response := &fakeBufferedResponse{}
			if _, err := adapter.ReleaseProtected(context.Background(), finalizer.leaked, response); ErrorCodeOf(err) != CodeBoundaryDenied {
				t.Fatalf("invalidated revision reached boundary: %v", err)
			}
			released, suppressed := response.counts()
			if rechecker.calls.Load() != 0 || released != 0 || suppressed != 1 {
				t.Fatalf("invalidated revision was consumed: rechecks=%d response=%d/%d", rechecker.calls.Load(), released, suppressed)
			}
			_, committed, begins, _, rollbacks, _ := backend.snapshot()
			if len(committed) != 0 || begins != 1 || rollbacks != 1 {
				t.Fatalf("failure lifecycle=%d/*/%d committed=%v", begins, rollbacks, committed)
			}
		})
	}
}

func TestLeakedDurableReceiptInvalidatesOnEveryFailureAfterIssuance(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*proofCapturingPreparation, *fakeAppender, *fakeBackend)
	}{
		{name: "owner error", configure: func(preparation *proofCapturingPreparation, _ *fakeAppender, _ *fakeBackend) {
			preparation.returnError = true
		}},
		{name: "owner panic", configure: func(preparation *proofCapturingPreparation, _ *fakeAppender, _ *fakeBackend) {
			preparation.panicAfter = true
		}},
		{name: "invalid intent", configure: func(preparation *proofCapturingPreparation, _ *fakeAppender, _ *fakeBackend) {
			preparation.intent = outbox.ValidatedIntent{}
		}},
		{name: "outbox error", configure: func(_ *proofCapturingPreparation, appender *fakeAppender, _ *fakeBackend) { appender.fail = true }},
		{name: "outbox panic", configure: func(_ *proofCapturingPreparation, appender *fakeAppender, _ *fakeBackend) { appender.panic = true }},
		{name: "ambiguous commit error", configure: func(_ *proofCapturingPreparation, _ *fakeAppender, backend *fakeBackend) { backend.failCommit = true }},
		{name: "ambiguous commit panic", configure: func(_ *proofCapturingPreparation, _ *fakeAppender, backend *fakeBackend) { backend.panicCommit = true }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{}
			appender := &fakeAppender{backend: backend}
			preparation := &proofCapturingPreparation{intent: testIntent()}
			testCase.configure(preparation, appender, backend)
			coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), appender, nil, preparation)
			returned, report, err := coordinator.PrepareDurableEffect(context.Background())
			if err == nil || returned.state != nil || report.Retries != 0 {
				t.Fatalf("failure escaped result: receipt=%#v report=%#v err=%v", returned, report, err)
			}
			leaked := preparation.leaked
			if leaked.state == nil || preparation.secondError == nil || leaked.validFor(leaked.state.seal) ||
				leaked.state.proof.state.Load() != proofInvalid || leaked.activate(leaked.state.seal) {
				t.Fatalf("leaked durable receipt was not permanently invalidated: %#v", leaked)
			}
			if _, err := preparation.retained.BindValidated(DurableEffectHandoffV1, []byte("post-return")); err == nil {
				t.Fatal("retained durable issuer remained open")
			}
			_, committed, begins, _, rollbacks, _ := backend.snapshot()
			if len(committed) != 0 || begins != 1 || rollbacks != 1 {
				t.Fatalf("failure lifecycle=%d/*/%d committed=%v", begins, rollbacks, committed)
			}
		})
	}
}

func TestBoundRevisionCopiesStayUnusableDuringOutboxThenActivateOnceAfterCommit(t *testing.T) {
	backend := &fakeBackend{}
	intent := testIntent()
	finalizer := &proofCapturingFinalizer{intent: &intent}
	gate := &proofGateAppender{
		delegate: &fakeAppender{backend: backend},
		entered:  make(chan struct{}),
		proceed:  make(chan struct{}),
	}
	coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), gate, finalizer, nil)
	type result struct {
		revision BoundRevision
		err      error
	}
	done := make(chan result, 1)
	go func() {
		revision, _, err := coordinator.FinalizeRead(context.Background())
		done <- result{revision: revision, err: err}
	}()
	<-gate.entered
	if finalizer.leaked.state == nil || finalizer.leaked.state.proof.state.Load() != proofPendingCommit || finalizer.leaked.verify() {
		t.Fatalf("precommit revision state=%#v", finalizer.leaked.state)
	}
	rechecker := &fakeRechecker{behavior: recheckConfirm}
	rechecker.allowed.Store(true)
	adapter, err := NewRequestBoundaryAdapter(rechecker)
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 16
	var wait sync.WaitGroup
	responses := make([]*fakeBufferedResponse, attempts)
	for index := range responses {
		responses[index] = &fakeBufferedResponse{}
		wait.Add(1)
		go func(response *fakeBufferedResponse) {
			defer wait.Done()
			if _, err := adapter.ReleaseProtected(context.Background(), finalizer.leaked, response); ErrorCodeOf(err) != CodeBoundaryDenied {
				t.Errorf("precommit revision result=%v", err)
			}
		}(responses[index])
	}
	wait.Wait()
	if rechecker.calls.Load() != 0 || finalizer.leaked.state.boundary.Load() != boundaryFresh {
		t.Fatalf("precommit revision consumed: rechecks=%d boundary=%d", rechecker.calls.Load(), finalizer.leaked.state.boundary.Load())
	}
	for _, response := range responses {
		if released, suppressed := response.counts(); released != 0 || suppressed != 1 {
			t.Fatalf("precommit response=%d/%d", released, suppressed)
		}
	}
	close(gate.proceed)
	completed := <-done
	if completed.err != nil || completed.revision.state != finalizer.leaked.state || !completed.revision.verify() || finalizer.leaked.activate() {
		t.Fatalf("committed revision did not share one activation: result=%#v leaked=%#v", completed, finalizer.leaked)
	}
	response := &fakeBufferedResponse{}
	if _, err := adapter.ReleaseProtected(context.Background(), completed.revision, response); err != nil {
		t.Fatal(err)
	}
	second := &fakeBufferedResponse{}
	if _, err := adapter.ReleaseProtected(context.Background(), finalizer.leaked, second); ErrorCodeOf(err) != CodeBoundaryDenied {
		t.Fatalf("leaked copy created a second proof: %v", err)
	}
	if rechecker.calls.Load() != 1 {
		t.Fatalf("postcommit rechecks=%d", rechecker.calls.Load())
	}
}

func TestDurableReceiptCopiesStayUnusableDuringOutboxThenActivateOnceAfterCommit(t *testing.T) {
	backend := &fakeBackend{}
	preparation := &proofCapturingPreparation{intent: testIntent()}
	gate := &proofGateAppender{
		delegate: &fakeAppender{backend: backend},
		entered:  make(chan struct{}),
		proceed:  make(chan struct{}),
	}
	coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), gate, nil, preparation)
	type result struct {
		receipt DurableEffectReceipt
		err     error
	}
	done := make(chan result, 1)
	go func() {
		receipt, _, err := coordinator.PrepareDurableEffect(context.Background())
		done <- result{receipt: receipt, err: err}
	}()
	<-gate.entered
	leaked := preparation.leaked
	if leaked.state == nil || leaked.state.proof.state.Load() != proofPendingCommit || leaked.validFor(leaked.state.seal) {
		t.Fatalf("precommit durable state=%#v", leaked.state)
	}
	const attempts = 32
	results := make(chan bool, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- leaked.validFor(leaked.state.seal)
		}()
	}
	wait.Wait()
	close(results)
	for valid := range results {
		if valid {
			t.Fatal("durable receipt became valid before commit")
		}
	}
	close(gate.proceed)
	completed := <-done
	if completed.err != nil || completed.receipt.state != leaked.state || !completed.receipt.validFor(leaked.state.seal) || leaked.activate(leaked.state.seal) {
		t.Fatalf("committed durable receipt did not share one activation: result=%#v leaked=%#v", completed, leaked)
	}
	if _, err := preparation.retained.BindValidated(DurableEffectHandoffV1, []byte("post-return")); err == nil {
		t.Fatal("retained durable issuer remained open after success")
	}
}
