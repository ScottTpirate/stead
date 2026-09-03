package transaction

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type adversarialSessionLifecycle struct {
	commits   atomic.Int32
	rollbacks atomic.Int32
}

// interfaceBearingSession is statically comparable, but comparing two
// interface values containing it panics when payload contains a slice.
type interfaceBearingSession struct {
	payload   any
	lifecycle *adversarialSessionLifecycle
}

func (session interfaceBearingSession) Commit(context.Context) error {
	session.lifecycle.commits.Add(1)
	return nil
}

func (session interfaceBearingSession) Rollback(context.Context) error {
	session.lifecycle.rollbacks.Add(1)
	return nil
}

// nonComparableSession is a valid Session whose dynamic type cannot be used in
// interface equality at all.
type nonComparableSession struct {
	values    []string
	lifecycle *adversarialSessionLifecycle
}

func (session nonComparableSession) Commit(context.Context) error {
	session.lifecycle.commits.Add(1)
	return nil
}

func (session nonComparableSession) Rollback(context.Context) error {
	session.lifecycle.rollbacks.Add(1)
	return nil
}

type fixedBeginResultBackend struct {
	result BeginResult
	err    error
	begins atomic.Int32
}

func (backend *fixedBeginResultBackend) Begin(context.Context) (BeginResult, error) {
	backend.begins.Add(1)
	return backend.result, backend.err
}

func comparisonPanics(left, right Session) (panicked bool) {
	defer func() {
		panicked = recover() != nil
	}()
	_ = left == right
	return false
}

func executeFixedBeginResult(t *testing.T, result BeginResult, participantCalls *atomic.Int32) (Report, error) {
	t.Helper()
	backend := &fixedBeginResultBackend{result: result}
	contract, err := NewBackendContract(backend)
	if err != nil {
		t.Fatal(err)
	}
	backendOperation, err := NewBackendOperation(contract, "owner", func(context.Context, ExecutorBinding, struct{}) error {
		participantCalls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := NewRegisteredOperation(backendOperation, func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error {
		return port.Execute(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
	template, planContract, err := NewPlanContract(ContractVersionV1, "adversarial_begin_pair", []TypedParticipant[struct{}]{{
		Key: "write", DeclaresWrite: true, Operation: operation,
	}}, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(Configuration{
		Backend: contract, Registry: registry, Outbox: &fakeAppender{backend: &fakeBackend{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planContract.Bind(registry, struct{}{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator.Execute(context.Background(), plan)
}

func TestExecutorBindingExcludesLifecycleAuthorityAtConstructionAndExecution(t *testing.T) {
	anchor := &fakeSession{}
	if bindingType := reflect.TypeOf(ExecutorBinding{}); !bindingType.Comparable() || bindingType.NumField() != 1 || bindingType.Field(0).IsExported() {
		t.Fatalf("executor binding is not a comparable opaque identity: %v", bindingType)
	}
	if resultType := reflect.TypeOf(BeginResult{}); !resultType.Comparable() || resultType.NumField() != 2 {
		t.Fatalf("begin result is not an opaque comparable pair: %v", resultType)
	}
	constructorType := reflect.TypeOf(NewBeginResult)
	if constructorType.NumIn() != 1 || constructorType.In(0) != reflect.TypeOf((*Session)(nil)).Elem() || constructorType.NumOut() != 3 {
		t.Fatalf("begin-result constructor accepts more than the lifecycle association: %v", constructorType)
	}
	if result, binding, err := NewBeginResult(nil); ErrorCodeOf(err) != CodeInvalidContract || binding.valid() || result.state != nil {
		t.Fatalf("pair without lifecycle association accepted: result=%#v binding=%#v err=%v", result, binding, err)
	}
	if forged := (ExecutorBinding{state: &executorBindingState{}}); forged.valid() {
		t.Fatal("executor identity without the package seal was accepted")
	}
	result, bound, err := NewBeginResult(anchor)
	if err != nil || !bound.valid() || result.binding != bound {
		t.Fatalf("executor binding was not sealed into one begin result: result=%#v binding=%#v err=%v", result, bound, err)
	}
	returned, consumed, pair, ok := result.consume()
	if !ok || returned != anchor || consumed != bound || !bound.validFor(pair) {
		t.Fatalf("begin pair was not consumed exactly: session=%T binding=%#v pair=%p ok=%t", returned, consumed, pair, ok)
	}
	if reused, reusedBinding, reusedPair, reusedOK := result.consume(); reused != anchor || reusedBinding.valid() || reusedPair != nil || reusedOK {
		t.Fatalf("begin pair was reusable: session=%T binding=%#v pair=%p ok=%t", reused, reusedBinding, reusedPair, reusedOK)
	}
	if copy := bound; copy != bound || copy.state != bound.state {
		t.Fatal("executor binding copy changed opaque identity")
	}
	for _, prohibited := range []string{"Commit", "Rollback", "Resolve", "Session", "Value"} {
		if _, exists := reflect.TypeOf(bound).MethodByName(prohibited); exists {
			t.Fatalf("executor binding exposes prohibited method %s", prohibited)
		}
	}

	backend := &fakeBackend{}
	var callbackCalls atomic.Int32
	operation := registeredOperationForTest(
		backend,
		"owner",
		func(ctx context.Context, binding ExecutorBinding, _ struct{}) error {
			callbackCalls.Add(1)
			return backend.stage(ctx, binding, "owner", "write")
		},
		func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error { return port.Execute(ctx) },
	)
	template, contract, err := NewPlanContract(ContractVersionV1, "no_early_commit", []TypedParticipant[struct{}]{{
		Key: "write", DeclaresWrite: true, Operation: operation,
	}}, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, struct{}{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	calls, committed, begins, commits, rollbacks, _ := backend.snapshot()
	if callbackCalls.Load() != 1 || !reflect.DeepEqual(calls, []string{"begin", "write", "commit"}) ||
		!reflect.DeepEqual(committed, []string{"write"}) || begins != 1 || commits != 1 || rollbacks != 0 {
		t.Fatalf("executor gained lifecycle control: callbacks=%d calls=%v committed=%v lifecycle=%d/%d/%d",
			callbackCalls.Load(), calls, committed, begins, commits, rollbacks)
	}
}

func TestBeginPairSupportsEveryNonNilSessionShapeWithoutInterfaceEquality(t *testing.T) {
	interfaceLifecycle := &adversarialSessionLifecycle{}
	interfaceBearing := interfaceBearingSession{payload: []string{"would", "panic", "under", "equality"}, lifecycle: interfaceLifecycle}
	if !reflect.TypeOf(interfaceBearing).Comparable() || !comparisonPanics(interfaceBearing, interfaceBearing) {
		t.Fatal("interface-bearing regression shape no longer demonstrates the equality panic")
	}
	nonComparableLifecycle := &adversarialSessionLifecycle{}
	nonComparable := nonComparableSession{values: []string{"not", "comparable"}, lifecycle: nonComparableLifecycle}
	if reflect.TypeOf(nonComparable).Comparable() {
		t.Fatal("non-comparable regression shape unexpectedly became comparable")
	}

	for _, testCase := range []struct {
		name      string
		session   Session
		lifecycle *adversarialSessionLifecycle
	}{
		{name: "comparable static type with interface-held slice", session: interfaceBearing, lifecycle: interfaceLifecycle},
		{name: "genuinely non-comparable dynamic type", session: nonComparable, lifecycle: nonComparableLifecycle},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result, binding, err := NewBeginResult(testCase.session)
			if err != nil || !binding.valid() {
				t.Fatalf("valid session shape rejected: binding=%#v err=%v", binding, err)
			}
			var participants atomic.Int32
			report, err := executeFixedBeginResult(t, result, &participants)
			if err != nil {
				t.Fatalf("valid session shape failed: %v", err)
			}
			if participants.Load() != 1 || testCase.lifecycle.commits.Load() != 1 || testCase.lifecycle.rollbacks.Load() != 0 ||
				report.BeginCalls != 1 || report.ParticipantCalls != 1 || report.CommitCalls != 1 || report.RollbackCalls != 0 {
				t.Fatalf("valid session lifecycle participants=%d commit=%d rollback=%d report=%+v",
					participants.Load(), testCase.lifecycle.commits.Load(), testCase.lifecycle.rollbacks.Load(), report)
			}
		})
	}
}

func TestCoordinatorRejectsMissingMismatchedAndReusedBeginPairsWithoutPanic(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		build func(*adversarialSessionLifecycle, *adversarialSessionLifecycle) BeginResult
	}{
		{
			name: "missing binding half with interface-bearing session",
			build: func(primary, _ *adversarialSessionLifecycle) BeginResult {
				result, _, err := NewBeginResult(interfaceBearingSession{payload: []int{1, 2, 3}, lifecycle: primary})
				if err != nil {
					panic(err)
				}
				result.binding = ExecutorBinding{}
				return result
			},
		},
		{
			name: "mismatched binding half with non-comparable session",
			build: func(primary, other *adversarialSessionLifecycle) BeginResult {
				result, _, err := NewBeginResult(nonComparableSession{values: []string{"primary"}, lifecycle: primary})
				if err != nil {
					panic(err)
				}
				_, foreignBinding, err := NewBeginResult(nonComparableSession{values: []string{"foreign"}, lifecycle: other})
				if err != nil {
					panic(err)
				}
				result.binding = foreignBinding
				return result
			},
		},
		{
			name: "reused consumed pair",
			build: func(primary, _ *adversarialSessionLifecycle) BeginResult {
				result, _, err := NewBeginResult(interfaceBearingSession{payload: []byte("reused"), lifecycle: primary})
				if err != nil {
					panic(err)
				}
				if _, _, _, ok := result.consume(); !ok {
					panic("fresh pair did not consume")
				}
				return result
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			primary := &adversarialSessionLifecycle{}
			other := &adversarialSessionLifecycle{}
			result := testCase.build(primary, other)
			var participants atomic.Int32
			report, err := executeFixedBeginResult(t, result, &participants)
			if ErrorCodeOf(err) != CodeBeginFailed {
				t.Fatalf("invalid begin pair error=%v", err)
			}
			if participants.Load() != 0 || primary.commits.Load() != 0 || primary.rollbacks.Load() != 1 ||
				other.commits.Load() != 0 || other.rollbacks.Load() != 0 || report.BeginCalls != 1 ||
				report.ParticipantCalls != 0 || report.CommitCalls != 0 || report.RollbackCalls != 1 {
				t.Fatalf("invalid pair escaped participants=%d primary=%d/%d other=%d/%d report=%+v",
					participants.Load(), primary.commits.Load(), primary.rollbacks.Load(), other.commits.Load(), other.rollbacks.Load(), report)
			}
		})
	}
}

func TestCoordinatorRejectsCrossSessionExecutorBindingBeforeOperation(t *testing.T) {
	backend := &fakeBackend{mismatchBinding: true}
	var callbackCalls atomic.Int32
	operation := registeredOperationForTest(
		backend,
		"owner",
		func(context.Context, ExecutorBinding, struct{}) error {
			callbackCalls.Add(1)
			return nil
		},
		func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error { return port.Execute(ctx) },
	)
	template, contract, err := NewPlanContract(ContractVersionV1, "cross_session_binding", []TypedParticipant[struct{}]{{Key: "write", Operation: operation}}, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, struct{}{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan); ErrorCodeOf(err) != CodeBeginFailed {
		t.Fatalf("cross-session binding error=%v", err)
	}
	_, committed, begins, commits, rollbacks, _ := backend.snapshot()
	_, _, active := backend.journals()
	if callbackCalls.Load() != 0 || len(committed) != 0 || begins != 1 || commits != 0 || rollbacks != 1 || active != 0 {
		t.Fatalf("cross-session binding reached operation: callbacks=%d lifecycle=%d/%d/%d active=%d committed=%v",
			callbackCalls.Load(), begins, commits, rollbacks, active, committed)
	}
}

func TestBackendBindingJournalRejectsUnknownForeignCrossSessionAndExpiredIdentities(t *testing.T) {
	backend := &fakeBackend{}
	firstResult, err := backend.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstSessionValue, firstBinding, firstPair, ok := firstResult.consume()
	if !ok {
		t.Fatal("first begin result was not consumable")
	}
	secondResult, err := backend.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondSessionValue, secondBinding, secondPair, ok := secondResult.consume()
	if !ok {
		t.Fatal("second begin result was not consumable")
	}
	firstSession := firstSessionValue.(*fakeSession)
	secondSession := secondSessionValue.(*fakeSession)
	if firstBinding == secondBinding || firstPair == secondPair || !firstBinding.validFor(firstPair) || !secondBinding.validFor(secondPair) ||
		firstBinding.validFor(secondPair) || secondBinding.validFor(firstPair) {
		t.Fatal("executor identities were not distinct and exact-session bound")
	}
	if err := backend.stage(context.Background(), ExecutorBinding{}, "owner", "zero"); err == nil {
		t.Fatal("zero executor identity reached storage")
	}
	foreign := &fakeBackend{}
	foreignResult, err := foreign.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	foreignSession, foreignBinding, _, ok := foreignResult.consume()
	if !ok {
		t.Fatal("foreign begin result was not consumable")
	}
	if err := backend.stage(context.Background(), foreignBinding, "owner", "foreign"); err == nil {
		t.Fatal("foreign-backend executor identity reached storage")
	}
	if err := foreignSession.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), firstBinding, "owner", "first"); err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), secondBinding, "owner", "second"); err != nil {
		t.Fatal(err)
	}
	firstCopy := firstBinding
	if err := firstSession.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), firstCopy, "owner", "after-commit"); err == nil {
		t.Fatal("copied executor identity survived commit")
	}
	if err := backend.stage(context.Background(), secondBinding, "owner", "second-still-live"); err != nil {
		t.Fatalf("committing first identity invalidated independent second identity: %v", err)
	}
	secondCopy := secondBinding
	if err := secondSession.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), secondCopy, "owner", "after-rollback"); err == nil {
		t.Fatal("copied executor identity survived rollback")
	}
	committed, rolledBack, active := backend.journals()
	backend.mu.Lock()
	bindings, bound := len(backend.bindings), len(backend.boundSession)
	backend.mu.Unlock()
	if !reflect.DeepEqual(committed[1], []string{"first"}) ||
		!reflect.DeepEqual(rolledBack[2], []string{"second", "second-still-live"}) ||
		active != 0 || bindings != 0 || bound != 0 {
		t.Fatalf("journal lifecycle committed=%v rolled-back=%v active=%d identities=%d/%d", committed, rolledBack, active, bindings, bound)
	}
}

func TestRegisteredExecutorLeakedBindingExpiresBeforePostTransactionStorageUse(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		ownerFail bool
	}{
		{name: "commit"},
		{name: "rollback", ownerFail: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{}
			var leaked ExecutorBinding
			operation := registeredOperationForTest(
				backend,
				"owner",
				func(ctx context.Context, binding ExecutorBinding, _ struct{}) error {
					leaked = binding
					return backend.stage(ctx, binding, "owner", "write")
				},
				func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error {
					if err := port.Execute(ctx); err != nil {
						return err
					}
					if testCase.ownerFail {
						return errInjected
					}
					return nil
				},
			)
			template, contract, err := NewPlanContract(ContractVersionV1, "leaked_binding_"+testCase.name, []TypedParticipant[struct{}]{{
				Key: "write", DeclaresWrite: true, Operation: operation,
			}}, OutboxOptional)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewRegistry([]PlanTemplate{template})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := contract.Bind(registry, struct{}{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, executeErr := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan)
			if (testCase.ownerFail && ErrorCodeOf(executeErr) != CodeParticipantFailed) || (!testCase.ownerFail && executeErr != nil) {
				t.Fatalf("transaction result = %v", executeErr)
			}
			if !leaked.valid() {
				t.Fatal("registered executor did not receive a sealed identity")
			}
			if err := backend.stage(context.Background(), leaked, "owner", "late-write"); err == nil {
				t.Fatal("binding leaked by registered executor remained usable after transaction")
			}
			_, _, active := backend.journals()
			backend.mu.Lock()
			bindings, bound := len(backend.bindings), len(backend.boundSession)
			backend.mu.Unlock()
			if active != 0 || bindings != 0 || bound != 0 {
				t.Fatalf("expired binding journal active=%d identities=%d/%d", active, bindings, bound)
			}
		})
	}
}

func TestOperationRegistrationRejectsZeroForeignAndCallerSelectedInputs(t *testing.T) {
	var typedNil *fakeBackend
	if _, err := NewBackendContract(typedNil); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("typed-nil backend error = %v", err)
	}
	backend := &fakeBackend{}
	contract := backend.backendContract()
	for _, testCase := range []struct {
		name     string
		contract BackendContract
		owner    string
		execute  func(context.Context, ExecutorBinding, struct{}) error
	}{
		{name: "zero backend contract", owner: "owner", execute: func(context.Context, ExecutorBinding, struct{}) error { return nil }},
		{name: "invalid owner", contract: contract, owner: "UPPER", execute: func(context.Context, ExecutorBinding, struct{}) error { return nil }},
		{name: "reserved outbox owner", contract: contract, owner: "core_outbox", execute: func(context.Context, ExecutorBinding, struct{}) error { return nil }},
		{name: "nil executor", contract: contract, owner: "owner"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewBackendOperation(testCase.contract, testCase.owner, testCase.execute); ErrorCodeOf(err) != CodeInvalidContract {
				t.Fatalf("backend operation error = %v", err)
			}
		})
	}
	valid, err := NewBackendOperation(contract, "owner", func(context.Context, ExecutorBinding, struct{}) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegisteredOperation(BackendOperation[struct{}]{}, func(context.Context, OperationPort[struct{}], struct{}) error { return nil }); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("zero backend operation error = %v", err)
	}
	if _, err := NewRegisteredOperation(valid, nil); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("nil owner adapter error = %v", err)
	}
}

func TestOperationPortRejectsDerivedContextsThatCanWidenTheCoordinatorCall(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		derive func(context.Context) context.Context
	}{
		{name: "without cancellation or deadline", derive: context.WithoutCancel},
		{name: "derived value context", derive: func(ctx context.Context) context.Context {
			return context.WithValue(ctx, struct{ name string }{"override"}, "changed")
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{}
			var backendCalls atomic.Int32
			operation := registeredOperationForTest(
				backend,
				"owner",
				func(context.Context, ExecutorBinding, struct{}) error {
					backendCalls.Add(1)
					return nil
				},
				func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error {
					return port.Execute(testCase.derive(ctx))
				},
			)
			template, contract, err := NewPlanContract(ContractVersionV1, "derived_context", []TypedParticipant[struct{}]{{Key: "write", Operation: operation}}, OutboxOptional)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewRegistry([]PlanTemplate{template})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := contract.Bind(registry, struct{}{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(ctx, plan); ErrorCodeOf(err) != CodeParticipantFailed {
				t.Fatalf("derived context error = %v", err)
			}
			_, committed, begins, commits, rollbacks, _ := backend.snapshot()
			if backendCalls.Load() != 0 || len(committed) != 0 || begins != 1 || commits != 0 || rollbacks != 1 {
				t.Fatalf("derived context reached backend: calls=%d lifecycle=%d/%d/%d committed=%v", backendCalls.Load(), begins, commits, rollbacks, committed)
			}
		})
	}
}

func TestBackendOperationUsesCoordinatorContextAndStopsAtItsDeadline(t *testing.T) {
	backend := &fakeBackend{}
	entered := make(chan struct{})
	var deadlineExpired atomic.Bool
	operation := registeredOperationForTest(
		backend,
		"owner",
		func(ctx context.Context, _ ExecutorBinding, _ struct{}) error {
			if _, present := ctx.Deadline(); !present {
				return errInjected
			}
			close(entered)
			<-ctx.Done()
			deadlineExpired.Store(ctx.Err() == context.DeadlineExceeded)
			return ctx.Err()
		},
		func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error {
			return port.Execute(ctx)
		},
	)
	template, contract, err := NewPlanContract(ContractVersionV1, "coordinator_deadline", []TypedParticipant[struct{}]{{Key: "write", Operation: operation}}, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, struct{}{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, executeErr := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(ctx, plan)
		done <- executeErr
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("backend operation did not start")
	}
	select {
	case err := <-done:
		if ErrorCodeOf(err) != CodeParticipantFailed {
			t.Fatalf("deadline backend error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backend operation did not stop on coordinator deadline")
	}
	_, committed, begins, commits, rollbacks, _ := backend.snapshot()
	if !deadlineExpired.Load() || len(committed) != 0 || begins != 1 || commits != 0 || rollbacks != 1 {
		t.Fatalf("deadline expired=%t lifecycle=%d/%d/%d committed=%v", deadlineExpired.Load(), begins, commits, rollbacks, committed)
	}
}

func TestBackendOperationFailureOrPanicCannotBeIgnoredByOwnerAdapter(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		execute func(context.Context, ExecutorBinding, struct{}) error
	}{
		{name: "error", execute: func(context.Context, ExecutorBinding, struct{}) error { return errInjected }},
		{name: "panic", execute: func(context.Context, ExecutorBinding, struct{}) error { panic("repository panic") }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{}
			operation := registeredOperationForTest(
				backend,
				"owner",
				testCase.execute,
				func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error {
					_ = port.Execute(ctx)
					return nil
				},
			)
			template, contract, err := NewPlanContract(ContractVersionV1, "repository_failure", []TypedParticipant[struct{}]{
				{Key: "write", DeclaresWrite: true, Operation: operation},
			}, OutboxOptional)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewRegistry([]PlanTemplate{template})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := contract.Bind(registry, struct{}{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan); ErrorCodeOf(err) != CodeParticipantFailed {
				t.Fatalf("repository failure error = %v", err)
			}
			_, committed, begins, commits, rollbacks, _ := backend.snapshot()
			if len(committed) != 0 || begins != 1 || commits != 0 || rollbacks != 1 {
				t.Fatalf("repository failure lifecycle=%d/%d/%d committed=%v", begins, commits, rollbacks, committed)
			}
		})
	}
}
