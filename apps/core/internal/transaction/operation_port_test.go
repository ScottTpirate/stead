package transaction

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type commitOnlyBinding struct{}

func (*commitOnlyBinding) Commit(context.Context) error { return nil }

type rollbackOnlyBinding struct{}

func (*rollbackOnlyBinding) Rollback(context.Context) error { return nil }

func TestExecutorBindingExcludesLifecycleAuthorityAtConstructionAndExecution(t *testing.T) {
	anchor := &fakeSession{}
	if binding, err := NewExecutorBinding(nil, struct{}{}); ErrorCodeOf(err) != CodeInvalidContract || binding.valid() {
		t.Fatalf("binding without lifecycle association accepted: binding=%#v err=%v", binding, err)
	}
	for _, value := range []any{nil, (*commitOnlyBinding)(nil), &commitOnlyBinding{}, &rollbackOnlyBinding{}, &fakeSession{}} {
		if binding, err := NewExecutorBinding(anchor, value); ErrorCodeOf(err) != CodeInvalidContract || binding.valid() {
			t.Fatalf("lifecycle-bearing binding accepted: type=%T binding=%#v err=%v", value, binding, err)
		}
	}
	bound, err := NewExecutorBinding(anchor, struct{}{})
	if err != nil || !bound.validFor(anchor) || bound.validFor(&fakeSession{}) {
		t.Fatalf("executor binding was not sealed to one lifecycle session: binding=%#v err=%v", bound, err)
	}

	backend := &fakeBackend{}
	var callbackCalls atomic.Int32
	operation := registeredOperationForTest(
		backend,
		"owner",
		func(ctx context.Context, binding ExecutorBinding, _ struct{}) error {
			callbackCalls.Add(1)
			if _, ok := ResolveExecutorBinding[Session](binding); ok {
				return errors.New("executor resolved coordinator lifecycle session")
			}
			if _, ok := ResolveExecutorBinding[commitCapability](binding); ok {
				return errors.New("executor resolved commit authority")
			}
			if _, ok := ResolveExecutorBinding[rollbackCapability](binding); ok {
				return errors.New("executor resolved rollback authority")
			}
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
