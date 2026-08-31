package transaction

import (
	"context"
	"testing"
)

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
		execute  func(context.Context, Session, struct{}) error
	}{
		{name: "zero backend contract", owner: "owner", execute: func(context.Context, Session, struct{}) error { return nil }},
		{name: "invalid owner", contract: contract, owner: "UPPER", execute: func(context.Context, Session, struct{}) error { return nil }},
		{name: "reserved outbox owner", contract: contract, owner: "core_outbox", execute: func(context.Context, Session, struct{}) error { return nil }},
		{name: "nil executor", contract: contract, owner: "owner"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewBackendOperation(testCase.contract, testCase.owner, testCase.execute); ErrorCodeOf(err) != CodeInvalidContract {
				t.Fatalf("backend operation error = %v", err)
			}
		})
	}
	valid, err := NewBackendOperation(contract, "owner", func(context.Context, Session, struct{}) error { return nil })
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

func TestBackendOperationFailureOrPanicCannotBeIgnoredByOwnerAdapter(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		execute func(context.Context, Session, struct{}) error
	}{
		{name: "error", execute: func(context.Context, Session, struct{}) error { return errInjected }},
		{name: "panic", execute: func(context.Context, Session, struct{}) error { panic("repository panic") }},
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
