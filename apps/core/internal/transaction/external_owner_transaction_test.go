package transaction_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	transaction "github.com/ScottTpirate/stead/apps/core/internal/transaction"
	testbackendadapter "github.com/ScottTpirate/stead/apps/core/internal/transaction/testbackendadapter"
	testowneradapter "github.com/ScottTpirate/stead/apps/core/internal/transaction/testowneradapter"
)

type externalHarness struct {
	backend  *testbackendadapter.Backend
	contract transaction.BackendContract
}

func newExternalHarness(t testing.TB) externalHarness {
	t.Helper()
	backend := &testbackendadapter.Backend{}
	contract, err := transaction.NewBackendContract(backend)
	if err != nil {
		t.Fatal(err)
	}
	return externalHarness{backend: backend, contract: contract}
}

func (harness externalHarness) registered(t testing.TB, owner string, invoke func(context.Context, transaction.OperationPort[testowneradapter.Command], testowneradapter.Command) error) transaction.RegisteredOperation[testowneradapter.Command] {
	t.Helper()
	backendOperation, err := testbackendadapter.RegisterCommandOperation(harness.backend, harness.contract, owner)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := transaction.NewRegisteredOperation(backendOperation, invoke)
	if err != nil {
		t.Fatal(err)
	}
	return registered
}

func externalTemplate(t testing.TB, key string, operation transaction.RegisteredOperation[testowneradapter.Command]) (transaction.PlanTemplate, transaction.PlanContract[testowneradapter.Command]) {
	t.Helper()
	template, contract, err := transaction.NewPlanContract(
		transaction.ContractVersionV1,
		key,
		[]transaction.TypedParticipant[testowneradapter.Command]{{Key: "owner_write", DeclaresWrite: true, Operation: operation}},
		transaction.OutboxOptional,
	)
	if err != nil {
		t.Fatal(err)
	}
	return template, contract
}

func externalCoordinator(t testing.TB, harness externalHarness, templates ...transaction.PlanTemplate) (*transaction.Coordinator, transaction.Registry) {
	t.Helper()
	registry, err := transaction.NewRegistry(templates)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := transaction.NewCoordinator(transaction.Configuration{
		Backend:  harness.contract,
		Registry: registry,
		Outbox:   externalAppender{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, registry
}

func TestExternalOwnerOperationIsEnlistedInExactCommitAndRollback(t *testing.T) {
	harness := newExternalHarness(t)
	operation := harness.registered(t, "organization", testowneradapter.Adapter{}.Apply)
	template, contract := externalTemplate(t, "external_commit_rollback", operation)
	coordinator, registry := externalCoordinator(t, harness, template)

	commitPlan, err := contract.Bind(registry, testowneradapter.Command{Value: "committed"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Execute(context.Background(), commitPlan); err != nil {
		t.Fatal(err)
	}
	rollbackPlan, err := contract.Bind(registry, testowneradapter.Command{Value: "rolled-back", FailAfterExecute: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Execute(context.Background(), rollbackPlan); transaction.ErrorCodeOf(err) != transaction.CodeParticipantFailed {
		t.Fatalf("post-repository owner failure = %v", err)
	}

	committed, rolledBack, active, executed := harness.backend.Snapshot()
	begins, commits, rollbacks := harness.backend.Lifecycle()
	if !reflect.DeepEqual(committed, []testbackendadapter.Record{{SessionID: 1, Owner: "organization", Value: "committed"}}) ||
		!reflect.DeepEqual(rolledBack, []testbackendadapter.Record{{SessionID: 2, Owner: "organization", Value: "rolled-back"}}) ||
		active != 0 || executed["organization"] != 2 || begins != 2 || commits != 1 || rollbacks != 1 {
		t.Fatalf("commit=%v rollback=%v active=%d executed=%v lifecycle=%d/%d/%d", committed, rolledBack, active, executed, begins, commits, rollbacks)
	}
}

func TestExternalOwnerOverlappingSessionsKeepStagedWritesIndependent(t *testing.T) {
	harness := newExternalHarness(t)
	operation := harness.registered(t, "organization", testowneradapter.Adapter{}.Apply)
	template, contract := externalTemplate(t, "external_overlap", operation)
	coordinator, registry := externalCoordinator(t, harness, template)
	commitEntered, releaseCommit := harness.backend.Block("commit")
	rollbackEntered, releaseRollback := harness.backend.Block("rollback")

	commitPlan, err := contract.Bind(registry, testowneradapter.Command{Value: "commit"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rollbackPlan, err := contract.Bind(registry, testowneradapter.Command{Value: "rollback", FailAfterExecute: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	type result struct{ err error }
	results := make(chan result, 2)
	go func() { _, err := coordinator.Execute(context.Background(), commitPlan); results <- result{err: err} }()
	go func() { _, err := coordinator.Execute(context.Background(), rollbackPlan); results <- result{err: err} }()
	awaitSignal(t, commitEntered, "commit session did not stage")
	awaitSignal(t, rollbackEntered, "rollback session did not overlap")
	_, _, active, _ := harness.backend.Snapshot()
	if active != 2 {
		t.Fatalf("overlapping active sessions = %d", active)
	}
	releaseCommit()
	releaseRollback()
	first, second := <-results, <-results
	if (first.err == nil) == (second.err == nil) {
		t.Fatalf("overlap results = %v / %v", first.err, second.err)
	}
	if first.err != nil && transaction.ErrorCodeOf(first.err) != transaction.CodeParticipantFailed ||
		second.err != nil && transaction.ErrorCodeOf(second.err) != transaction.CodeParticipantFailed {
		t.Fatalf("overlap errors = %v / %v", first.err, second.err)
	}
	committed, rolledBack, active, executed := harness.backend.Snapshot()
	begins, commits, rollbacks := harness.backend.Lifecycle()
	if len(committed) != 1 || committed[0].Value != "commit" || committed[0].Owner != "organization" ||
		len(rolledBack) != 1 || rolledBack[0].Value != "rollback" || rolledBack[0].Owner != "organization" ||
		committed[0].SessionID == rolledBack[0].SessionID || active != 0 || executed["organization"] != 2 ||
		begins != 2 || commits != 1 || rollbacks != 1 {
		t.Fatalf("overlap commit=%v rollback=%v active=%d executed=%v lifecycle=%d/%d/%d", committed, rolledBack, active, executed, begins, commits, rollbacks)
	}
}

func TestExternalOwnerRetainedPortAndGoroutineAfterReturnAreRejected(t *testing.T) {
	harness := newExternalHarness(t)
	captured := make(chan testowneradapter.CapturedOperation, 1)
	operation := harness.registered(t, "organization", testowneradapter.RetainingAdapter{Captured: captured}.Apply)
	template, contract := externalTemplate(t, "external_retained", operation)
	coordinator, registry := externalCoordinator(t, harness, template)
	plan, err := contract.Bind(registry, testowneradapter.Command{Value: "once"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	retained := <-captured
	late := make(chan error, 1)
	go func() { late <- retained.Port.Execute(retained.Context) }()
	if err := <-late; transaction.ErrorCodeOf(err) != transaction.CodeParticipantFailed {
		t.Fatalf("late goroutine error = %v", err)
	}
	if err := retained.Port.Execute(retained.Context); transaction.ErrorCodeOf(err) != transaction.CodeParticipantFailed {
		t.Fatalf("retained port error = %v", err)
	}
	committed, rolledBack, active, executed := harness.backend.Snapshot()
	begins, commits, rollbacks := harness.backend.Lifecycle()
	if len(committed) != 1 || committed[0].Value != "once" || len(rolledBack) != 0 || active != 0 || executed["organization"] != 1 ||
		begins != 1 || commits != 1 || rollbacks != 0 {
		t.Fatalf("retained commit=%v rollback=%v active=%d executed=%v lifecycle=%d/%d/%d", committed, rolledBack, active, executed, begins, commits, rollbacks)
	}
}

func TestExternalOwnerNeverConsumedPortCannotStartInGoroutineAfterReturn(t *testing.T) {
	harness := newExternalHarness(t)
	captured := make(chan testowneradapter.CapturedOperation, 1)
	operation := harness.registered(t, "organization", testowneradapter.DeferredAdapter{Captured: captured}.Apply)
	template, contract := externalTemplate(t, "external_deferred", operation)
	coordinator, registry := externalCoordinator(t, harness, template)
	plan, err := contract.Bind(registry, testowneradapter.Command{Value: "must-not-stage"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Execute(context.Background(), plan); transaction.ErrorCodeOf(err) != transaction.CodeParticipantFailed {
		t.Fatalf("unconsumed callback error = %v", err)
	}
	deferred := <-captured
	late := make(chan error, 1)
	go func() { late <- deferred.Port.Execute(deferred.Context) }()
	if err := <-late; transaction.ErrorCodeOf(err) != transaction.CodeParticipantFailed {
		t.Fatalf("after-return first execution error = %v", err)
	}
	committed, rolledBack, active, executed := harness.backend.Snapshot()
	begins, commits, rollbacks := harness.backend.Lifecycle()
	if len(committed) != 0 || len(rolledBack) != 0 || active != 0 || executed["organization"] != 0 ||
		begins != 1 || commits != 0 || rollbacks != 1 {
		t.Fatalf("deferred commit=%v rollback=%v active=%d executed=%v lifecycle=%d/%d/%d", committed, rolledBack, active, executed, begins, commits, rollbacks)
	}
}

func TestExternalOwnerReturnWaitsForRunningBackendBeforeRollback(t *testing.T) {
	harness := newExternalHarness(t)
	backendEntered, releaseBackend := harness.backend.Block("running-after-owner-return")
	portResult := make(chan error, 1)
	ownerReturning := make(chan struct{})
	operation := harness.registered(t, "organization", func(ctx context.Context, port transaction.OperationPort[testowneradapter.Command], _ testowneradapter.Command) error {
		go func() { portResult <- port.Execute(ctx) }()
		<-backendEntered
		close(ownerReturning)
		return nil
	})
	template, contract := externalTemplate(t, "external_running_after_return", operation)
	coordinator, registry := externalCoordinator(t, harness, template)
	plan, err := contract.Bind(registry, testowneradapter.Command{Value: "running-after-owner-return"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	coordinatorResult := make(chan error, 1)
	go func() {
		_, executeErr := coordinator.Execute(context.Background(), plan)
		coordinatorResult <- executeErr
	}()
	awaitSignal(t, ownerReturning, "owner did not return while backend was running")

	select {
	case executeErr := <-coordinatorResult:
		t.Fatalf("coordinator reached rollback while backend was running: %v", executeErr)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case executeErr := <-portResult:
		t.Fatalf("port returned while backend was blocked: %v", executeErr)
	default:
	}
	committed, rolledBack, active, executed := harness.backend.Snapshot()
	begins, commits, rollbacks := harness.backend.Lifecycle()
	if len(committed) != 0 || len(rolledBack) != 0 || active != 1 || executed["organization"] != 1 ||
		begins != 1 || commits != 0 || rollbacks != 0 {
		t.Fatalf("premature lifecycle commit=%v rollback=%v active=%d executed=%v lifecycle=%d/%d/%d", committed, rolledBack, active, executed, begins, commits, rollbacks)
	}

	releaseBackend()
	if executeErr := <-portResult; transaction.ErrorCodeOf(executeErr) != transaction.CodeParticipantFailed {
		t.Fatalf("late port completion error = %v", executeErr)
	}
	if executeErr := <-coordinatorResult; transaction.ErrorCodeOf(executeErr) != transaction.CodeParticipantFailed {
		t.Fatalf("coordinator error = %v", executeErr)
	}
	committed, rolledBack, active, executed = harness.backend.Snapshot()
	begins, commits, rollbacks = harness.backend.Lifecycle()
	if len(committed) != 0 || len(rolledBack) != 1 || rolledBack[0].Value != "running-after-owner-return" ||
		active != 0 || executed["organization"] != 1 || begins != 1 || commits != 0 || rollbacks != 1 {
		t.Fatalf("completed lifecycle commit=%v rollback=%v active=%d executed=%v lifecycle=%d/%d/%d", committed, rolledBack, active, executed, begins, commits, rollbacks)
	}
}

func TestExternalOwnerCrossSessionAndCrossOwnerPortSubstitutionFailBeforeRepository(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		owners []string
	}{
		{name: "same owner overlapping sessions", owners: []string{"organization", "organization"}},
		{name: "different registered owners", owners: []string{"organization", "project"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newExternalHarness(t)
			arrivals := make(chan testowneradapter.Exchange, 2)
			adapter := testowneradapter.SwappingAdapter{Arrivals: arrivals}
			templates := make([]transaction.PlanTemplate, 2)
			contracts := make([]transaction.PlanContract[testowneradapter.Command], 2)
			for index := range 2 {
				operation := harness.registered(t, testCase.owners[index], adapter.Apply)
				templates[index], contracts[index] = externalTemplate(t, "external_swap_"+string(rune('a'+index)), operation)
			}
			coordinator, registry := externalCoordinator(t, harness, templates...)
			plans := make([]transaction.Plan, 2)
			for index := range 2 {
				var err error
				plans[index], err = contracts[index].Bind(registry, testowneradapter.Command{Value: "foreign"}, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			go func() {
				first := <-arrivals
				second := <-arrivals
				first.Peer <- second
				second.Peer <- first
			}()
			results := make(chan error, 2)
			for _, plan := range plans {
				plan := plan
				go func() { _, err := coordinator.Execute(context.Background(), plan); results <- err }()
			}
			for range 2 {
				if err := <-results; transaction.ErrorCodeOf(err) != transaction.CodeParticipantFailed {
					t.Fatalf("substitution error = %v", err)
				}
			}
			committed, rolledBack, active, executed := harness.backend.Snapshot()
			begins, commits, rollbacks := harness.backend.Lifecycle()
			if len(committed) != 0 || len(rolledBack) != 0 || active != 0 || executed["organization"] != 0 || executed["project"] != 0 ||
				begins != 2 || commits != 0 || rollbacks != 2 {
				t.Fatalf("substitution reached repository: commit=%v rollback=%v active=%d executed=%v lifecycle=%d/%d/%d", committed, rolledBack, active, executed, begins, commits, rollbacks)
			}
		})
	}
}

func awaitSignal(t testing.TB, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}
