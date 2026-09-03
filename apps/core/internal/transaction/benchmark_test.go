package transaction

import (
	"context"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

type benchmarkBackend struct{}
type benchmarkSession struct{}

func (benchmarkBackend) Begin(context.Context) (Session, ExecutorBinding, error) {
	session := &benchmarkSession{}
	binding, err := NewExecutorBinding(session)
	return session, binding, err
}
func (*benchmarkSession) Commit(context.Context) error   { return nil }
func (*benchmarkSession) Rollback(context.Context) error { return nil }

type benchmarkAppender struct{}

func (benchmarkAppender) Append(_ context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	return scope.Use(func(binding SessionBinding) (BindingReceipt, error) {
		return binding.Use(intent.Verify)
	})
}

type benchmarkFinalizer struct{}

func (benchmarkFinalizer) Finalize(ctx context.Context, port OperationPort[*FinalAuthorizationAuditOperation], issuer BoundRevisionIssuer) (FinalAuthorizationAuditResult, error) {
	if err := port.Execute(ctx); err != nil {
		return FinalAuthorizationAuditResult{}, err
	}
	revision, err := issuer.BindValidated(BoundRevisionHandoffV1, []byte("benchmark-revision"))
	return FinalAuthorizationAuditResult{Revision: revision}, err
}

type benchmarkRechecker struct{}

func (benchmarkRechecker) Recheck(_ context.Context, revision BoundRevision, issuer RecheckIssuer) (RecheckReceipt, error) {
	return issuer.Confirm(revision)
}

type benchmarkResponse struct{}

func (benchmarkResponse) Release(context.Context) error { return nil }
func (benchmarkResponse) Suppress()                     {}

type benchmarkReferenceInvocation struct {
	ResourceID string
	Items      []string
	Attributes map[string]string
}

func benchmarkRegistry(b testing.TB) (BackendContract, Registry, PlanContract[struct{}]) {
	b.Helper()
	backend, err := NewBackendContract(benchmarkBackend{})
	if err != nil {
		b.Fatal(err)
	}
	operation := func(owner string) RegisteredOperation[struct{}] {
		backendOperation, err := NewBackendOperation(backend, owner, func(context.Context, ExecutorBinding, struct{}) error { return nil })
		if err != nil {
			b.Fatal(err)
		}
		registered, err := NewRegisteredOperation(backendOperation, func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error { return port.Execute(ctx) })
		if err != nil {
			b.Fatal(err)
		}
		return registered
	}
	template, contract, err := NewPlanContract(
		ContractVersionV1,
		"benchmark_operation",
		[]TypedParticipant[struct{}]{
			{Key: "authorization", DeclaresWrite: true, Operation: operation("authorization")},
			{Key: "domain", After: []string{"authorization"}, DeclaresWrite: true, Operation: operation("domain")},
		},
		OutboxRequired,
	)
	if err != nil {
		b.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		b.Fatal(err)
	}
	return backend, registry, contract
}

func benchmarkCoordinator(b testing.TB, backend BackendContract, registry Registry, finalizer FinalAuthorizationAuditPort) *Coordinator {
	b.Helper()
	var finalOperation BackendOperation[*FinalAuthorizationAuditOperation]
	if !isNil(finalizer) {
		finalOperation, _ = NewBackendOperation(backend, FinalAuthorizationOwner, func(context.Context, ExecutorBinding, *FinalAuthorizationAuditOperation) error { return nil })
	}
	coordinator, err := NewCoordinator(Configuration{
		Backend:                     backend,
		Registry:                    registry,
		Outbox:                      benchmarkAppender{},
		FinalAuthorizationAudit:     finalizer,
		FinalAuthorizationOperation: finalOperation,
	})
	if err != nil {
		b.Fatal(err)
	}
	return coordinator
}

func BenchmarkExecuteClosedPlan(b *testing.B) {
	backend, registry, contract := benchmarkRegistry(b)
	coordinator := benchmarkCoordinator(b, backend, registry, nil)
	intent := testIntent()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		plan, err := contract.Bind(registry, struct{}{}, &intent)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := coordinator.Execute(context.Background(), plan); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExecuteReferenceSnapshotPlan(b *testing.B) {
	backendValue := benchmarkBackend{}
	backend, err := NewBackendContract(backendValue)
	if err != nil {
		b.Fatal(err)
	}
	operation := func(owner string) RegisteredOperation[*benchmarkReferenceInvocation] {
		backendOperation, err := NewBackendOperation(backend, owner, func(context.Context, ExecutorBinding, *benchmarkReferenceInvocation) error { return nil })
		if err != nil {
			b.Fatal(err)
		}
		registered, err := NewRegisteredOperation(backendOperation, func(ctx context.Context, port OperationPort[*benchmarkReferenceInvocation], _ *benchmarkReferenceInvocation) error {
			return port.Execute(ctx)
		})
		if err != nil {
			b.Fatal(err)
		}
		return registered
	}
	template, contract, err := NewPlanContract(
		ContractVersionV1,
		"benchmark_reference_snapshot",
		[]TypedParticipant[*benchmarkReferenceInvocation]{
			{Key: "authorization", DeclaresWrite: true, Operation: operation("authorization")},
			{Key: "domain", After: []string{"authorization"}, DeclaresWrite: true, Operation: operation("domain")},
		},
		OutboxRequired,
	)
	if err != nil {
		b.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		b.Fatal(err)
	}
	coordinator := benchmarkCoordinator(b, backend, registry, nil)
	intent := testIntent()
	invocation := &benchmarkReferenceInvocation{
		ResourceID: "stead:workitem:01JTESTREFERENCE000000000001",
		Items:      []string{"first", "second", "third"},
		Attributes: map[string]string{"scope": "project", "version": "7"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		plan, err := contract.Bind(registry, invocation, &intent)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := coordinator.Execute(context.Background(), plan); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFinalizeReadNoIntent(b *testing.B) {
	backend, registry, _ := benchmarkRegistry(b)
	coordinator := benchmarkCoordinator(b, backend, registry, benchmarkFinalizer{})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := coordinator.FinalizeRead(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRequestBoundaryRecheck(b *testing.B) {
	adapter, err := NewRequestBoundaryAdapter(benchmarkRechecker{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		issuer := newBoundRevisionIssuer()
		revision, err := issuer.BindValidated(BoundRevisionHandoffV1, []byte("benchmark-revision"))
		if err != nil {
			b.Fatal(err)
		}
		if !issuer.accept(revision) {
			b.Fatal("benchmark revision acceptance failed")
		}
		issuer.close()
		if !revision.activate() {
			b.Fatal("benchmark revision activation failed")
		}
		if _, err := adapter.ReleaseProtected(context.Background(), revision, benchmarkResponse{}); err != nil {
			b.Fatal(err)
		}
	}
}
