package transaction

import (
	"context"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

type benchmarkBackend struct{}
type benchmarkSession struct{}

func (benchmarkBackend) Begin(context.Context) (Session, error) { return &benchmarkSession{}, nil }
func (*benchmarkSession) Commit(context.Context) error          { return nil }
func (*benchmarkSession) Rollback(context.Context) error        { return nil }

type benchmarkAppender struct{}

func (benchmarkAppender) Append(_ context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	return scope.Use(func(binding SessionBinding) (BindingReceipt, error) {
		return binding.Use(intent.Verify)
	})
}

type benchmarkFinalizer struct{}

func (benchmarkFinalizer) Finalize(_ context.Context, binding SessionBinding, issuer BoundRevisionIssuer) (result FinalAuthorizationAuditResult, resultErr error) {
	var receipt BindingReceipt
	receipt, resultErr = binding.Use(func() error {
		revision, err := issuer.BindValidated(BoundRevisionHandoffV1, []byte("benchmark-revision"))
		result = FinalAuthorizationAuditResult{Revision: revision}
		return err
	})
	result.Binding = receipt
	return result, resultErr
}

type benchmarkRechecker struct{}

func (benchmarkRechecker) Recheck(_ context.Context, revision BoundRevision, issuer RecheckIssuer) (RecheckReceipt, error) {
	return issuer.Confirm(revision)
}

type benchmarkResponse struct{}

func (benchmarkResponse) Release(context.Context) error { return nil }
func (benchmarkResponse) Suppress()                     {}

func benchmarkRegistry(b testing.TB) (Registry, PlanContract[struct{}]) {
	b.Helper()
	template, contract, err := NewPlanContract(
		ContractVersionV1,
		"benchmark_operation",
		[]TypedParticipant[struct{}]{
			{Key: "authorization", Owner: "authorization", DeclaresWrite: true, Operation: func(_ context.Context, binding SessionBinding, _ struct{}) (BindingReceipt, error) {
				return binding.Use(func() error { return nil })
			}},
			{Key: "domain", Owner: "domain", After: []string{"authorization"}, DeclaresWrite: true, Operation: func(_ context.Context, binding SessionBinding, _ struct{}) (BindingReceipt, error) {
				return binding.Use(func() error { return nil })
			}},
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
	return registry, contract
}

func benchmarkCoordinator(b testing.TB, registry Registry, finalizer FinalAuthorizationAuditPort) *Coordinator {
	b.Helper()
	coordinator, err := NewCoordinator(Configuration{
		Backend:                 benchmarkBackend{},
		Registry:                registry,
		Outbox:                  benchmarkAppender{},
		FinalAuthorizationAudit: finalizer,
	})
	if err != nil {
		b.Fatal(err)
	}
	return coordinator
}

func BenchmarkExecuteClosedPlan(b *testing.B) {
	registry, contract := benchmarkRegistry(b)
	coordinator := benchmarkCoordinator(b, registry, nil)
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

func BenchmarkFinalizeReadNoIntent(b *testing.B) {
	registry, _ := benchmarkRegistry(b)
	coordinator := benchmarkCoordinator(b, registry, benchmarkFinalizer{})
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
		issuer.close()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := adapter.ReleaseProtected(context.Background(), revision, benchmarkResponse{}); err != nil {
			b.Fatal(err)
		}
	}
}
