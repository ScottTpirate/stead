package transaction

import (
	"context"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

type benchmarkBackend struct{}
type benchmarkSession struct{}

func (benchmarkBackend) Begin(context.Context) (Session, error) { return benchmarkSession{}, nil }
func (benchmarkSession) Commit(context.Context) error           { return nil }
func (benchmarkSession) Rollback(context.Context) error         { return nil }

type benchmarkAppender struct{}

func (benchmarkAppender) Append(_ context.Context, scope outbox.TransactionScope, intent outbox.ValidatedIntent) error {
	if err := scope.Verify(); err != nil {
		return err
	}
	return intent.Verify()
}

type benchmarkFinalizer struct{}

func (benchmarkFinalizer) Finalize(_ context.Context, capability OwnerCapability, issuer BoundRevisionIssuer) (FinalAuthorizationAuditResult, error) {
	if !capability.ValidFor(FinalAuthorizationOwner) {
		return FinalAuthorizationAuditResult{}, errInjected
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

func benchmarkRegistry(b testing.TB) Registry {
	b.Helper()
	template := PlanTemplate{
		ContractVersion: ContractVersionV1,
		Key:             "benchmark_operation",
		OutboxPolicy:    OutboxRequired,
		Participants: []ParticipantTemplate{
			{Key: "authorization", Owner: "authorization", DeclaresWrite: true, Operation: func(_ context.Context, capability OwnerCapability) error {
				if !capability.ValidFor("authorization") {
					return errInjected
				}
				return nil
			}},
			{Key: "domain", Owner: "domain", After: []string{"authorization"}, DeclaresWrite: true, Operation: func(_ context.Context, capability OwnerCapability) error {
				if !capability.ValidFor("domain") {
					return errInjected
				}
				return nil
			}},
		},
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		b.Fatal(err)
	}
	return registry
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
	registry := benchmarkRegistry(b)
	coordinator := benchmarkCoordinator(b, registry, nil)
	intent := testIntent()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		plan, err := registry.Bind("benchmark_operation", &intent)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := coordinator.Execute(context.Background(), plan); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFinalizeReadNoIntent(b *testing.B) {
	registry := benchmarkRegistry(b)
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
