package transaction

import (
	"context"
	"sync/atomic"
	"testing"
)

type strictPortSpy struct {
	calls atomic.Int64
}

func (spy *strictPortSpy) RequireReady(context.Context, CommitBoundaryContext) error {
	spy.calls.Add(1)
	return nil
}

func (spy *strictPortSpy) Acquire(context.Context, CommitBoundaryContext) (ServingLease, error) {
	spy.calls.Add(1)
	return ServingLease{}, nil
}

func (spy *strictPortSpy) Release(context.Context, ServingLease) error {
	spy.calls.Add(1)
	return nil
}

func (spy *strictPortSpy) Register(_ context.Context, _ CommitBoundaryContext, _ ServingLease) (QuiescenceBarrier, error) {
	spy.calls.Add(1)
	return QuiescenceBarrier{}, nil
}

type strictGuardSpy struct{ calls *atomic.Int64 }

func (spy strictGuardSpy) Register(context.Context, CommitBoundaryContext, ServingLease) (BoundedReadGuard, error) {
	spy.calls.Add(1)
	return BoundedReadGuard{}, nil
}

func (spy *strictPortSpy) Hold(context.Context, CommitBoundaryContext, BoundedReadGuard) (DisclosureFenceSession, error) {
	spy.calls.Add(1)
	return DisclosureFenceSession{}, nil
}

func (spy *strictPortSpy) Suppress(context.Context, DisclosureFenceSession) error {
	spy.calls.Add(1)
	return nil
}

func (spy *strictPortSpy) Prove(context.Context, DisclosureFenceSession, QuiescenceBarrier) (TerminalProof, error) {
	spy.calls.Add(1)
	return TerminalProof{}, nil
}

func TestCommitBoundaryRemainsDenyOnlyWithoutFallback(t *testing.T) {
	spy := &strictPortSpy{}
	adapter := NewCommitBoundaryAdapter(CommitBoundaryPorts{
		ModeReadiness: spy,
		ServingLease:  spy,
		Quiescence:    spy,
		Guard:         strictGuardSpy{calls: &spy.calls},
		EgressFence:   spy,
		TerminalProof: spy,
	})
	response := &fakeBufferedResponse{}
	report, err := adapter.ReleaseProtected(context.Background(), testBoundRevision(t), response)
	if ErrorCodeOf(err) != CodeStrictUnavailable || report != (BoundaryReport{Suppressions: 1}) {
		t.Fatalf("error=%v report=%#v", err, report)
	}
	released, suppressed := response.counts()
	if released != 0 || suppressed != 1 || spy.calls.Load() != 0 {
		t.Fatalf("released=%d suppressed=%d strict-calls=%d", released, suppressed, spy.calls.Load())
	}

	noProvider := NewCommitBoundaryAdapter(CommitBoundaryPorts{})
	response = &fakeBufferedResponse{}
	if _, err := noProvider.ReleaseProtected(context.Background(), testBoundRevision(t), response); ErrorCodeOf(err) != CodeStrictUnavailable {
		t.Fatalf("no-provider strict result=%v", err)
	}
}

func TestRequestBoundaryNeverInvokesStrictPorts(t *testing.T) {
	spy := &strictPortSpy{}
	_ = CommitBoundaryPorts{ModeReadiness: spy, ServingLease: spy, Quiescence: spy, Guard: strictGuardSpy{calls: &spy.calls}, EgressFence: spy, TerminalProof: spy}
	rechecker := &fakeRechecker{behavior: recheckConfirm}
	rechecker.allowed.Store(true)
	adapter, _ := NewRequestBoundaryAdapter(rechecker)
	response := &fakeBufferedResponse{}
	if _, err := adapter.ReleaseProtected(context.Background(), testBoundRevision(t), response); err != nil {
		t.Fatal(err)
	}
	if spy.calls.Load() != 0 {
		t.Fatalf("request_boundary invoked %d strict operations", spy.calls.Load())
	}
}

var (
	_ ModeReadinessPort         = (*strictPortSpy)(nil)
	_ ServingLeasePort          = (*strictPortSpy)(nil)
	_ QuiescencePort            = (*strictPortSpy)(nil)
	_ BoundedReadGuardPort      = strictGuardSpy{}
	_ DisclosureEgressFencePort = (*strictPortSpy)(nil)
	_ TerminalProofPort         = (*strictPortSpy)(nil)
)
