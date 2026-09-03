package transaction

import "context"

// CommitBoundaryContext is an opaque carrier reserved for the later complete
// strict runtime. It is not persisted and exposes no request-selected mode,
// label, policy, role, buffer, epoch, or proof constructor in this slice.
type CommitBoundaryContext struct {
	seal *strictSeal
}

type strictSeal struct{ marker byte }

type ServingLease struct{ seal *strictSeal }
type QuiescenceBarrier struct{ seal *strictSeal }
type BoundedReadGuard struct{ seal *strictSeal }
type DisclosureFenceSession struct{ seal *strictSeal }
type TerminalProof struct{ seal *strictSeal }

// These ports preserve the accepted ADR-0005 commit-boundary vocabulary and
// ownership seam without supplying the later high-assurance implementation.
type ModeReadinessPort interface {
	RequireReady(context.Context, CommitBoundaryContext) error
}

type ServingLeasePort interface {
	Acquire(context.Context, CommitBoundaryContext) (ServingLease, error)
	Release(context.Context, ServingLease) error
}

type QuiescencePort interface {
	Register(context.Context, CommitBoundaryContext, ServingLease) (QuiescenceBarrier, error)
}

type BoundedReadGuardPort interface {
	Register(context.Context, CommitBoundaryContext, ServingLease) (BoundedReadGuard, error)
}

type DisclosureEgressFencePort interface {
	Hold(context.Context, CommitBoundaryContext, BoundedReadGuard) (DisclosureFenceSession, error)
	Suppress(context.Context, DisclosureFenceSession) error
}

type TerminalProofPort interface {
	Prove(context.Context, DisclosureFenceSession, QuiescenceBarrier) (TerminalProof, error)
}

type CommitBoundaryPorts struct {
	ModeReadiness ModeReadinessPort
	ServingLease  ServingLeasePort
	Quiescence    QuiescencePort
	Guard         BoundedReadGuardPort
	EgressFence   DisclosureEgressFencePort
	TerminalProof TerminalProofPort
}

// CommitBoundaryAdapter is deliberately deny-only in this Phase 1 slice. Even
// a syntactically complete port bundle cannot activate strict mode until the
// separately gated runtime, transport, recovery, and performance evidence is
// implemented. It never falls back to RequestBoundaryAdapter.
type CommitBoundaryAdapter struct {
	ports CommitBoundaryPorts
}

func NewCommitBoundaryAdapter(ports CommitBoundaryPorts) *CommitBoundaryAdapter {
	return &CommitBoundaryAdapter{ports: ports}
}

func (adapter *CommitBoundaryAdapter) ReleaseProtected(_ context.Context, _ BoundRevision, response BufferedProtectedResponse) (BoundaryReport, error) {
	report := BoundaryReport{Suppressions: 1}
	if !isNil(response) {
		safeSuppress(response)
	}
	return report, fail(CodeStrictUnavailable)
}
