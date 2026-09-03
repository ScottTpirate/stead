package transaction

import (
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

const (
	BoundRevisionHandoffV1  = "stead.core.bound-revision-handoff/v1"
	FinalAuthorizationOwner = "authorization.final-authorization-audit"
	finalReadTemplateKey    = "core.finalize_read.v1"
)

type revisionSeal struct{ marker byte }

type revisionState struct {
	seal     *revisionSeal
	version  string
	opaque   []byte
	digest   [sha256.Size]byte
	proof    proofLifecycle
	boundary atomic.Uint32
}

type revisionIssuerState struct {
	mu       sync.Mutex
	seal     *revisionSeal
	open     bool
	issued   *revisionState
	accepted bool
}

// BoundRevisionIssuer is supplied only during the registered WS-06 handoff.
// BindValidated wraps owner-validated opaque revision material; core does not
// parse principal, policy, tuple, label, provider, or fence semantics.
type BoundRevisionIssuer struct {
	state *revisionIssuerState
}

func newBoundRevisionIssuer() BoundRevisionIssuer {
	return BoundRevisionIssuer{state: &revisionIssuerState{seal: &revisionSeal{}, open: true}}
}

func (issuer BoundRevisionIssuer) BindValidated(version string, opaque []byte) (BoundRevision, error) {
	if issuer.state == nil || version != BoundRevisionHandoffV1 || len(opaque) == 0 {
		return BoundRevision{}, fail(CodeBoundaryDenied)
	}
	issuer.state.mu.Lock()
	defer issuer.state.mu.Unlock()
	if issuer.state.seal == nil || !issuer.state.open || issuer.state.issued != nil {
		return BoundRevision{}, fail(CodeBoundaryDenied)
	}
	value := append([]byte(nil), opaque...)
	state := &revisionState{
		seal:    issuer.state.seal,
		version: version,
		opaque:  value,
		digest:  sha256.Sum256(value),
	}
	issuer.state.issued = state
	return BoundRevision{state: state}, nil
}

func (issuer BoundRevisionIssuer) close() {
	if issuer.state == nil {
		return
	}
	issuer.state.mu.Lock()
	if !issuer.state.open {
		issuer.state.mu.Unlock()
		return
	}
	issuer.state.open = false
	issued := issuer.state.issued
	accepted := issuer.state.accepted
	issuer.state.mu.Unlock()
	if issued != nil && !accepted {
		issued.proof.invalidate()
	}
}

// accept seals the one exact value returned by this issuer for the surrounding
// transaction. It remains unusable until FinalizeRead activates it after a
// successful commit.
func (issuer BoundRevisionIssuer) accept(revision BoundRevision) bool {
	if issuer.state == nil || revision.state == nil {
		return false
	}
	issuer.state.mu.Lock()
	defer issuer.state.mu.Unlock()
	if issuer.state.seal == nil || !issuer.state.open || issuer.state.accepted ||
		issuer.state.issued != revision.state || !revision.validMaterial() ||
		!revision.state.proof.sealForCommit() {
		return false
	}
	issuer.state.accepted = true
	return true
}

// BoundRevision is an opaque, immutable, single-use response-boundary input.
// The zero value, a value from another issuer, a modified value, and a reused
// value all deny.
type BoundRevision struct {
	state *revisionState
}

func (revision BoundRevision) HandoffVersion() string {
	if revision.state == nil {
		return ""
	}
	return revision.state.version
}

func (revision BoundRevision) Digest() [sha256.Size]byte {
	if revision.state == nil {
		return [sha256.Size]byte{}
	}
	return revision.state.digest
}

func (revision BoundRevision) OpaqueCopy() []byte {
	if revision.state == nil {
		return nil
	}
	return append([]byte(nil), revision.state.opaque...)
}

func (revision BoundRevision) validMaterial() bool {
	return revision.state != nil && revision.state.seal != nil && revision.state.version == BoundRevisionHandoffV1 &&
		len(revision.state.opaque) != 0 && sha256.Sum256(revision.state.opaque) == revision.state.digest
}

func (revision BoundRevision) verify() bool {
	return revision.validMaterial() && revision.state.proof.isActive()
}

func (revision BoundRevision) activate() bool {
	return revision.validMaterial() && revision.state.proof.activate()
}

func (revision BoundRevision) invalidate() {
	if revision.state != nil {
		revision.state.proof.invalidate()
	}
}

type FinalAuthorizationAuditResult struct {
	Revision BoundRevision
	Intent   *outbox.ValidatedIntent
}

// FinalAuthorizationAuditPort is the one logical WS-06/WS-07 handoff for a
// finite composed read. Implementations may return zero or one aggregate
// validated intent, never a list or a per-row callback.
type FinalAuthorizationAuditPort interface {
	Finalize(context.Context, OperationPort[*FinalAuthorizationAuditOperation], BoundRevisionIssuer) (FinalAuthorizationAuditResult, error)
}

// FinalAuthorizationAuditOperation is an opaque invocation identity used only
// to type the registration-bound repository port. Its result is private to the
// coordinator and cannot be supplied or changed by the backend executor.
type FinalAuthorizationAuditOperation struct {
	result FinalAuthorizationAuditResult
}

func (invocation *FinalAuthorizationAuditOperation) intent() *outbox.ValidatedIntent {
	if invocation == nil {
		return nil
	}
	return invocation.result.Intent
}

func (coordinator *Coordinator) finalizeReadParticipant(ctx context.Context, port OperationPort[*FinalAuthorizationAuditOperation], invocation *FinalAuthorizationAuditOperation) error {
	if coordinator == nil || isNil(coordinator.finalAuthorizationAudit) || invocation == nil {
		return fail(CodeBoundaryDenied)
	}
	issuer := newBoundRevisionIssuer()
	defer issuer.close()
	result, err := coordinator.finalAuthorizationAudit.Finalize(ctx, port, issuer)
	if err != nil {
		return fail(CodeBoundaryDenied)
	}
	if result.Intent != nil {
		if err := result.Intent.Verify(); err != nil {
			return fail(CodeOutboxFailed)
		}
		intent := *result.Intent
		result.Intent = &intent
	}
	if !issuer.accept(result.Revision) {
		return fail(CodeBoundaryDenied)
	}
	invocation.result = result
	return nil
}

// FinalizeRead invokes the registered final logical operation once, then the
// predeclared outbox slot, then commit. The bound revision is returned only
// after commit succeeds.
func (coordinator *Coordinator) FinalizeRead(ctx context.Context) (BoundRevision, Report, error) {
	if coordinator == nil || isNil(coordinator.finalAuthorizationAudit) {
		return BoundRevision{}, Report{}, fail(CodeBoundaryDenied)
	}
	invocation := &FinalAuthorizationAuditOperation{}
	activated := false
	defer func() {
		if !activated {
			invocation.result.Revision.invalidate()
		}
	}()
	plan, err := coordinator.finalReadContract.bindCoordinatorOwned(coordinator.registry, invocation, func(value *FinalAuthorizationAuditOperation) *outbox.ValidatedIntent {
		return value.intent()
	})
	if err != nil {
		return BoundRevision{}, Report{}, fail(CodeBoundaryDenied)
	}
	report, err := coordinator.Execute(ctx, plan)
	if err != nil {
		return BoundRevision{}, report, err
	}
	if !invocation.result.Revision.activate() || !invocation.result.Revision.verify() {
		return BoundRevision{}, report, fail(CodeBoundaryDenied)
	}
	activated = true
	return invocation.result.Revision, report, nil
}

const (
	boundaryFresh uint32 = iota
	boundaryChecking
	boundaryReleased
	boundarySuppressed
)

type recheckSeal struct{ marker byte }

type recheckIssuerState struct {
	seal     *recheckSeal
	revision *revisionState
	active   atomic.Bool
}

// RecheckIssuer can confirm only the exact bound revision passed to the
// current recheck call. It has no allow/deny boolean and expires on return.
type RecheckIssuer struct {
	state *recheckIssuerState
}

func newRecheckIssuer(revision BoundRevision) RecheckIssuer {
	state := &recheckIssuerState{seal: &recheckSeal{}, revision: revision.state}
	state.active.Store(true)
	return RecheckIssuer{state: state}
}

func (issuer RecheckIssuer) Confirm(revision BoundRevision) (RecheckReceipt, error) {
	if issuer.state == nil || issuer.state.seal == nil || !issuer.state.active.Load() ||
		!revision.verify() || revision.state != issuer.state.revision {
		return RecheckReceipt{}, fail(CodeBoundaryDenied)
	}
	return RecheckReceipt{
		seal:     issuer.state.seal,
		revision: revision.state,
		digest:   revision.state.digest,
	}, nil
}

func (issuer RecheckIssuer) close() {
	if issuer.state != nil {
		issuer.state.active.Store(false)
	}
}

type RecheckReceipt struct {
	seal     *recheckSeal
	revision *revisionState
	digest   [sha256.Size]byte
}

func (receipt RecheckReceipt) validFor(issuer RecheckIssuer, revision BoundRevision) bool {
	return receipt.seal != nil && issuer.state != nil && receipt.seal == issuer.state.seal &&
		receipt.revision == revision.state && receipt.digest == revision.state.digest
}

// RevisionRechecker is implemented by the WS-06 integration adapter. Changed,
// pending, missing, malformed, stale, or unverifiable authoritative state must
// return an error or no receipt; all such results collapse to one safe denial.
type RevisionRechecker interface {
	Recheck(context.Context, BoundRevision, RecheckIssuer) (RecheckReceipt, error)
}

// BufferedProtectedResponse owns a fully buffered finite response. Release is
// the atomic handoff that commits headers/first protected byte; no caller may
// invoke it before RequestBoundaryAdapter does. Suppress must discard it.
type BufferedProtectedResponse interface {
	Release(context.Context) error
	Suppress()
}

type BoundaryReport struct {
	RecheckCalls uint64
	ReleaseCalls uint64
	Suppressions uint64
	Retries      uint64
}

type RequestBoundaryAdapter struct {
	rechecker RevisionRechecker
}

func NewRequestBoundaryAdapter(rechecker RevisionRechecker) (*RequestBoundaryAdapter, error) {
	if isNil(rechecker) {
		return nil, fail(CodeInvalidContract)
	}
	return &RequestBoundaryAdapter{rechecker: rechecker}, nil
}

func (adapter *RequestBoundaryAdapter) ReleaseProtected(ctx context.Context, revision BoundRevision, response BufferedProtectedResponse) (report BoundaryReport, resultErr error) {
	claimed := false
	suppress := func() {
		report.Suppressions++
		if !isNil(response) {
			safeSuppress(response)
		}
		if claimed && revision.state != nil {
			revision.state.boundary.CompareAndSwap(boundaryChecking, boundarySuppressed)
		}
	}
	if adapter == nil || isNil(adapter.rechecker) || isNil(response) || !revision.verify() {
		suppress()
		return report, fail(CodeBoundaryDenied)
	}
	if !revision.state.boundary.CompareAndSwap(boundaryFresh, boundaryChecking) {
		suppress()
		return report, fail(CodeBoundaryDenied)
	}
	claimed = true
	if err := contextFailure(ctx); err != nil {
		suppress()
		return report, fail(CodeBoundaryDenied)
	}

	issuer := newRecheckIssuer(revision)
	report.RecheckCalls++
	receipt, err := safeRecheck(ctx, adapter.rechecker, revision, issuer)
	issuer.close()
	if err != nil || !receipt.validFor(issuer, revision) {
		suppress()
		return report, fail(CodeBoundaryDenied)
	}
	if err := contextFailure(ctx); err != nil {
		suppress()
		return report, fail(CodeBoundaryDenied)
	}

	report.ReleaseCalls++
	if err := safeRelease(ctx, response); err != nil {
		suppress()
		return report, fail(CodeBoundaryDenied)
	}
	revision.state.boundary.Store(boundaryReleased)
	return report, nil
}

func safeRecheck(ctx context.Context, rechecker RevisionRechecker, revision BoundRevision, issuer RecheckIssuer) (receipt RecheckReceipt, err error) {
	defer func() {
		if recover() != nil {
			receipt = RecheckReceipt{}
			err = fail(CodeBoundaryDenied)
		}
	}()
	return rechecker.Recheck(ctx, revision, issuer)
}

func safeRelease(ctx context.Context, response BufferedProtectedResponse) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeBoundaryDenied)
		}
	}()
	return response.Release(ctx)
}

func safeSuppress(response BufferedProtectedResponse) {
	defer func() {
		_ = recover()
	}()
	response.Suppress()
}
