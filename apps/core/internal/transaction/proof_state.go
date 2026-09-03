package transaction

import "sync/atomic"

const (
	proofProvisional uint32 = iota
	proofPendingCommit
	proofActive
	proofInvalid
)

// proofLifecycle keeps an owner-minted value provisional until the exact
// coordinator execution that accepted it commits. Copies of a public proof
// share the containing state and therefore share this lifecycle.
type proofLifecycle struct {
	state atomic.Uint32
}

func (lifecycle *proofLifecycle) sealForCommit() bool {
	return lifecycle != nil && lifecycle.state.CompareAndSwap(proofProvisional, proofPendingCommit)
}

func (lifecycle *proofLifecycle) activate() bool {
	return lifecycle != nil && lifecycle.state.CompareAndSwap(proofPendingCommit, proofActive)
}

func (lifecycle *proofLifecycle) isActive() bool {
	return lifecycle != nil && lifecycle.state.Load() == proofActive
}

func (lifecycle *proofLifecycle) invalidate() {
	if lifecycle == nil {
		return
	}
	for {
		switch state := lifecycle.state.Load(); state {
		case proofInvalid:
			return
		default:
			if lifecycle.state.CompareAndSwap(state, proofInvalid) {
				return
			}
		}
	}
}
