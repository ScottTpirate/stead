package authorization

import (
	"context"
	"reflect"
	"sync"
	"time"
)

// EffectExecution can invoke one mutation callback, never a read, retry or
// arbitrary provider plan. Only the reviewed provider adapter should consume it;
// binding its exact private plan to this callback is that adapter's obligation.
// It carries no response-release or canonical-acceptance authority.
// The private pointer is intentional: even a value copy shares one claim,
// cancellation state and mutex, rather than cloning dispatch authority.
type EffectExecution struct{ *effectExecutionState }
type effectExecutionState struct {
	mu                                   sync.Mutex
	effects                              *Effects
	record                               EffectRecord
	request                              context.Context
	issueRequest, consumeRequest         context.Context
	call                                 context.Context
	cancel                               context.CancelFunc
	sessionID                            string
	committed, used, running, suppressed bool
}

func newEffectExecution(effects *Effects, issued *IssuedEffect, consumeRequest context.Context) *EffectExecution {
	original := issued.decision.effectUse.request
	call, cancel := context.WithDeadline(original, issued.record.ExpiresAt)
	execution := &EffectExecution{&effectExecutionState{effects: effects, record: issued.record, request: original,
		issueRequest: issued.request, consumeRequest: consumeRequest, call: call, cancel: cancel, sessionID: issued.record.Authorization.SessionID}}
	stopIssue := context.AfterFunc(issued.request, cancel)
	stopConsume := context.AfterFunc(consumeRequest, cancel)
	context.AfterFunc(call, func() {
		stopIssue()
		stopConsume()
		execution.Suppress()
	})
	return execution
}

func (execution *EffectExecution) requestsActive() bool {
	return execution.request != nil && execution.request.Err() == nil && execution.issueRequest != nil && execution.issueRequest.Err() == nil &&
		execution.consumeRequest != nil && execution.consumeRequest.Err() == nil
}

func (execution *EffectExecution) Record() EffectRecord {
	if execution == nil || execution.effectExecutionState == nil {
		return EffectRecord{}
	}
	execution.mu.Lock()
	defer execution.mu.Unlock()
	return execution.record
}

// Suppress stops the registered context and requires the consumer to discard
// every not-yet-released output. This signal does NOT prove transport/provider
// cancellation, terminal buffering, no effect, or safe revocation completion.
func (execution *EffectExecution) Suppress() {
	if execution == nil || execution.effectExecutionState == nil {
		return
	}
	execution.mu.Lock()
	execution.suppressed = true
	cancel := execution.cancel
	execution.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// SuppressionRequired is a deny signal only. False never grants disclosure.
func (execution *EffectExecution) SuppressionRequired() bool {
	if execution == nil || execution.effectExecutionState == nil {
		return true
	}
	execution.mu.Lock()
	defer execution.mu.Unlock()
	return execution.suppressed || !execution.committed || execution.record.State != EffectConsumed || execution.call == nil || execution.call.Err() != nil || !execution.requestsActive() || !execution.effects.currentProcess()
}

// Run's nil result means only that the one callback returned nil while its
// execution context remained valid. It is NOT terminal proof. The exact
// provider/transport receipt must be verified separately before terminalization.
// Provider results must stay private and withheld from canonical acceptance and
// caller disclosure until their independent authorization/fence checks pass.
func (execution *EffectExecution) Run(binding EffectBinding, dispatch func(context.Context) error) (err error) {
	if execution == nil || execution.effectExecutionState == nil {
		return ErrDenied
	}
	binding.OriginalDeadline = binding.OriginalDeadline.UTC()
	binding.ProviderNotAfter = binding.ProviderNotAfter.UTC()
	execution.mu.Lock()
	if execution.used || !execution.committed || execution.record.State != EffectConsumed || execution.suppressed || execution.call == nil || execution.call.Err() != nil || !execution.requestsActive() ||
		!execution.effects.currentProcess() || !reflect.DeepEqual(binding, execution.record.Binding) || dispatch == nil ||
		!execution.effects.clock().Before(execution.record.ExpiresAt) {
		execution.mu.Unlock()
		return ErrDenied
	}
	execution.used, execution.running = true, true
	call := execution.call
	execution.mu.Unlock()
	defer func() {
		if recover() != nil {
			err = ErrDenied
		}
		execution.mu.Lock()
		execution.running = false
		if execution.suppressed || call.Err() != nil || !execution.requestsActive() || !execution.effects.currentProcess() {
			err = ErrDenied
		}
		record := execution.record
		execution.mu.Unlock()
		if err != nil {
			execution.Suppress()
			// Cancellation must not prevent recording ambiguity. This is a
			// bounded, non-authorizing owner-state write, never an I/O retry.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = execution.effects.ReconcileLost(ctx, record)
			err = ErrDenied
		}
	}()
	if call.Err() != nil || !execution.requestsActive() {
		return ErrDenied
	}
	return dispatch(call)
}
