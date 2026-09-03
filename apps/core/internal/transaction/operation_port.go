package transaction

import (
	"context"
	"sync/atomic"
)

type beginPairSeal struct{ marker byte }
type executorBindingSeal struct{ marker byte }

const (
	beginPairMarker       byte = 0xb4
	executorBindingMarker byte = 0xa7
)

type beginPairState struct {
	session  Session
	consumed atomic.Bool
	seal     beginPairSeal
	executor executorBindingState
}

type executorBindingState struct {
	seal executorBindingSeal
}

// BeginResult is the opaque, single-use result returned by a trusted WS-02
// Backend. It keeps the lifecycle Session and executor identity in separate
// private halves joined by one package-minted pair identity. The coordinator
// alone consumes it; it exposes no session, binding, resolver, or lifecycle
// method.
type BeginResult struct {
	state   *beginPairState
	binding ExecutorBinding
}

// ExecutorBinding is the opaque per-transaction storage binding delivered to
// registered backend operations. It is only a comparable identity: it contains
// no caller-supplied payload and exposes no resolver, session, commit, or
// rollback authority. The trusted backend adapter keeps its own private mapping
// from this identity to storage state and expires that mapping with Session.
type ExecutorBinding struct {
	state *executorBindingState
}

// NewBeginResult mints one opaque result for a non-nil lifecycle Session and
// returns the matching executor identity for the trusted backend's private
// identity-to-session journal. The Session itself may have any dynamic shape;
// it is retained behind a pointer and is never compared. Backend.Begin returns
// the result while keeping only its already-owned Session and the identity.
func NewBeginResult(session Session) (BeginResult, ExecutorBinding, error) {
	if isNil(session) {
		return BeginResult{}, ExecutorBinding{}, fail(CodeInvalidContract)
	}
	pair := &beginPairState{
		session:  session,
		seal:     beginPairSeal{marker: beginPairMarker},
		executor: executorBindingState{seal: executorBindingSeal{marker: executorBindingMarker}},
	}
	binding := ExecutorBinding{state: &pair.executor}
	return BeginResult{
		state:   pair,
		binding: binding,
	}, binding, nil
}

// consume is the only transition from a backend result into coordinator-owned
// execution state. It returns a valid lifecycle Session even when the binding
// half is missing, mismatched, or already consumed so the coordinator can
// perform exactly one fail-closed rollback. It never compares Session values.
func (result BeginResult) consume() (Session, ExecutorBinding, *beginPairState, bool) {
	pair := result.state
	if pair == nil || pair.seal.marker != beginPairMarker || isNil(pair.session) {
		return nil, ExecutorBinding{}, nil, false
	}
	if !result.binding.matches(pair) || !pair.consumed.CompareAndSwap(false, true) {
		return pair.session, ExecutorBinding{}, nil, false
	}
	return pair.session, result.binding, pair, true
}

func (binding ExecutorBinding) valid() bool {
	return binding.state != nil && binding.state.seal.marker == executorBindingMarker
}

func (binding ExecutorBinding) matches(pair *beginPairState) bool {
	return binding.valid() && pair != nil && pair.seal.marker == beginPairMarker && binding.state == &pair.executor
}

func (binding ExecutorBinding) validFor(pair *beginPairState) bool {
	return binding.matches(pair) && pair.consumed.Load()
}

// BackendContract is the opaque authority for one lifecycle backend. It is
// minted once at server startup and binds every registered owner operation,
// registry, Begin session, and coordinator that may participate together.
// It exposes neither the backend nor a session to an owner package.
type BackendContract struct {
	seal    *backendSeal
	backend Backend
}

type backendSeal struct{ marker byte }

func NewBackendContract(backend Backend) (BackendContract, error) {
	if isNil(backend) {
		return BackendContract{}, fail(CodeInvalidContract)
	}
	return BackendContract{seal: &backendSeal{}, backend: backend}, nil
}

type backendOperationSeal struct{ marker byte }

type backendOperationDefinition[T any] struct {
	backend *backendSeal
	seal    *backendOperationSeal
	owner   string
	execute func(context.Context, ExecutorBinding, T) error
}

// BackendOperation is a startup-only, fixed-owner repository operation. The
// trusted WS-02 integration constructs it; request and owner code receive only
// the OperationPort minted from it after Begin.
type BackendOperation[T any] struct {
	definition *backendOperationDefinition[T]
}

// NewBackendOperation binds one typed repository operation to one backend and
// owner. The executor belongs at the trusted storage integration boundary and
// receives only the non-lifecycle binding minted beside BeginResult for the
// backend's private journal. Domain owner adapters consume RegisteredOperation
// instead.
func NewBackendOperation[T any](contract BackendContract, owner string, execute func(context.Context, ExecutorBinding, T) error) (BackendOperation[T], error) {
	if contract.seal == nil || isNil(contract.backend) || !identifierPattern.MatchString(owner) || execute == nil || owner == "core_outbox" {
		return BackendOperation[T]{}, fail(CodeInvalidContract)
	}
	return BackendOperation[T]{definition: &backendOperationDefinition[T]{
		backend: contract.seal,
		seal:    &backendOperationSeal{},
		owner:   owner,
		execute: execute,
	}}, nil
}

type registeredOperationDefinition[T any] struct {
	backend   *backendSeal
	operation *backendOperationSeal
	owner     string
	execute   func(context.Context, ExecutorBinding, T) error
	invoke    func(context.Context, OperationPort[T], T) error
}

// RegisteredOperation closes a fixed backend operation over one owner-authored
// typed adapter. It has no request-time owner, executor, or session input.
type RegisteredOperation[T any] struct {
	definition *registeredOperationDefinition[T]
}

func NewRegisteredOperation[T any](operation BackendOperation[T], invoke func(context.Context, OperationPort[T], T) error) (RegisteredOperation[T], error) {
	definition := operation.definition
	if definition == nil || definition.backend == nil || definition.seal == nil ||
		!identifierPattern.MatchString(definition.owner) || definition.execute == nil || invoke == nil {
		return RegisteredOperation[T]{}, fail(CodeInvalidContract)
	}
	return RegisteredOperation[T]{definition: &registeredOperationDefinition[T]{
		backend:   definition.backend,
		operation: definition.seal,
		owner:     definition.owner,
		execute:   definition.execute,
		invoke:    invoke,
	}}, nil
}

const (
	operationFresh uint32 = iota
	operationRunning
	operationConsumed
	operationFailed
	operationClosing
	operationClosed
)

type operationCallSeal struct{ marker byte }
type operationContextKey struct{}

type operationPortState[T any] struct {
	session           *sessionState
	backend           *backendSeal
	operation         *backendOperationSeal
	owner             string
	backendInvocation T
	execute           func(context.Context, ExecutorBinding, T) error
	call              *operationCallSeal
	context           context.Context
	done              chan struct{}
	state             atomic.Uint32
}

// OperationPort is the only capability delivered to an owner adapter. It is
// bound to the exact Begin-created session, backend, registered operation,
// owner, invocation, and synchronous adapter call. It exposes no lifecycle,
// SQL, role, transaction, or validity method.
type OperationPort[T any] struct {
	state *operationPortState[T]
}

// Execute synchronously invokes only the repository operation fixed during
// registration. The invocation, owner, session, and execution context cannot
// be supplied or replaced by the caller. Only the exact coordinator-created
// call context is accepted; derived contexts cannot remove its cancellation,
// deadline, or trusted values. Copied, swapped, concurrent, retained, and late
// ports fail before the backend executor runs.
func (port OperationPort[T]) Execute(ctx context.Context) error {
	state := port.state
	if state == nil || state.session == nil || state.backend == nil || state.operation == nil ||
		state.execute == nil || state.call == nil || state.context == nil || state.done == nil || ctx == nil ||
		ctx != state.context || state.context.Err() != nil || state.context.Value(operationContextKey{}) != state.call ||
		state.session.backend != state.backend ||
		state.session.registry == nil || state.session.plan == nil || !state.session.binding.validFor(state.session.begin) || !state.session.active.Load() ||
		state.session.plan.state.Load() != planRunning ||
		!state.state.CompareAndSwap(operationFresh, operationRunning) {
		return fail(CodeParticipantFailed)
	}

	err := safeBackendOperation(state.context, state.execute, state.session.binding, state.backendInvocation)
	completed := operationConsumed
	if err != nil {
		completed = operationFailed
	}
	if state.state.CompareAndSwap(operationRunning, uint32(completed)) {
		close(state.done)
		if err != nil {
			return fail(CodeParticipantFailed)
		}
		return nil
	}

	// The owner invocation returned before the backend executor completed.
	// RegisteredOperation.run seals the call as closing and waits on done before
	// allowing rollback. A late completion is never reported as success.
	state.state.CompareAndSwap(operationClosing, operationClosed)
	close(state.done)
	if err != nil {
		return fail(CodeParticipantFailed)
	}
	return fail(CodeParticipantFailed)
}

func (operation RegisteredOperation[T]) run(ctx context.Context, session *sessionState, ownerInvocation, backendInvocation T) error {
	definition := operation.definition
	if definition == nil || definition.backend == nil || definition.operation == nil ||
		definition.execute == nil || definition.invoke == nil || session == nil ||
		session.backend != definition.backend {
		return fail(CodeParticipantFailed)
	}
	call := &operationCallSeal{}
	callContext := context.WithValue(ctx, operationContextKey{}, call)
	state := &operationPortState[T]{
		session:           session,
		backend:           definition.backend,
		operation:         definition.operation,
		owner:             definition.owner,
		backendInvocation: backendInvocation,
		execute:           definition.execute,
		call:              call,
		context:           callContext,
		done:              make(chan struct{}),
	}
	port := OperationPort[T]{state: state}
	err := safeOwnerOperation(callContext, definition.invoke, port, ownerInvocation)
	for {
		switch state.state.Load() {
		case operationFresh:
			if state.state.CompareAndSwap(operationFresh, operationClosed) {
				return fail(CodeParticipantFailed)
			}
		case operationRunning:
			if state.state.CompareAndSwap(operationRunning, operationClosing) {
				<-state.done
				return fail(CodeParticipantFailed)
			}
		case operationConsumed:
			if state.state.CompareAndSwap(operationConsumed, operationClosed) {
				if err != nil {
					return fail(CodeParticipantFailed)
				}
				return nil
			}
		case operationFailed:
			if state.state.CompareAndSwap(operationFailed, operationClosed) {
				return fail(CodeParticipantFailed)
			}
		default:
			return fail(CodeParticipantFailed)
		}
	}
}

func safeOwnerOperation[T any](ctx context.Context, invoke func(context.Context, OperationPort[T], T) error, port OperationPort[T], invocation T) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeParticipantFailed)
		}
	}()
	return invoke(ctx, port, invocation)
}

func safeBackendOperation[T any](ctx context.Context, execute func(context.Context, ExecutorBinding, T) error, binding ExecutorBinding, invocation T) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeParticipantFailed)
		}
	}()
	return execute(ctx, binding, invocation)
}
