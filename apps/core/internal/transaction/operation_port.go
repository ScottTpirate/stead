package transaction

import (
	"context"
	"sync/atomic"
)

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
	execute func(context.Context, Session, T) error
}

// BackendOperation is a startup-only, fixed-owner repository operation. The
// trusted WS-02 integration constructs it; request and owner code receive only
// the OperationPort minted from it after Begin.
type BackendOperation[T any] struct {
	definition *backendOperationDefinition[T]
}

// NewBackendOperation binds one typed repository operation to one backend and
// owner. The executor belongs at the trusted lifecycle/storage integration
// boundary. Domain owner adapters must not receive the BackendContract or this
// constructor's Session-bearing executor; they consume RegisteredOperation.
func NewBackendOperation[T any](contract BackendContract, owner string, execute func(context.Context, Session, T) error) (BackendOperation[T], error) {
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
	execute   func(context.Context, Session, T) error
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
	execute           func(context.Context, Session, T) error
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
		state.session.registry == nil || state.session.plan == nil || !state.session.active.Load() ||
		state.session.plan.state.Load() != planRunning ||
		!state.state.CompareAndSwap(operationFresh, operationRunning) {
		return fail(CodeParticipantFailed)
	}

	err := safeBackendOperation(state.context, state.execute, state.session.session, state.backendInvocation)
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

func safeBackendOperation[T any](ctx context.Context, execute func(context.Context, Session, T) error, session Session, invocation T) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeParticipantFailed)
		}
	}()
	return execute(ctx, session, invocation)
}
