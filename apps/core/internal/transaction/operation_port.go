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
	operationClosed
)

type operationCallSeal struct{ marker byte }
type operationContextKey struct{}

type operationPortState[T any] struct {
	session    *sessionState
	backend    *backendSeal
	operation  *backendOperationSeal
	owner      string
	invocation T
	execute    func(context.Context, Session, T) error
	call       *operationCallSeal
	state      atomic.Uint32
}

// OperationPort is the only capability delivered to an owner adapter. It is
// bound to the exact Begin-created session, backend, registered operation,
// owner, invocation, and synchronous adapter call. It exposes no lifecycle,
// SQL, role, transaction, or validity method.
type OperationPort[T any] struct {
	state *operationPortState[T]
}

// Execute synchronously invokes only the repository operation fixed during
// registration. The invocation, owner, and session cannot be supplied or
// replaced by the caller. Copied, swapped, concurrent, retained, and late
// ports fail before the backend executor runs.
func (port OperationPort[T]) Execute(ctx context.Context) error {
	state := port.state
	if state == nil || state.session == nil || state.backend == nil || state.operation == nil ||
		state.execute == nil || state.call == nil || ctx == nil || ctx.Err() != nil ||
		ctx.Value(operationContextKey{}) != state.call || state.session.backend != state.backend ||
		state.session.registry == nil || state.session.plan == nil || !state.session.active.Load() ||
		state.session.plan.state.Load() != planRunning ||
		!state.state.CompareAndSwap(operationFresh, operationRunning) {
		return fail(CodeParticipantFailed)
	}
	if err := safeBackendOperation(ctx, state.execute, state.session.session, state.invocation); err != nil {
		state.state.CompareAndSwap(operationRunning, operationFailed)
		return fail(CodeParticipantFailed)
	}
	state.state.CompareAndSwap(operationRunning, operationConsumed)
	return nil
}

func (operation RegisteredOperation[T]) run(ctx context.Context, session *sessionState, invocation T) error {
	definition := operation.definition
	if definition == nil || definition.backend == nil || definition.operation == nil ||
		definition.execute == nil || definition.invoke == nil || session == nil ||
		session.backend != definition.backend {
		return fail(CodeParticipantFailed)
	}
	call := &operationCallSeal{}
	state := &operationPortState[T]{
		session:    session,
		backend:    definition.backend,
		operation:  definition.operation,
		owner:      definition.owner,
		invocation: invocation,
		execute:    definition.execute,
		call:       call,
	}
	port := OperationPort[T]{state: state}
	callContext := context.WithValue(ctx, operationContextKey{}, call)
	err := safeOwnerOperation(callContext, definition.invoke, port, invocation)
	consumed := state.state.Swap(operationClosed) == operationConsumed
	if err != nil || !consumed {
		return fail(CodeParticipantFailed)
	}
	return nil
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
