// Package testowneradapter proves that an owner-authored typed adapter can
// live outside the transaction package while receiving only an exact-call
// OperationPort. It cannot access Session, lifecycle, SQL, owner selection, or
// a global repository handle. It is test evidence, not a domain API.
package testowneradapter

import (
	"context"
	"errors"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
)

type Command struct {
	Value            string
	FailAfterExecute bool
}

var ErrAfterExecute = errors.New("test owner rejected after repository execution")

type Adapter struct{}

func (Adapter) Apply(ctx context.Context, port transaction.OperationPort[Command], command Command) error {
	if err := port.Execute(ctx); err != nil {
		return err
	}
	if command.FailAfterExecute {
		return ErrAfterExecute
	}
	return nil
}

// CapturedOperation is opaque with respect to transaction state: even when an
// owner retains both values, the port is closed as soon as Apply returns.
type CapturedOperation struct {
	Context context.Context
	Port    transaction.OperationPort[Command]
}

type RetainingAdapter struct {
	Captured chan<- CapturedOperation
}

func (adapter RetainingAdapter) Apply(ctx context.Context, port transaction.OperationPort[Command], _ Command) error {
	if err := port.Execute(ctx); err != nil {
		return err
	}
	adapter.Captured <- CapturedOperation{Context: ctx, Port: port}
	return nil
}

// DeferredAdapter deliberately returns without consuming the port. The
// coordinator closes it before any retained goroutine may try to execute it.
type DeferredAdapter struct {
	Captured chan<- CapturedOperation
}

func (adapter DeferredAdapter) Apply(ctx context.Context, port transaction.OperationPort[Command], _ Command) error {
	adapter.Captured <- CapturedOperation{Context: ctx, Port: port}
	return nil
}

// SwappingAdapter exchanges two concurrent calls and deliberately attempts to
// execute each exact port with the other call's context. Both must be rejected
// before either registered backend executor runs.
type SwappingAdapter struct {
	Arrivals chan Exchange
}

type Exchange struct {
	Context context.Context
	Port    transaction.OperationPort[Command]
	Peer    chan Exchange
}

func (adapter SwappingAdapter) Apply(ctx context.Context, port transaction.OperationPort[Command], _ Command) error {
	peer := make(chan Exchange, 1)
	adapter.Arrivals <- Exchange{Context: ctx, Port: port, Peer: peer}
	foreign := <-peer
	return foreign.Port.Execute(ctx)
}
