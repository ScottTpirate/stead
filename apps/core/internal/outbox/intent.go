// Package outbox defines the WS-02-owned, transaction-scoped handoff for an
// immutable intent that has already been validated by its WS-07 owner.
//
// The package deliberately does not define event fields, audit meaning,
// publication, retention, replay, or delivery behavior. Those remain WS-07
// contracts. The types here only preserve immutability and transaction scope.
package outbox

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync/atomic"
)

const (
	// ValidatedIntentHandoffV1 versions the internal WS-07-to-WS-02 handoff.
	// It is not an event-schema or audit-payload version.
	ValidatedIntentHandoffV1 = "stead.core.validated-intent-handoff/v1"
)

var (
	ErrInvalidValidatedIntent  = errors.New("invalid validated intent handoff")
	ErrInvalidTransactionScope = errors.New("invalid outbox transaction scope")
)

type validationSeal struct{ marker byte }

// ValidationAuthority is handed by the core composition root only to the
// adapter for the separately owned WS-07 validator. Calling WrapValidated is
// an assertion that WS-07 validation already succeeded; core never parses or
// reinterprets the payload.
type ValidationAuthority struct {
	seal *validationSeal
}

func NewValidationAuthority() ValidationAuthority {
	return ValidationAuthority{seal: &validationSeal{}}
}

// ValidatedIntent is immutable after construction. Its zero value and values
// assembled with a struct literal cannot pass Verify.
type ValidatedIntent struct {
	seal    *validationSeal
	version string
	payload []byte
	digest  [sha256.Size]byte
}

func (a ValidationAuthority) WrapValidated(version string, canonicalPayload []byte) (ValidatedIntent, error) {
	if a.seal == nil || version != ValidatedIntentHandoffV1 || len(canonicalPayload) == 0 {
		return ValidatedIntent{}, ErrInvalidValidatedIntent
	}
	payload := append([]byte(nil), canonicalPayload...)
	return ValidatedIntent{
		seal:    a.seal,
		version: version,
		payload: payload,
		digest:  sha256.Sum256(payload),
	}, nil
}

func (i ValidatedIntent) Verify() error {
	if i.seal == nil || i.version != ValidatedIntentHandoffV1 || len(i.payload) == 0 {
		return ErrInvalidValidatedIntent
	}
	if sha256.Sum256(i.payload) != i.digest {
		return ErrInvalidValidatedIntent
	}
	return nil
}

func (i ValidatedIntent) HandoffVersion() string {
	return i.version
}

func (i ValidatedIntent) Digest() [sha256.Size]byte {
	return i.digest
}

func (i ValidatedIntent) Size() int {
	return len(i.payload)
}

// PayloadCopy returns an isolated copy for the WS-02-owned storage adapter.
// The value must not be logged, inspected for business meaning, or exposed to
// another module. Keeping this package internal prevents module consumers from
// obtaining it directly.
func (i ValidatedIntent) PayloadCopy() []byte {
	return append([]byte(nil), i.payload...)
}

type scopeSeal struct{ marker byte }

const (
	scopeFresh uint32 = iota
	scopeRunning
	scopeConsumed
	scopeClosed
)

type scopeState[T, R any] struct {
	seal    *scopeSeal
	binding T
	state   atomic.Uint32
}

// ScopeAuthority is owned by one coordinator. It is required to bind and close
// short-lived outbox scopes; the appender cannot mint one itself.
type ScopeAuthority struct {
	seal *scopeSeal
}

func NewScopeAuthority() ScopeAuthority {
	return ScopeAuthority{seal: &scopeSeal{}}
}

// TransactionScope carries one opaque transaction binding into exactly one
// synchronous append callback. It exposes no binding value, SQL, driver,
// connection, role, table, commit, or rollback operation.
type TransactionScope[T, R any] struct {
	state *scopeState[T, R]
}

// ScopeReceipt proves that one exact TransactionScope completed its own Use
// callback. It carries no binding or result and cannot be forged by callers.
type ScopeReceipt[T, R any] struct {
	state *scopeState[T, R]
}

// OpenScope binds one coordinator-owned transaction value to an outbox scope.
// Go does not permit parameterized methods, so this is a free function rather
// than a ScopeAuthority method.
func OpenScope[T, R any](a ScopeAuthority, binding T) (TransactionScope[T, R], error) {
	if a.seal == nil {
		return TransactionScope[T, R]{}, ErrInvalidTransactionScope
	}
	state := &scopeState[T, R]{seal: a.seal, binding: binding}
	return TransactionScope[T, R]{state: state}, nil
}

// Use consumes the scope around one exact synchronous appender operation. A
// copy, a concurrent second call, or a retained call after return fails.
func (scope TransactionScope[T, R]) Use(operation func(T) (R, error)) (receipt ScopeReceipt[T, R], result R, resultErr error) {
	if scope.state == nil || scope.state.seal == nil || operation == nil ||
		!scope.state.state.CompareAndSwap(scopeFresh, scopeRunning) {
		return receipt, result, ErrInvalidTransactionScope
	}
	defer scope.state.state.CompareAndSwap(scopeRunning, scopeConsumed)
	result, resultErr = operation(scope.state.binding)
	if resultErr != nil {
		return ScopeReceipt[T, R]{}, result, resultErr
	}
	return ScopeReceipt[T, R]{state: scope.state}, result, nil
}

// CloseScope invalidates every copy and reports whether the exact owned scope
// completed one synchronous Use callback and returned that scope's receipt.
func CloseScope[T, R any](a ScopeAuthority, scope TransactionScope[T, R], receipt ScopeReceipt[T, R]) bool {
	if a.seal == nil || scope.state == nil || scope.state.seal != a.seal {
		return false
	}
	previous := scope.state.state.Swap(scopeClosed)
	return previous == scopeConsumed && receipt.state == scope.state
}

// AppendPort is the only transaction-scoped insertion surface. It deliberately
// contains no table, SQL, publish, delete, claim, or delivery method.
type AppendPort[T, R any] interface {
	Append(context.Context, TransactionScope[T, R], ValidatedIntent) (ScopeReceipt[T, R], R, error)
}
