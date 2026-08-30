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

type scopeState struct {
	seal   *scopeSeal
	active atomic.Bool
}

// ScopeAuthority is owned by one coordinator. It mints short-lived outbox
// scopes and invalidates them before the transaction ends.
type ScopeAuthority struct {
	seal *scopeSeal
}

func NewScopeAuthority() ScopeAuthority {
	return ScopeAuthority{seal: &scopeSeal{}}
}

// TransactionScope is an opaque capability. It exposes no SQL, driver,
// connection, role, table, commit, or rollback operation.
type TransactionScope struct {
	state *scopeState
}

func (a ScopeAuthority) Open() (TransactionScope, error) {
	if a.seal == nil {
		return TransactionScope{}, ErrInvalidTransactionScope
	}
	state := &scopeState{seal: a.seal}
	state.active.Store(true)
	return TransactionScope{state: state}, nil
}

func (a ScopeAuthority) Close(scope TransactionScope) {
	if a.Owns(scope) {
		scope.state.active.Store(false)
	}
}

func (a ScopeAuthority) Owns(scope TransactionScope) bool {
	return a.seal != nil && scope.state != nil && scope.state.seal == a.seal && scope.state.active.Load()
}

func (scope TransactionScope) Verify() error {
	if scope.state == nil || scope.state.seal == nil || !scope.state.active.Load() {
		return ErrInvalidTransactionScope
	}
	return nil
}

// AppendPort is the only transaction-scoped insertion surface. It deliberately
// contains no table, SQL, publish, delete, claim, or delivery method.
type AppendPort interface {
	Append(context.Context, TransactionScope, ValidatedIntent) error
}
