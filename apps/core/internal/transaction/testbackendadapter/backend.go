// Package testbackendadapter is a trusted lifecycle/storage integration test
// fixture. Unlike an owner adapter, it owns a private binding-to-session journal
// while registering fixed typed repository operations. The journal proves that
// owner calls through OperationPort enlist in commit and rollback and that a
// binding expires with its transaction.
package testbackendadapter

import (
	"context"
	"errors"
	"sync"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/apps/core/internal/transaction/testowneradapter"
)

var errInvalidSession = errors.New("invalid test backend session")

type Record struct {
	SessionID int
	Owner     string
	Value     string
}

type gate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type Backend struct {
	mu sync.Mutex

	next       int
	begins     int
	commits    int
	rollbacks  int
	active     map[*session]struct{}
	bindings   map[transaction.ExecutorBinding]*session
	bound      map[*session]transaction.ExecutorBinding
	committed  []Record
	rolledBack []Record
	executed   map[string]int
	gates      map[string]*gate
}

type session struct {
	backend *Backend
	id      int
	staged  []Record
	closed  bool
}

func (backend *Backend) initializeLocked() {
	if backend.active == nil {
		backend.active = make(map[*session]struct{})
	}
	if backend.bindings == nil {
		backend.bindings = make(map[transaction.ExecutorBinding]*session)
	}
	if backend.bound == nil {
		backend.bound = make(map[*session]transaction.ExecutorBinding)
	}
	if backend.executed == nil {
		backend.executed = make(map[string]int)
	}
	if backend.gates == nil {
		backend.gates = make(map[string]*gate)
	}
}

func (backend *Backend) Begin(context.Context) (transaction.Session, transaction.ExecutorBinding, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	backend.next++
	backend.begins++
	value := &session{backend: backend, id: backend.next}
	backend.active[value] = struct{}{}
	binding, err := transaction.NewExecutorBinding(value)
	if err != nil {
		return nil, transaction.ExecutorBinding{}, err
	}
	backend.bindings[binding] = value
	backend.bound[value] = binding
	return value, binding, nil
}

func (value *session) Commit(context.Context) error {
	backend := value.backend
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	backend.commits++
	if value.closed {
		return errInvalidSession
	}
	if _, ok := backend.active[value]; !ok {
		return errInvalidSession
	}
	backend.committed = append(backend.committed, value.staged...)
	backend.expireBindingLocked(value)
	delete(backend.active, value)
	value.closed = true
	return nil
}

func (value *session) Rollback(context.Context) error {
	backend := value.backend
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	backend.rollbacks++
	if _, ok := backend.active[value]; ok {
		backend.rolledBack = append(backend.rolledBack, value.staged...)
		delete(backend.active, value)
	}
	backend.expireBindingLocked(value)
	value.closed = true
	value.staged = nil
	return nil
}

func (backend *Backend) expireBindingLocked(value *session) {
	binding, exists := backend.bound[value]
	if !exists {
		return
	}
	delete(backend.bound, value)
	delete(backend.bindings, binding)
}

// RegisterCommandOperation is the trusted integration step. The returned
// operation fixes owner and backend; testowneradapter never receives either
// the contract or the executor binding.
func RegisterCommandOperation(backend *Backend, contract transaction.BackendContract, owner string) (transaction.BackendOperation[testowneradapter.Command], error) {
	return transaction.NewBackendOperation(contract, owner, func(ctx context.Context, binding transaction.ExecutorBinding, command testowneradapter.Command) error {
		return backend.stage(ctx, binding, owner, command.Value)
	})
}

func (backend *Backend) stage(ctx context.Context, binding transaction.ExecutorBinding, owner, item string) error {
	backend.mu.Lock()
	backend.initializeLocked()
	value, ok := backend.bindings[binding]
	if !ok || value == nil || value.backend != backend {
		backend.mu.Unlock()
		return errInvalidSession
	}
	if value.closed {
		backend.mu.Unlock()
		return errInvalidSession
	}
	if _, ok = backend.active[value]; !ok {
		backend.mu.Unlock()
		return errInvalidSession
	}
	record := Record{SessionID: value.id, Owner: owner, Value: item}
	value.staged = append(value.staged, record)
	backend.executed[owner]++
	block := backend.gates[item]
	backend.mu.Unlock()

	if block != nil {
		block.once.Do(func() { close(block.entered) })
		select {
		case <-block.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (backend *Backend) Block(value string) (<-chan struct{}, func()) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	block := &gate{entered: make(chan struct{}), release: make(chan struct{})}
	backend.gates[value] = block
	return block.entered, func() {
		block.once.Do(func() { close(block.entered) })
		select {
		case <-block.release:
		default:
			close(block.release)
		}
	}
}

func (backend *Backend) Snapshot() (committed, rolledBack []Record, active int, executed map[string]int) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	return append([]Record(nil), backend.committed...), append([]Record(nil), backend.rolledBack...), len(backend.active), cloneCounts(backend.executed)
}

func (backend *Backend) Lifecycle() (begins, commits, rollbacks int) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.begins, backend.commits, backend.rollbacks
}

func cloneCounts(source map[string]int) map[string]int {
	result := make(map[string]int, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
