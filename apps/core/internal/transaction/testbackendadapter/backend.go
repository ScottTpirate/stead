// Package testbackendadapter is a trusted lifecycle/storage integration test
// fixture. Unlike an owner adapter, it may see transaction.Session while
// registering a fixed typed repository operation. Its per-session journal
// proves that owner calls through OperationPort enlist in commit and rollback.
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
	if backend.executed == nil {
		backend.executed = make(map[string]int)
	}
	if backend.gates == nil {
		backend.gates = make(map[string]*gate)
	}
}

func (backend *Backend) Begin(context.Context) (transaction.Session, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	backend.next++
	backend.begins++
	value := &session{backend: backend, id: backend.next}
	backend.active[value] = struct{}{}
	return value, nil
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
	value.closed = true
	value.staged = nil
	return nil
}

// RegisterCommandOperation is the trusted integration step. The returned
// operation fixes owner and backend; testowneradapter never receives either
// the contract or the Session-bearing executor.
func RegisterCommandOperation(backend *Backend, contract transaction.BackendContract, owner string) (transaction.BackendOperation[testowneradapter.Command], error) {
	return transaction.NewBackendOperation(contract, owner, func(ctx context.Context, raw transaction.Session, command testowneradapter.Command) error {
		value, ok := raw.(*session)
		if !ok || value.backend != backend {
			return errInvalidSession
		}
		return backend.stage(ctx, value, owner, command.Value)
	})
}

func (backend *Backend) stage(ctx context.Context, value *session, owner, item string) error {
	backend.mu.Lock()
	backend.initializeLocked()
	if value.closed {
		backend.mu.Unlock()
		return errInvalidSession
	}
	if _, ok := backend.active[value]; !ok {
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
