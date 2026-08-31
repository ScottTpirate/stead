package transaction

import (
	"context"
	"errors"
	"sync"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

var errInjected = errors.New("injected failure")

type fakeBackend struct {
	mu sync.Mutex

	active       map[*fakeSession]struct{}
	committed    []string
	committedBy  map[int][]string
	rolledBackBy map[int][]string
	calls        []string
	nextSession  int

	beginCalls    int
	commitCalls   int
	rollbackCalls int

	failBegin     bool
	failCommit    bool
	failRollback  bool
	panicBegin    bool
	panicCommit   bool
	panicRollback bool

	rollbackContextWasLive bool
}

type fakeSession struct {
	backend *fakeBackend
	id      int
	staged  []string
	closed  bool
}

func (backend *fakeBackend) initializeLocked() {
	if backend.active == nil {
		backend.active = make(map[*fakeSession]struct{})
	}
	if backend.committedBy == nil {
		backend.committedBy = make(map[int][]string)
	}
	if backend.rolledBackBy == nil {
		backend.rolledBackBy = make(map[int][]string)
	}
}

func (backend *fakeBackend) Begin(context.Context) (Session, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	backend.beginCalls++
	backend.calls = append(backend.calls, "begin")
	if backend.panicBegin {
		panic("injected begin panic")
	}
	if backend.failBegin {
		return nil, errInjected
	}
	backend.nextSession++
	session := &fakeSession{backend: backend, id: backend.nextSession}
	backend.active[session] = struct{}{}
	return session, nil
}

func (session *fakeSession) Commit(context.Context) error {
	backend := session.backend
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	backend.commitCalls++
	backend.calls = append(backend.calls, "commit")
	if backend.panicCommit {
		panic("injected commit panic")
	}
	if backend.failCommit || session.closed {
		return errInjected
	}
	if _, active := backend.active[session]; !active {
		return errInjected
	}
	backend.committed = append(backend.committed, session.staged...)
	backend.committedBy[session.id] = append([]string(nil), session.staged...)
	session.closed = true
	delete(backend.active, session)
	return nil
}

func (session *fakeSession) Rollback(ctx context.Context) error {
	backend := session.backend
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.initializeLocked()
	backend.rollbackCalls++
	backend.calls = append(backend.calls, "rollback")
	backend.rollbackContextWasLive = ctx != nil && ctx.Err() == nil
	if _, active := backend.active[session]; active {
		backend.rolledBackBy[session.id] = append([]string(nil), session.staged...)
		delete(backend.active, session)
	}
	session.closed = true
	session.staged = nil
	if backend.panicRollback {
		panic("injected rollback panic")
	}
	if backend.failRollback {
		return errInjected
	}
	return nil
}

// stage is the fake owner-authored typed adapter. SessionBinding.Use encloses
// the exact synchronous call; resolve is confined to the trusted WS-02 fake
// lifecycle/storage boundary and returns only the Begin-created Session.
func (backend *fakeBackend) stage(binding SessionBinding, owner, value string) (BindingReceipt, error) {
	return binding.Use(func() error {
		sessionValue, ok := binding.resolve(owner)
		if !ok {
			return errInjected
		}
		session, ok := sessionValue.(*fakeSession)
		if !ok || session.backend != backend {
			return errInjected
		}
		backend.mu.Lock()
		defer backend.mu.Unlock()
		backend.initializeLocked()
		if session.closed {
			return errInjected
		}
		if _, active := backend.active[session]; !active {
			return errInjected
		}
		backend.calls = append(backend.calls, value)
		session.staged = append(session.staged, value)
		return nil
	})
}

func (backend *fakeBackend) stageOutbox(scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	if intent.Verify() != nil {
		return outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}, BindingReceipt{}, errInjected
	}
	return scope.Use(func(binding SessionBinding) (BindingReceipt, error) {
		return binding.Use(func() error {
			sessionValue, ok := binding.resolve("core_outbox")
			if !ok {
				return errInjected
			}
			session, ok := sessionValue.(*fakeSession)
			if !ok || session.backend != backend {
				return errInjected
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			backend.initializeLocked()
			if session.closed {
				return errInjected
			}
			if _, active := backend.active[session]; !active {
				return errInjected
			}
			backend.calls = append(backend.calls, "outbox")
			session.staged = append(session.staged, "outbox")
			return nil
		})
	})
}

func (backend *fakeBackend) snapshot() (calls, committed []string, begin, commit, rollback int, rollbackContextLive bool) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]string(nil), backend.calls...), append([]string(nil), backend.committed...),
		backend.beginCalls, backend.commitCalls, backend.rollbackCalls, backend.rollbackContextWasLive
}

func (backend *fakeBackend) journals() (committed, rolledBack map[int][]string, active int) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	committed = make(map[int][]string, len(backend.committedBy))
	for id, values := range backend.committedBy {
		committed[id] = append([]string(nil), values...)
	}
	rolledBack = make(map[int][]string, len(backend.rolledBackBy))
	for id, values := range backend.rolledBackBy {
		rolledBack[id] = append([]string(nil), values...)
	}
	return committed, rolledBack, len(backend.active)
}

type fakeAppender struct {
	backend *fakeBackend
	fail    bool
	panic   bool
	mu      sync.Mutex
	calls   int
}

func (appender *fakeAppender) Append(_ context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	appender.mu.Lock()
	appender.calls++
	appender.mu.Unlock()
	if appender.panic {
		panic("injected outbox panic")
	}
	if appender.fail {
		return outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}, BindingReceipt{}, errInjected
	}
	return appender.backend.stageOutbox(scope, intent)
}

func (appender *fakeAppender) callCount() int {
	appender.mu.Lock()
	defer appender.mu.Unlock()
	return appender.calls
}

type participantControl struct {
	fail       bool
	panic      bool
	cancel     context.CancelFunc
	capture    *SessionBinding
	inFlight   *int
	maxFlight  *int
	flightLock *sync.Mutex
	entered    chan struct{}
	proceed    chan struct{}
}

type testInvocation struct {
	prefix string
}

func registeredTestPlan(backend *fakeBackend, controls []participantControl, policy OutboxPolicy) (PlanTemplate, PlanContract[testInvocation]) {
	participants := make([]TypedParticipant[testInvocation], len(controls))
	for index := range controls {
		index := index
		key := "participant_" + string(rune('a'+index))
		owner := "owner_" + string(rune('a'+index))
		after := []string(nil)
		if index > 0 {
			after = []string{participants[index-1].Key}
		}
		participants[index] = TypedParticipant[testInvocation]{
			Key:           key,
			Owner:         owner,
			After:         after,
			DeclaresWrite: true,
			Operation: func(_ context.Context, binding SessionBinding, invocation testInvocation) (BindingReceipt, error) {
				control := &controls[index]
				if control.flightLock != nil {
					control.flightLock.Lock()
					*control.inFlight++
					if *control.inFlight > *control.maxFlight {
						*control.maxFlight = *control.inFlight
					}
					control.flightLock.Unlock()
					defer func() {
						control.flightLock.Lock()
						*control.inFlight--
						control.flightLock.Unlock()
					}()
				}
				if control.capture != nil {
					*control.capture = binding
				}
				if control.entered != nil {
					close(control.entered)
				}
				if control.proceed != nil {
					<-control.proceed
				}
				if control.panic {
					panic("injected participant panic")
				}
				if control.fail {
					return BindingReceipt{}, errInjected
				}
				receipt, err := backend.stage(binding, owner, invocation.prefix+key)
				if err != nil {
					return BindingReceipt{}, err
				}
				if control.cancel != nil {
					control.cancel()
				}
				return receipt, nil
			},
		}
	}
	template, contract, err := NewPlanContract(ContractVersionV1, "test_operation", participants, policy)
	if err != nil {
		panic(err)
	}
	return template, contract
}

func newTestCoordinator(backend *fakeBackend, registry Registry, appender *fakeAppender, finalizer FinalAuthorizationAuditPort, durable DurableEffectPreparationPort) *Coordinator {
	coordinator, err := NewCoordinator(Configuration{
		Backend:                  backend,
		Registry:                 registry,
		Outbox:                   appender,
		FinalAuthorizationAudit:  finalizer,
		DurableEffectPreparation: durable,
	})
	if err != nil {
		panic(err)
	}
	return coordinator
}

func testIntent() outbox.ValidatedIntent {
	authority := outbox.NewValidationAuthority()
	intent, err := authority.WrapValidated(outbox.ValidatedIntentHandoffV1, []byte(`{"safe_aggregate_ref":"aggregate:test"}`))
	if err != nil {
		panic(err)
	}
	return intent
}
