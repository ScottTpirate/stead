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

	active    *fakeSession
	committed []string
	calls     []string

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
	staged  []string
	closed  bool
}

func (backend *fakeBackend) Begin(context.Context) (Session, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.beginCalls++
	backend.calls = append(backend.calls, "begin")
	if backend.panicBegin {
		panic("injected begin panic")
	}
	if backend.failBegin || backend.active != nil {
		return nil, errInjected
	}
	session := &fakeSession{backend: backend}
	backend.active = session
	return session, nil
}

func (session *fakeSession) Commit(context.Context) error {
	backend := session.backend
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.commitCalls++
	backend.calls = append(backend.calls, "commit")
	if backend.panicCommit {
		panic("injected commit panic")
	}
	if backend.failCommit || session.closed || backend.active != session {
		return errInjected
	}
	backend.committed = append(backend.committed, session.staged...)
	session.closed = true
	backend.active = nil
	return nil
}

func (session *fakeSession) Rollback(ctx context.Context) error {
	backend := session.backend
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.rollbackCalls++
	backend.calls = append(backend.calls, "rollback")
	backend.rollbackContextWasLive = ctx != nil && ctx.Err() == nil
	if backend.active == session {
		backend.active = nil
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

func (backend *fakeBackend) stage(capability OwnerCapability, owner, value string) error {
	if !capability.ValidFor(owner) {
		return errInjected
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.active == nil || backend.active.closed {
		return errInjected
	}
	backend.calls = append(backend.calls, value)
	backend.active.staged = append(backend.active.staged, value)
	return nil
}

func (backend *fakeBackend) stageOutbox(scope outbox.TransactionScope, intent outbox.ValidatedIntent) error {
	if scope.Verify() != nil || intent.Verify() != nil {
		return errInjected
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.active == nil || backend.active.closed {
		return errInjected
	}
	backend.calls = append(backend.calls, "outbox")
	backend.active.staged = append(backend.active.staged, "outbox")
	return nil
}

func (backend *fakeBackend) snapshot() (calls, committed []string, begin, commit, rollback int, rollbackContextLive bool) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]string(nil), backend.calls...), append([]string(nil), backend.committed...),
		backend.beginCalls, backend.commitCalls, backend.rollbackCalls, backend.rollbackContextWasLive
}

type fakeAppender struct {
	backend *fakeBackend
	fail    bool
	panic   bool
	calls   int
}

func (appender *fakeAppender) Append(_ context.Context, scope outbox.TransactionScope, intent outbox.ValidatedIntent) error {
	appender.calls++
	if appender.panic {
		panic("injected outbox panic")
	}
	if appender.fail {
		return errInjected
	}
	return appender.backend.stageOutbox(scope, intent)
}

type participantControl struct {
	fail       bool
	panic      bool
	cancel     context.CancelFunc
	capture    *OwnerCapability
	inFlight   *int
	maxFlight  *int
	flightLock *sync.Mutex
}

func registeredTestPlan(backend *fakeBackend, controls []participantControl, policy OutboxPolicy) PlanTemplate {
	participants := make([]ParticipantTemplate, len(controls))
	for index := range controls {
		index := index
		key := "participant_" + string(rune('a'+index))
		owner := "owner_" + string(rune('a'+index))
		after := []string(nil)
		if index > 0 {
			after = []string{participants[index-1].Key}
		}
		participants[index] = ParticipantTemplate{
			Key:           key,
			Owner:         owner,
			After:         after,
			DeclaresWrite: true,
			Operation: func(_ context.Context, capability OwnerCapability) error {
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
					*control.capture = capability
				}
				if !capability.ValidFor(owner) || capability.ValidFor("foreign_owner") {
					return errInjected
				}
				if control.panic {
					panic("injected participant panic")
				}
				if control.fail {
					return errInjected
				}
				if err := backend.stage(capability, owner, key); err != nil {
					return err
				}
				if control.cancel != nil {
					control.cancel()
				}
				return nil
			},
		}
	}
	return PlanTemplate{
		ContractVersion: ContractVersionV1,
		Key:             "test_operation",
		Participants:    participants,
		OutboxPolicy:    policy,
	}
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
