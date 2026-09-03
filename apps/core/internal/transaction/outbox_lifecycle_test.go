package transaction

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

type escapedOutboxResult struct {
	scopeErr      error
	bindingErr    error
	bindingResult BindingReceipt
	panicked      bool
}

func TestSessionBindingCloseWaitsForActiveUseAndSuppressesLateReceipt(t *testing.T) {
	plan := &planState{}
	plan.state.Store(planRunning)
	session := &sessionState{registry: &registrySeal{}, backend: &backendSeal{}, plan: plan, session: &fakeSession{}}
	session.active.Store(true)
	binding := newSessionBinding(session, "core_outbox")
	copy := binding
	entered := make(chan struct{})
	release := make(chan struct{})
	type useResult struct {
		receipt BindingReceipt
		err     error
	}
	useDone := make(chan useResult, 1)
	go func() {
		receipt, useErr := binding.Use(func() error {
			if _, ok := binding.resolve("core_outbox"); !ok {
				return errInjected
			}
			close(entered)
			<-release
			return nil
		})
		useDone <- useResult{receipt: receipt, err: useErr}
	}()
	<-entered
	closeDone := make(chan bool, 2)
	go func() { closeDone <- copy.close(BindingReceipt{}) }()
	deadline := time.After(time.Second)
	for copy.state.state.Load() != bindingClosing {
		select {
		case <-deadline:
			t.Fatal("binding close did not enter closing state")
		default:
		}
	}
	go func() { closeDone <- copy.close(BindingReceipt{}) }()
	if _, err := copy.Use(func() error { return nil }); ErrorCodeOf(err) != CodeParticipantFailed {
		t.Fatalf("closing binding admitted another Use: %v", err)
	}
	if _, ok := copy.resolve("core_outbox"); ok {
		t.Fatal("closing binding still resolved its session")
	}
	select {
	case result := <-closeDone:
		t.Fatalf("binding close returned before Use: %t", result)
	default:
	}
	close(release)
	result := <-useDone
	if result.receipt.state != nil || ErrorCodeOf(result.err) != CodeParticipantFailed {
		t.Fatalf("late binding receipt escaped: %#v", result)
	}
	for range 2 {
		if consumed := <-closeDone; consumed {
			t.Fatal("closing binding reported synchronous consumption")
		}
	}
	if copy.state.state.Load() != bindingClosed || copy.close(BindingReceipt{}) || copy.state.finishUse() {
		t.Fatal("closed binding was reusable")
	}
}

type outerEscapingAppender struct {
	backend   *fakeBackend
	entered   chan struct{}
	release   chan struct{}
	completed chan escapedOutboxResult
	panicUse  bool
}

func (appender *outerEscapingAppender) Append(_ context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	if intent.Verify() != nil {
		return outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}, BindingReceipt{}, errInjected
	}
	go func() {
		result := escapedOutboxResult{}
		defer func() {
			if recover() != nil {
				result.panicked = true
			}
			appender.completed <- result
		}()
		_, result.bindingResult, result.scopeErr = scope.Use(func(binding SessionBinding) (BindingReceipt, error) {
			close(appender.entered)
			<-appender.release
			if appender.panicUse {
				panic("escaped outer scope")
			}
			result.bindingResult, result.bindingErr = binding.Use(func() error {
				sessionValue, ok := binding.resolve("core_outbox")
				session, typed := sessionValue.(*fakeSession)
				if !ok || !typed || session.backend != appender.backend {
					return errInjected
				}
				return appender.backend.stage(context.Background(), session, "core_outbox", "escaped-outbox")
			})
			return result.bindingResult, result.bindingErr
		})
	}()
	<-appender.entered
	return outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}, BindingReceipt{}, nil
}

type innerEscapingAppender struct {
	backend   *fakeBackend
	entered   chan struct{}
	release   chan struct{}
	completed chan escapedOutboxResult
	panicUse  bool
}

func (appender *innerEscapingAppender) Append(_ context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	if intent.Verify() != nil {
		return outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}, BindingReceipt{}, errInjected
	}
	return scope.Use(func(binding SessionBinding) (BindingReceipt, error) {
		go func() {
			result := escapedOutboxResult{}
			defer func() {
				if recover() != nil {
					result.panicked = true
				}
				appender.completed <- result
			}()
			result.bindingResult, result.bindingErr = binding.Use(func() error {
				sessionValue, ok := binding.resolve("core_outbox")
				session, typed := sessionValue.(*fakeSession)
				if !ok || !typed || session.backend != appender.backend {
					return errInjected
				}
				close(appender.entered)
				<-appender.release
				if appender.panicUse {
					panic("escaped inner binding")
				}
				return appender.backend.stage(context.Background(), session, "core_outbox", "escaped-outbox")
			})
		}()
		<-appender.entered
		return BindingReceipt{}, nil
	})
}

func TestEscapedOutboxScopesFinishBeforeExactlyOneRollback(t *testing.T) {
	tests := []struct {
		name       string
		layer      string
		panicUse   bool
		cancelNow  bool
		contextFor func() (context.Context, context.CancelFunc)
		awaitStop  func(context.Context)
	}{
		{
			name:      "outer scope cancellation",
			layer:     "outer",
			cancelNow: true,
			contextFor: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			awaitStop: func(ctx context.Context) { <-ctx.Done() },
		},
		{
			name:  "inner binding deadline",
			layer: "inner",
			contextFor: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			awaitStop: func(ctx context.Context) { <-ctx.Done() },
		},
		{name: "outer scope panic", layer: "outer", panicUse: true},
		{name: "inner binding panic", layer: "inner", panicUse: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{}
			template, contract := registeredTestPlan(backend, make([]participantControl, 1), OutboxRequired)
			registry, err := NewRegistry([]PlanTemplate{template})
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			completed := make(chan escapedOutboxResult, 1)
			var appendPort outbox.AppendPort[SessionBinding, BindingReceipt]
			if testCase.layer == "outer" {
				appendPort = &outerEscapingAppender{backend: backend, entered: entered, release: release, completed: completed, panicUse: testCase.panicUse}
			} else {
				appendPort = &innerEscapingAppender{backend: backend, entered: entered, release: release, completed: completed, panicUse: testCase.panicUse}
			}
			coordinator, err := NewCoordinator(Configuration{Backend: backend.backendContract(), Registry: registry, Outbox: appendPort})
			if err != nil {
				t.Fatal(err)
			}
			intent := testIntent()
			plan, err := contract.Bind(registry, testInvocation{}, &intent)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			cancel := func() {}
			if testCase.contextFor != nil {
				ctx, cancel = testCase.contextFor()
			}
			defer cancel()
			executeDone := make(chan error, 1)
			go func() {
				_, executeErr := coordinator.Execute(ctx, plan)
				executeDone <- executeErr
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("escaped callback did not start")
			}
			if testCase.cancelNow {
				cancel()
			}
			if testCase.contextFor != nil {
				testCase.awaitStop(ctx)
			}
			_, committed, begins, commits, rollbacks, _ := backend.snapshot()
			if begins != 1 || commits != 0 || rollbacks != 0 || len(committed) != 0 {
				t.Fatalf("lifecycle overlapped escaped callback: %d/%d/%d committed=%v", begins, commits, rollbacks, committed)
			}
			select {
			case err := <-executeDone:
				t.Fatalf("Execute returned before escaped callback completed: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			close(release)
			result := <-completed
			if testCase.panicUse != result.panicked {
				t.Fatalf("panic result = %t", result.panicked)
			}
			if !testCase.panicUse {
				if testCase.layer == "outer" {
					if !errors.Is(result.scopeErr, outbox.ErrInvalidTransactionScope) || result.bindingResult.state != nil {
						t.Fatalf("outer late result escaped: %#v", result)
					}
				} else if ErrorCodeOf(result.bindingErr) != CodeParticipantFailed || result.bindingResult.state != nil {
					t.Fatalf("inner late result escaped: %#v", result)
				}
			}
			select {
			case err := <-executeDone:
				if ErrorCodeOf(err) != CodeOutboxFailed {
					t.Fatalf("Execute error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Execute did not finish after callback completion")
			}
			_, committed, begins, commits, rollbacks, _ = backend.snapshot()
			committedJournals, rolledBackJournals, active := backend.journals()
			if begins != 1 || commits != 0 || rollbacks != 1 || len(committed) != 0 || len(committedJournals) != 0 || len(rolledBackJournals) != 1 || active != 0 {
				t.Fatalf("final lifecycle=%d/%d/%d committed=%v journals=%v/%v active=%d", begins, commits, rollbacks, committed, committedJournals, rolledBackJournals, active)
			}
			if !testCase.panicUse && !reflect.DeepEqual(rolledBackJournals[1], []string{"participant_a", "escaped-outbox"}) {
				t.Fatalf("rollback journal = %v", rolledBackJournals)
			}
		})
	}
}
