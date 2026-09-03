package transaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

func TestRegisteredTypedPlanRunsSeriallyAndOutboxLast(t *testing.T) {
	backend := &fakeBackend{}
	var captured [3]OperationPort[testInvocation]
	inFlight, maxFlight := 0, 0
	flightLock := &sync.Mutex{}
	controls := make([]participantControl, 3)
	for index := range controls {
		controls[index] = participantControl{
			capture:    &captured[index],
			inFlight:   &inFlight,
			maxFlight:  &maxFlight,
			flightLock: flightLock,
		}
	}
	template, contract := registeredTestPlan(backend, controls, OutboxRequired)
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}

	intent := testIntent()
	plan, err := contract.Bind(registry, testInvocation{}, &intent)
	if err != nil {
		t.Fatal(err)
	}
	appender := &fakeAppender{backend: backend}
	coordinator := newTestCoordinator(backend, registry, appender, nil, nil)
	report, err := coordinator.Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	calls, committed, beginCalls, commitCalls, rollbackCalls, _ := backend.snapshot()
	wantCalls := []string{"begin", "participant_a", "participant_b", "participant_c", "outbox", "commit"}
	wantCommitted := []string{"participant_a", "participant_b", "participant_c", "outbox"}
	if !reflect.DeepEqual(calls, wantCalls) || !reflect.DeepEqual(committed, wantCommitted) {
		t.Fatalf("order drifted\ncalls: %v\ncommitted: %v", calls, committed)
	}
	if beginCalls != 1 || commitCalls != 1 || rollbackCalls != 0 || appender.callCount() != 1 || maxFlight != 1 {
		t.Fatalf("lifecycle counts = begin:%d commit:%d rollback:%d append:%d max-flight:%d", beginCalls, commitCalls, rollbackCalls, appender.callCount(), maxFlight)
	}
	wantReport := Report{
		BeginCalls:                    1,
		ParticipantCalls:              3,
		DeclaredWriteParticipantCalls: 3,
		OutboxParticipantCalls:        1,
		OutboxAppendCalls:             1,
		CommitCalls:                   1,
	}
	if report != wantReport {
		t.Fatalf("report = %#v, want %#v", report, wantReport)
	}
	for index, port := range captured {
		if err := port.Execute(context.Background()); ErrorCodeOf(err) != CodeParticipantFailed {
			t.Fatalf("participant %d retained a usable port: err=%v", index, err)
		}
	}
	if _, err := coordinator.Execute(context.Background(), plan); ErrorCodeOf(err) != CodePlanUnavailable {
		t.Fatalf("reused plan error = %v", err)
	}
	if beginCallsAfter := func() int { _, _, value, _, _, _ := backend.snapshot(); return value }(); beginCallsAfter != 1 {
		t.Fatal("single-use plan retried the transaction")
	}
}

func TestOptionalOutboxStillHasOneFinalSlot(t *testing.T) {
	backend := &fakeBackend{}
	template, contract := registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, testInvocation{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	appender := &fakeAppender{backend: backend}
	report, err := newTestCoordinator(backend, registry, appender, nil, nil).Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if report.OutboxParticipantCalls != 1 || report.OutboxAppendCalls != 0 || appender.callCount() != 0 {
		t.Fatalf("optional outbox counts = %#v, appender=%d", report, appender.callCount())
	}
	_, committed, _, _, _, _ := backend.snapshot()
	if !reflect.DeepEqual(committed, []string{"participant_a"}) {
		t.Fatalf("committed = %v", committed)
	}
}

func TestTypedContractFreezesOrderOwnersAndOperationsBeforeRequestBinding(t *testing.T) {
	backend := &fakeBackend{}
	events := []string{}
	operation := func(owner, event string) RegisteredOperation[struct{}] {
		return registeredOperationForTest(
			backend,
			owner,
			func(ctx context.Context, binding ExecutorBinding, _ struct{}) error {
				return backend.stage(ctx, binding, owner, event)
			},
			func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error {
				events = append(events, event)
				return port.Execute(ctx)
			},
		)
	}
	participants := []TypedParticipant[struct{}]{
		{Key: "first", Operation: operation("owner_a", "first")},
		{Key: "second", After: []string{"first"}, Operation: operation("owner_b", "second")},
	}
	template, contract, err := NewPlanContract(ContractVersionV1, "frozen_typed_contract", participants, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	participants[0].Key = "injected"
	participants[0].Operation = operation("request_owner", "injected")
	participants[1].After[0] = "injected"
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, struct{}{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"first", "second"}) {
		t.Fatalf("caller mutation changed frozen contract: %v", events)
	}
}

func TestPlanContractsRejectInvalidDefinitionsAndMismatchesBeforeBegin(t *testing.T) {
	backend := &fakeBackend{}
	validParticipants := []TypedParticipant[testInvocation]{
		{Key: "first", DeclaresWrite: true, Operation: passthroughOperationForTest(backend, "owner_a", func(testInvocation) string { return "first" })},
		{Key: "second", After: []string{"first"}, DeclaresWrite: true, Operation: passthroughOperationForTest(backend, "owner_b", func(testInvocation) string { return "second" })},
	}
	tests := []struct {
		name    string
		version string
		key     string
		policy  OutboxPolicy
		mutate  func([]TypedParticipant[testInvocation]) []TypedParticipant[testInvocation]
	}{
		{name: "wrong version", version: ContractVersionV1 + ".unknown", key: "operation", policy: OutboxOptional},
		{name: "empty key", version: ContractVersionV1, key: "", policy: OutboxOptional},
		{name: "bad key", version: ContractVersionV1, key: "UPPER", policy: OutboxOptional},
		{name: "no participant", version: ContractVersionV1, key: "operation", policy: OutboxOptional, mutate: func([]TypedParticipant[testInvocation]) []TypedParticipant[testInvocation] { return nil }},
		{name: "bad policy", version: ContractVersionV1, key: "operation", policy: "best_effort"},
		{name: "duplicate participant", version: ContractVersionV1, key: "operation", policy: OutboxOptional, mutate: func(value []TypedParticipant[testInvocation]) []TypedParticipant[testInvocation] {
			value[1].Key = value[0].Key
			return value
		}},
		{name: "unknown dependency", version: ContractVersionV1, key: "operation", policy: OutboxOptional, mutate: func(value []TypedParticipant[testInvocation]) []TypedParticipant[testInvocation] {
			value[1].After = []string{"missing"}
			return value
		}},
		{name: "forward dependency", version: ContractVersionV1, key: "operation", policy: OutboxOptional, mutate: func(value []TypedParticipant[testInvocation]) []TypedParticipant[testInvocation] {
			value[0].After = []string{"second"}
			return value
		}},
		{name: "duplicate dependency", version: ContractVersionV1, key: "operation", policy: OutboxOptional, mutate: func(value []TypedParticipant[testInvocation]) []TypedParticipant[testInvocation] {
			value[1].After = []string{"first", "first"}
			return value
		}},
		{name: "outbox participant", version: ContractVersionV1, key: "operation", policy: OutboxOptional, mutate: func(value []TypedParticipant[testInvocation]) []TypedParticipant[testInvocation] {
			value[0].Key = "core_outbox"
			return value
		}},
		{name: "nil operation", version: ContractVersionV1, key: "operation", policy: OutboxOptional, mutate: func(value []TypedParticipant[testInvocation]) []TypedParticipant[testInvocation] {
			value[0].Operation = RegisteredOperation[testInvocation]{}
			return value
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			participants := cloneTypedParticipants(validParticipants)
			if testCase.mutate != nil {
				participants = testCase.mutate(participants)
			}
			if _, _, err := NewPlanContract(testCase.version, testCase.key, participants, testCase.policy); err == nil {
				t.Fatal("invalid typed template accepted")
			}
		})
	}
	tooMany := make([]TypedParticipant[testInvocation], maxParticipants+1)
	sharedOperation := passthroughOperationForTest(backend, "owner", func(testInvocation) string { return "participant" })
	for index := range tooMany {
		tooMany[index] = TypedParticipant[testInvocation]{
			Key:       "p." + string(rune('a'+index%26)) + string(rune('a'+index/26)),
			Operation: sharedOperation,
		}
	}
	if _, _, err := NewPlanContract(ContractVersionV1, "operation", tooMany, OutboxOptional); err == nil {
		t.Fatal("participant limit not enforced")
	}
	if _, err := NewRegistry(nil); err == nil {
		t.Fatal("empty registry accepted")
	}

	template, contract := registeredTestPlan(backend, make([]participantControl, 1), OutboxRequired)
	if _, err := NewRegistry([]PlanTemplate{template, template}); err == nil {
		t.Fatal("duplicate template accepted")
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.Bind(registry, testInvocation{}, nil); err == nil {
		t.Fatal("required outbox omission accepted")
	}
	intent := testIntent()
	if _, err := (PlanContract[testInvocation]{}).Bind(registry, testInvocation{}, &intent); err == nil {
		t.Fatal("zero contract accepted")
	}
	foreignBackend := &fakeBackend{}
	foreignTemplate, foreignContract := registeredTestPlan(foreignBackend, make([]participantControl, 1), OutboxRequired)
	foreignRegistry, err := NewRegistry([]PlanTemplate{foreignTemplate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.Bind(foreignRegistry, testInvocation{}, &intent); err == nil {
		t.Fatal("contract bound to same-key foreign template")
	}
	if _, err := foreignContract.Bind(registry, testInvocation{}, &intent); err == nil {
		t.Fatal("foreign contract bound to registry template")
	}
	pointerTemplate, pointerContract, err := NewPlanContract(
		ContractVersionV1,
		"pointer_invocation",
		[]TypedParticipant[*testInvocation]{
			{Key: "typed", Operation: passthroughOperationForTest(backend, "owner", func(*testInvocation) string { return "typed" })},
		},
		OutboxOptional,
	)
	if err != nil {
		t.Fatal(err)
	}
	pointerRegistry, err := NewRegistry([]PlanTemplate{pointerTemplate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pointerContract.Bind(pointerRegistry, nil, nil); err == nil {
		t.Fatal("typed nil invocation accepted")
	}

	plan, err := contract.Bind(registry, testInvocation{}, &intent)
	if err != nil {
		t.Fatal(err)
	}
	foreignCoordinator := newTestCoordinator(foreignBackend, foreignRegistry, &fakeAppender{backend: foreignBackend}, nil, nil)
	if _, err := foreignCoordinator.Execute(context.Background(), plan); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("foreign plan error = %v", err)
	}
	_, _, beginCalls, _, _, _ := foreignBackend.snapshot()
	if beginCalls != 0 {
		t.Fatal("foreign plan reached Begin")
	}
}

func cloneTypedParticipants[T any](source []TypedParticipant[T]) []TypedParticipant[T] {
	result := make([]TypedParticipant[T], len(source))
	for index, participant := range source {
		result[index] = participant
		result[index].After = append([]string(nil), participant.After...)
	}
	return result
}

func TestEveryFailureAfterBeginRollsBackWithoutPartialSuccessOrRetry(t *testing.T) {
	tests := []struct {
		id           string
		configure    func(*fakeBackend, []participantControl, *fakeAppender, context.CancelFunc)
		wantCode     ErrorCode
		wantBegin    int
		wantCommit   int
		wantRollback int
	}{
		{"begin_error", func(backend *fakeBackend, _ []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			backend.failBegin = true
		}, CodeBeginFailed, 1, 0, 0},
		{"begin_panic", func(backend *fakeBackend, _ []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			backend.panicBegin = true
		}, CodeBeginFailed, 1, 0, 0},
		{"first_participant_error", func(_ *fakeBackend, controls []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			controls[0].fail = true
		}, CodeParticipantFailed, 1, 0, 1},
		{"stale_fence_error", func(_ *fakeBackend, controls []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			controls[1].fail = true
		}, CodeParticipantFailed, 1, 0, 1},
		{"participant_panic", func(_ *fakeBackend, controls []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			controls[0].panic = true
		}, CodeParticipantFailed, 1, 0, 1},
		{"cancellation_between_participants", func(_ *fakeBackend, controls []participantControl, _ *fakeAppender, cancel context.CancelFunc) {
			controls[0].cancel = cancel
		}, CodeCancelled, 1, 0, 1},
		{"outbox_error", func(_ *fakeBackend, _ []participantControl, appender *fakeAppender, _ context.CancelFunc) {
			appender.fail = true
		}, CodeOutboxFailed, 1, 0, 1},
		{"outbox_panic", func(_ *fakeBackend, _ []participantControl, appender *fakeAppender, _ context.CancelFunc) {
			appender.panic = true
		}, CodeOutboxFailed, 1, 0, 1},
		{"commit_error", func(backend *fakeBackend, _ []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			backend.failCommit = true
		}, CodeCommitFailed, 1, 1, 1},
		{"commit_panic", func(backend *fakeBackend, _ []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			backend.panicCommit = true
		}, CodeCommitFailed, 1, 1, 1},
		{"rollback_error", func(backend *fakeBackend, controls []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			controls[0].fail = true
			backend.failRollback = true
		}, CodeRollbackFailed, 1, 0, 1},
		{"rollback_panic", func(backend *fakeBackend, controls []participantControl, _ *fakeAppender, _ context.CancelFunc) {
			controls[0].fail = true
			backend.panicRollback = true
		}, CodeRollbackFailed, 1, 0, 1},
	}
	type failureRecord struct {
		ID            string    `json:"id"`
		ExpectedCode  ErrorCode `json:"expected_code"`
		BeginCalls    int       `json:"begin_calls"`
		CommitCalls   int       `json:"commit_calls"`
		RollbackCalls int       `json:"rollback_calls"`
	}
	data, err := os.ReadFile("../../../../tests/integration/core/transaction_failure_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Scope string          `json:"scope"`
		Cases []failureRecord `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("failure inventory contains trailing data")
	}
	wantInventory := make([]failureRecord, len(tests))
	for index, testCase := range tests {
		wantInventory[index] = failureRecord{testCase.id, testCase.wantCode, testCase.wantBegin, testCase.wantCommit, testCase.wantRollback}
	}
	if inventory.Scope != "P1-015-CORE-PORTS dependency-free rollback contribution" || !reflect.DeepEqual(inventory.Cases, wantInventory) {
		t.Fatalf("failure inventory drifted: scope=%q cases=%#v want=%#v", inventory.Scope, inventory.Cases, wantInventory)
	}
	for _, testCase := range tests {
		t.Run(testCase.id, func(t *testing.T) {
			backend := &fakeBackend{}
			controls := make([]participantControl, 2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			appender := &fakeAppender{backend: backend}
			testCase.configure(backend, controls, appender, cancel)
			template, contract := registeredTestPlan(backend, controls, OutboxRequired)
			registry, err := NewRegistry([]PlanTemplate{template})
			if err != nil {
				t.Fatal(err)
			}
			intent := testIntent()
			plan, err := contract.Bind(registry, testInvocation{}, &intent)
			if err != nil {
				t.Fatal(err)
			}
			report, err := newTestCoordinator(backend, registry, appender, nil, nil).Execute(ctx, plan)
			if ErrorCodeOf(err) != testCase.wantCode {
				t.Fatalf("error = %v, code = %s, want %s", err, ErrorCodeOf(err), testCase.wantCode)
			}
			_, committed, beginCalls, commitCalls, rollbackCalls, rollbackContextLive := backend.snapshot()
			if len(committed) != 0 {
				t.Fatalf("partial success committed: %v", committed)
			}
			if beginCalls != testCase.wantBegin || commitCalls != testCase.wantCommit || rollbackCalls != testCase.wantRollback {
				t.Fatalf("lifecycle = begin:%d commit:%d rollback:%d", beginCalls, commitCalls, rollbackCalls)
			}
			if report.Retries != 0 || beginCalls > 1 {
				t.Fatal("coordinator retried after a decision/effect boundary")
			}
			if rollbackCalls == 1 && !rollbackContextLive {
				t.Fatal("cancellation prevented rollback attempt")
			}
		})
	}
}

func TestCancellationBeforeBeginAndDeadlineFailClosed(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "deadline"}[deadline], func(t *testing.T) {
			backend := &fakeBackend{}
			template, contract := registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)
			registry, err := NewRegistry([]PlanTemplate{template})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := contract.Bind(registry, testInvocation{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(ctx, plan); ErrorCodeOf(err) != CodeCancelled {
				t.Fatalf("error = %v", err)
			}
			_, _, beginCalls, _, _, _ := backend.snapshot()
			if beginCalls != 0 {
				t.Fatal("cancelled operation reached Begin")
			}
		})
	}
}

func TestConcurrentSessionsInterleaveAndKeepCommitRollbackOutboxIndependent(t *testing.T) {
	type invocation struct {
		label string
		fail  bool
	}
	type invocationControl struct {
		entered chan struct{}
		proceed chan struct{}
	}
	backend := &fakeBackend{}
	aEntered, bEntered := make(chan struct{}), make(chan struct{})
	aProceed, bProceed := make(chan struct{}), make(chan struct{})
	controls := map[string]invocationControl{
		"a": {entered: aEntered, proceed: aProceed},
		"b": {entered: bEntered, proceed: bProceed},
	}
	participants := []TypedParticipant[invocation]{
		{Key: "first", DeclaresWrite: true, Operation: passthroughOperationForTest(backend, "owner", func(value invocation) string { return value.label + ":first" })},
		{Key: "second", After: []string{"first"}, DeclaresWrite: true, Operation: registeredOperationForTest(
			backend,
			"owner",
			func(ctx context.Context, binding ExecutorBinding, value invocation) error {
				return backend.stage(ctx, binding, "owner", value.label+":second")
			},
			func(ctx context.Context, port OperationPort[invocation], value invocation) error {
				control := controls[value.label]
				close(control.entered)
				<-control.proceed
				if err := port.Execute(ctx); err != nil {
					return err
				}
				if value.fail {
					return errInjected
				}
				return nil
			},
		)},
	}
	template, contract, err := NewPlanContract(ContractVersionV1, "interleaved_operation", participants, OutboxRequired)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	appender := &fakeAppender{backend: backend}
	coordinator := newTestCoordinator(backend, registry, appender, nil, nil)
	intent := testIntent()
	planA, err := contract.Bind(registry, invocation{label: "a"}, &intent)
	if err != nil {
		t.Fatal(err)
	}
	planB, err := contract.Bind(registry, invocation{label: "b", fail: true}, &intent)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		report Report
		err    error
	}
	results := make(chan result, 2)
	go func() {
		report, err := coordinator.Execute(context.Background(), planA)
		results <- result{report, err}
	}()
	go func() {
		report, err := coordinator.Execute(context.Background(), planB)
		results <- result{report, err}
	}()
	select {
	case <-aEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("session a did not reach interleave point")
	}
	select {
	case <-bEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("session b did not overlap session a")
	}
	close(aProceed)
	close(bProceed)
	first, second := <-results, <-results
	if (first.err == nil) == (second.err == nil) {
		t.Fatalf("results did not independently commit and roll back: %v / %v", first.err, second.err)
	}
	if first.err != nil && ErrorCodeOf(first.err) != CodeParticipantFailed || second.err != nil && ErrorCodeOf(second.err) != CodeParticipantFailed {
		t.Fatalf("unexpected concurrent errors: %v / %v", first.err, second.err)
	}
	committed, rolledBack, active := backend.journals()
	if active != 0 || len(committed) != 1 || len(rolledBack) != 1 {
		t.Fatalf("journals committed=%v rolled-back=%v active=%d", committed, rolledBack, active)
	}
	for _, values := range committed {
		if !reflect.DeepEqual(values, []string{"a:first", "a:second", "outbox"}) {
			t.Fatalf("commit association = %v", values)
		}
	}
	for _, values := range rolledBack {
		if !reflect.DeepEqual(values, []string{"b:first", "b:second"}) {
			t.Fatalf("rollback association = %v", values)
		}
	}
	_, _, beginCalls, commitCalls, rollbackCalls, _ := backend.snapshot()
	if beginCalls != 2 || commitCalls != 1 || rollbackCalls != 1 || appender.callCount() != 1 {
		t.Fatalf("concurrent lifecycle begin=%d commit=%d rollback=%d append=%d", beginCalls, commitCalls, rollbackCalls, appender.callCount())
	}
}

func TestCrossSwappedLiveOperationPortsFailBeforeRepositoryExecution(t *testing.T) {
	type invocation struct {
		index int
		label string
	}
	type exchange struct {
		mu    sync.Mutex
		ports [2]OperationPort[invocation]
		count int
		ready chan struct{}
	}
	backend := &fakeBackend{}
	shared := &exchange{ready: make(chan struct{})}
	operation := registeredOperationForTest(
		backend,
		"owner",
		func(ctx context.Context, binding ExecutorBinding, value invocation) error {
			return backend.stage(ctx, binding, "owner", value.label+":cross-swapped")
		},
		func(ctx context.Context, port OperationPort[invocation], value invocation) error {
			shared.mu.Lock()
			shared.ports[value.index] = port
			shared.count++
			if shared.count == 2 {
				close(shared.ready)
			}
			shared.mu.Unlock()
			<-shared.ready
			shared.mu.Lock()
			foreign := shared.ports[1-value.index]
			shared.mu.Unlock()
			return foreign.Execute(ctx)
		},
	)
	participants := []TypedParticipant[invocation]{
		{Key: "write", DeclaresWrite: true, Operation: operation},
	}
	template, contract, err := NewPlanContract(ContractVersionV1, "cross_swapped_binding", participants, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil)
	plans := make([]Plan, 2)
	for index, label := range []string{"a", "b"} {
		plans[index], err = contract.Bind(registry, invocation{index: index, label: label}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	errorsChannel := make(chan error, 2)
	for _, plan := range plans {
		plan := plan
		go func() { _, err := coordinator.Execute(context.Background(), plan); errorsChannel <- err }()
	}
	for range 2 {
		if err := <-errorsChannel; ErrorCodeOf(err) != CodeParticipantFailed {
			t.Fatalf("cross-swapped binding error = %v", err)
		}
	}
	committed, rolledBack, active := backend.journals()
	if len(committed) != 0 || len(rolledBack) != 2 || active != 0 {
		t.Fatalf("cross-swapped journals committed=%v rolled-back=%v active=%d", committed, rolledBack, active)
	}
	_, _, begins, commits, rollbacks, _ := backend.snapshot()
	if begins != 2 || commits != 0 || rollbacks != 2 {
		t.Fatalf("cross-swapped lifecycle begin=%d commit=%d rollback=%d", begins, commits, rollbacks)
	}
	_, staged, _, _, _, _ := backend.snapshot()
	if len(staged) != 0 {
		t.Fatalf("cross-swapped ports reached repository executor: %v", staged)
	}
}

type crossSwapAppender struct {
	backend *fakeBackend
	mu      sync.Mutex
	scopes  [2]outbox.TransactionScope[SessionBinding, BindingReceipt]
	count   int
	ready   chan struct{}
}

func (appender *crossSwapAppender) Append(_ context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	appender.mu.Lock()
	index := appender.count
	if index >= len(appender.scopes) {
		appender.mu.Unlock()
		return outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}, BindingReceipt{}, errInjected
	}
	appender.scopes[index] = scope
	appender.count++
	if appender.count == len(appender.scopes) {
		close(appender.ready)
	}
	appender.mu.Unlock()
	<-appender.ready
	appender.mu.Lock()
	foreign := appender.scopes[1-index]
	appender.mu.Unlock()
	return appender.backend.stageOutbox(foreign, intent)
}

func TestCrossSwappedLiveOutboxScopesFailExactReceiptVerification(t *testing.T) {
	backend := &fakeBackend{}
	template, contract := registeredTestPlan(backend, make([]participantControl, 1), OutboxRequired)
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	appender := &crossSwapAppender{backend: backend, ready: make(chan struct{})}
	coordinator, err := NewCoordinator(Configuration{Backend: backend.backendContract(), Registry: registry, Outbox: appender})
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent()
	plans := make([]Plan, 2)
	for index, label := range []string{"a:", "b:"} {
		plans[index], err = contract.Bind(registry, testInvocation{Prefix: label}, &intent)
		if err != nil {
			t.Fatal(err)
		}
	}
	errorsChannel := make(chan error, 2)
	for _, plan := range plans {
		plan := plan
		go func() { _, err := coordinator.Execute(context.Background(), plan); errorsChannel <- err }()
	}
	for range 2 {
		if err := <-errorsChannel; ErrorCodeOf(err) != CodeOutboxFailed {
			t.Fatalf("cross-swapped outbox error = %v", err)
		}
	}
	committed, rolledBack, active := backend.journals()
	if len(committed) != 0 || len(rolledBack) != 2 || active != 0 {
		t.Fatalf("cross-swapped outbox journals committed=%v rolled-back=%v active=%d", committed, rolledBack, active)
	}
	_, _, begins, commits, rollbacks, _ := backend.snapshot()
	if begins != 2 || commits != 0 || rollbacks != 2 {
		t.Fatalf("cross-swapped outbox lifecycle begin=%d commit=%d rollback=%d", begins, commits, rollbacks)
	}
}

type receiptDroppingAppender struct{ backend *fakeBackend }

func (appender receiptDroppingAppender) Append(_ context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	_, _, err := appender.backend.stageOutbox(scope, intent)
	return outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}, BindingReceipt{}, err
}

func TestOutboxCannotClaimSuccessWithoutExactScopeAndBindingReceipts(t *testing.T) {
	backend := &fakeBackend{}
	template, contract := registeredTestPlan(backend, make([]participantControl, 1), OutboxRequired)
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(Configuration{Backend: backend.backendContract(), Registry: registry, Outbox: receiptDroppingAppender{backend: backend}})
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent()
	plan, err := contract.Bind(registry, testInvocation{}, &intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Execute(context.Background(), plan); ErrorCodeOf(err) != CodeOutboxFailed {
		t.Fatalf("missing append receipts error = %v", err)
	}
	_, committed, begins, commits, rollbacks, _ := backend.snapshot()
	if begins != 1 || commits != 0 || rollbacks != 1 || len(committed) != 0 {
		t.Fatalf("missing receipt lifecycle begin=%d commit=%d rollback=%d committed=%v", begins, commits, rollbacks, committed)
	}
}

func TestWrongBackendRegistrationCannotConstructCoordinator(t *testing.T) {
	backend := &fakeBackend{}
	foreign := &fakeBackend{}
	participants := []TypedParticipant[struct{}]{
		{Key: "wrong_backend", DeclaresWrite: true, Operation: passthroughOperationForTest(foreign, "owner", func(struct{}) string { return "foreign" })},
	}
	template, _, err := NewPlanContract(ContractVersionV1, "wrong_backend_binding", participants, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(Configuration{Backend: backend.backendContract(), Registry: registry, Outbox: &fakeAppender{backend: backend}}); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("wrong backend error = %v", err)
	}
	_, committed, begins, commits, rollbacks, _ := backend.snapshot()
	_, foreignCommitted, foreignBegins, _, _, _ := foreign.snapshot()
	if begins != 0 || commits != 0 || rollbacks != 0 || len(committed) != 0 || foreignBegins != 0 || len(foreignCommitted) != 0 {
		t.Fatalf("local=%d/%d/%d %v foreign=%d %v", begins, commits, rollbacks, committed, foreignBegins, foreignCommitted)
	}
}

func TestRegisteredOwnerBindingRejectsOwnerSubstitution(t *testing.T) {
	backend := &fakeBackend{}
	type invocation struct{ attemptedOwner string }
	operation := passthroughOperationForTest(backend, "registered_owner", func(invocation) string { return "registered-owner-write" })
	template, contract, err := NewPlanContract(
		ContractVersionV1,
		"owner_substitution",
		[]TypedParticipant[invocation]{
			{Key: "write", DeclaresWrite: true, Operation: operation},
		},
		OutboxOptional,
	)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, invocation{attemptedOwner: "request_selected_owner"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan); err != nil {
		t.Fatalf("fixed owner execution error = %v", err)
	}
	_, committed, begins, commits, rollbacks, _ := backend.snapshot()
	if begins != 1 || commits != 1 || rollbacks != 0 || !reflect.DeepEqual(committed, []string{"registered-owner-write"}) {
		t.Fatalf("owner substitution lifecycle begin=%d commit=%d rollback=%d committed=%v", begins, commits, rollbacks, committed)
	}
}

func TestRetainedAndGoroutineAfterReturnPortsFailWithoutCallingRepository(t *testing.T) {
	backend := &fakeBackend{}
	var retained OperationPort[struct{}]
	var retainedContext context.Context
	done := make(chan error, 1)
	operation := registeredOperationForTest(
		backend,
		"owner",
		func(ctx context.Context, binding ExecutorBinding, _ struct{}) error {
			return backend.stage(ctx, binding, "owner", "local")
		},
		func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error {
			retained = port
			retainedContext = ctx
			if err := port.Execute(ctx); err != nil {
				return err
			}
			go func(copy OperationPort[struct{}], operationContext context.Context) {
				<-time.After(10 * time.Millisecond)
				done <- copy.Execute(operationContext)
			}(port, ctx)
			return nil
		},
	)
	participants := []TypedParticipant[struct{}]{
		{Key: "capture", DeclaresWrite: true, Operation: operation},
	}
	template, contract, err := NewPlanContract(ContractVersionV1, "binding_lifecycle", participants, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, struct{}{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := <-done; ErrorCodeOf(err) != CodeParticipantFailed {
		t.Fatalf("retained goroutine error = %v", err)
	}
	if err := retained.Execute(retainedContext); ErrorCodeOf(err) != CodeParticipantFailed {
		t.Fatalf("retained port err=%v", err)
	}
}

func TestConfigurationRejectsNilDependencies(t *testing.T) {
	backend := &fakeBackend{}
	template, _ := registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	var typedNilAppender *fakeAppender
	for _, configuration := range []Configuration{
		{Registry: registry, Outbox: &fakeAppender{backend: backend}},
		{Backend: backend.backendContract(), Registry: registry},
		{Backend: BackendContract{}, Registry: registry, Outbox: &fakeAppender{backend: backend}},
		{Backend: backend.backendContract(), Registry: registry, Outbox: typedNilAppender},
		{Backend: backend.backendContract(), Registry: Registry{}, Outbox: &fakeAppender{backend: backend}},
	} {
		if _, err := NewCoordinator(configuration); ErrorCodeOf(err) != CodeInvalidContract {
			t.Fatalf("invalid configuration error = %v", err)
		}
	}
}

func TestConfiguredReservedOwnerPortsRequireExactBackendAndOwnerOperations(t *testing.T) {
	backend := &fakeBackend{}
	foreign := &fakeBackend{}
	registry := minimalRegistry(t, backend)
	appender := &fakeAppender{backend: backend}
	finalizer := &fakeFinalizer{backend: backend}
	durable := &fakeDurablePreparation{backend: backend, intent: testIntent()}
	foreignFinal, _ := NewBackendOperation(foreign.backendContract(), FinalAuthorizationOwner, func(context.Context, ExecutorBinding, *FinalAuthorizationAuditOperation) error { return nil })
	wrongFinalOwner, _ := NewBackendOperation(backend.backendContract(), "wrong.final.owner", func(context.Context, ExecutorBinding, *FinalAuthorizationAuditOperation) error { return nil })
	foreignDurable, _ := NewBackendOperation(foreign.backendContract(), DurableEffectOwner, func(context.Context, ExecutorBinding, *DurableEffectOperation) error { return nil })
	wrongDurableOwner, _ := NewBackendOperation(backend.backendContract(), "wrong.durable.owner", func(context.Context, ExecutorBinding, *DurableEffectOperation) error { return nil })
	tests := []Configuration{
		{Backend: backend.backendContract(), Registry: registry, Outbox: appender, FinalAuthorizationAudit: finalizer},
		{Backend: backend.backendContract(), Registry: registry, Outbox: appender, FinalAuthorizationAudit: finalizer, FinalAuthorizationOperation: foreignFinal},
		{Backend: backend.backendContract(), Registry: registry, Outbox: appender, FinalAuthorizationAudit: finalizer, FinalAuthorizationOperation: wrongFinalOwner},
		{Backend: backend.backendContract(), Registry: registry, Outbox: appender, DurableEffectPreparation: durable},
		{Backend: backend.backendContract(), Registry: registry, Outbox: appender, DurableEffectPreparation: durable, DurableEffectOperation: foreignDurable},
		{Backend: backend.backendContract(), Registry: registry, Outbox: appender, DurableEffectPreparation: durable, DurableEffectOperation: wrongDurableOwner},
	}
	for index, configuration := range tests {
		if _, err := NewCoordinator(configuration); ErrorCodeOf(err) != CodeInvalidContract {
			t.Fatalf("case %d accepted mismatched reserved operation: %v", index, err)
		}
	}
	_, _, begins, _, _, _ := backend.snapshot()
	if begins != 0 {
		t.Fatalf("mismatched reserved operation reached Begin %d times", begins)
	}
}

func TestRegistryRejectsTemplatesBoundToDifferentBackends(t *testing.T) {
	backend := &fakeBackend{}
	foreign := &fakeBackend{}
	template, _ := registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)
	foreignTemplate, _, err := NewPlanContract(ContractVersionV1, "foreign_backend_template", []TypedParticipant[struct{}]{
		{Key: "foreign", Operation: passthroughOperationForTest(foreign, "foreign", func(struct{}) string { return "foreign" })},
	}, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistry([]PlanTemplate{template, foreignTemplate}); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("mixed-backend registry error = %v", err)
	}
}

func TestReservedHandoffTemplatesAreFrozenAtCoordinatorConstruction(t *testing.T) {
	backend := &fakeBackend{}
	registry := minimalRegistry(t, backend)
	coordinator := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil)
	if _, exists := registry.templates[finalReadTemplateKey]; exists {
		t.Fatal("caller registry gained reserved template")
	}
	checks := []struct {
		key          string
		owner        string
		policy       OutboxPolicy
		logicalAudit bool
		durable      bool
	}{
		{finalReadTemplateKey, FinalAuthorizationOwner, OutboxOptional, true, false},
		{durableEffectTemplateKey, DurableEffectOwner, OutboxRequired, false, true},
	}
	for _, check := range checks {
		template, ok := coordinator.registry.templates[check.key]
		if !ok || template.definition == nil || len(template.definition.participants) != 1 {
			t.Fatalf("reserved template %q missing or open-ended", check.key)
		}
		participant := template.definition.participants[0]
		if participant.owner != check.owner || participant.logicalAuthorizationAudit != check.logicalAudit ||
			participant.durableEffectHandoff != check.durable || template.definition.outboxPolicy != check.policy {
			t.Fatalf("reserved template %q drifted: %#v", check.key, template)
		}
	}
	conflict, _, err := NewPlanContract(ContractVersionV1, finalReadTemplateKey, []TypedParticipant[struct{}]{
		{Key: "caller_override", Operation: passthroughOperationForTest(backend, "caller", func(struct{}) string { return "caller" })},
	}, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	conflictingRegistry, err := NewRegistry([]PlanTemplate{conflict})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(Configuration{Backend: backend.backendContract(), Registry: conflictingRegistry, Outbox: &fakeAppender{backend: backend}}); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("caller replaced reserved handoff template: %v", err)
	}
}

func FuzzTemplateIdentifiersFailClosed(f *testing.F) {
	f.Add("operation", "participant", "owner")
	f.Add("UPPER", "participant", "owner")
	f.Add("operation", "../escape", "owner")
	f.Fuzz(func(t *testing.T, operation, participant, owner string) {
		backend := &fakeBackend{}
		backendOperation, _ := NewBackendOperation(backend.backendContract(), owner, func(context.Context, ExecutorBinding, struct{}) error { return nil })
		registered, _ := NewRegisteredOperation(backendOperation, func(ctx context.Context, port OperationPort[struct{}], _ struct{}) error { return port.Execute(ctx) })
		_, _, err := NewPlanContract(ContractVersionV1, operation, []TypedParticipant[struct{}]{
			{Key: participant, Operation: registered},
		}, OutboxOptional)
		valid := identifierPattern.MatchString(operation) && identifierPattern.MatchString(participant) && identifierPattern.MatchString(owner) && participant != "core_outbox" && owner != "core_outbox"
		if valid != (err == nil) {
			t.Fatalf("validation mismatch for %q %q %q: %v", operation, participant, owner, err)
		}
	})
}

func TestContractErrorsDoNotExposeInjectedDetails(t *testing.T) {
	err := fail(CodeParticipantFailed)
	if errors.Is(err, errInjected) || err.Error() != "core transaction contract failed: participant_failed" {
		t.Fatalf("unsafe error = %q", err)
	}
}

func TestRegisteredPlanMatchesOwnedFixture(t *testing.T) {
	type participantFixture struct {
		Key           string   `json:"key"`
		Owner         string   `json:"owner"`
		After         []string `json:"after"`
		DeclaresWrite bool     `json:"declares_write"`
	}
	type planFixture struct {
		ContractVersion string               `json:"contract_version"`
		Key             string               `json:"key"`
		OutboxPolicy    OutboxPolicy         `json:"outbox_policy"`
		Participants    []participantFixture `json:"participants"`
	}
	data, err := os.ReadFile("../../../../packages/test-fixtures/core/transaction_plan_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture planFixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("plan fixture contains trailing data")
	}
	backend := &fakeBackend{}
	template, _ := registeredTestPlan(backend, make([]participantControl, 3), OutboxRequired)
	definition := template.definition
	actual := planFixture{ContractVersion: definition.contractVersion, Key: definition.key, OutboxPolicy: definition.outboxPolicy}
	for _, participant := range definition.participants {
		actual.Participants = append(actual.Participants, participantFixture{
			Key: participant.key, Owner: participant.owner, After: append([]string{}, participant.after...), DeclaresWrite: participant.declaresWrite,
		})
	}
	if !reflect.DeepEqual(actual, fixture) {
		t.Fatalf("registered plan fixture drifted\nactual: %#v\nfixture: %#v", actual, fixture)
	}
}
