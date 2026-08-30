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
)

func TestRegisteredPlanRunsSeriallyAndOutboxLast(t *testing.T) {
	backend := &fakeBackend{}
	var captured [3]OwnerCapability
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
	template := registeredTestPlan(backend, controls, OutboxRequired)
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}

	// Mutating the caller's registration slices after startup cannot change the
	// frozen registry order or dependencies.
	template.Participants[0].Key = "mutated"
	template.Participants[1].After[0] = "mutated"

	intent := testIntent()
	plan, err := registry.Bind("test_operation", &intent)
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
	if beginCalls != 1 || commitCalls != 1 || rollbackCalls != 0 || appender.calls != 1 || maxFlight != 1 {
		t.Fatalf("lifecycle counts = begin:%d commit:%d rollback:%d append:%d max-flight:%d", beginCalls, commitCalls, rollbackCalls, appender.calls, maxFlight)
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
	for index, capability := range captured {
		if capability.ValidFor("owner_" + string(rune('a'+index))) {
			t.Fatalf("participant %d retained a live capability", index)
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
	registry, err := NewRegistry([]PlanTemplate{registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := registry.Bind("test_operation", nil)
	if err != nil {
		t.Fatal(err)
	}
	appender := &fakeAppender{backend: backend}
	report, err := newTestCoordinator(backend, registry, appender, nil, nil).Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if report.OutboxParticipantCalls != 1 || report.OutboxAppendCalls != 0 || appender.calls != 0 {
		t.Fatalf("optional outbox counts = %#v, appender=%d", report, appender.calls)
	}
	_, committed, _, _, _, _ := backend.snapshot()
	if !reflect.DeepEqual(committed, []string{"participant_a"}) {
		t.Fatalf("committed = %v", committed)
	}
}

func TestPlanAndRegistryRejectInvalidOrForeignBindingsBeforeBegin(t *testing.T) {
	backend := &fakeBackend{}
	valid := registeredTestPlan(backend, make([]participantControl, 2), OutboxRequired)
	tests := []struct {
		name   string
		mutate func(*PlanTemplate)
	}{
		{"wrong version", func(value *PlanTemplate) { value.ContractVersion = ContractVersionV1 + ".unknown" }},
		{"empty key", func(value *PlanTemplate) { value.Key = "" }},
		{"bad key", func(value *PlanTemplate) { value.Key = "UPPER" }},
		{"no participant", func(value *PlanTemplate) { value.Participants = nil }},
		{"bad policy", func(value *PlanTemplate) { value.OutboxPolicy = "best_effort" }},
		{"duplicate participant", func(value *PlanTemplate) { value.Participants[1].Key = value.Participants[0].Key }},
		{"unknown dependency", func(value *PlanTemplate) { value.Participants[1].After = []string{"missing"} }},
		{"forward dependency", func(value *PlanTemplate) { value.Participants[0].After = []string{value.Participants[1].Key} }},
		{"duplicate dependency", func(value *PlanTemplate) {
			value.Participants[1].After = []string{value.Participants[0].Key, value.Participants[0].Key}
		}},
		{"outbox participant", func(value *PlanTemplate) { value.Participants[0].Key = "core_outbox" }},
		{"outbox owner", func(value *PlanTemplate) { value.Participants[0].Owner = "core_outbox" }},
		{"nil operation", func(value *PlanTemplate) { value.Participants[0].Operation = nil }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := cloneTemplate(valid)
			testCase.mutate(&candidate)
			if _, err := NewRegistry([]PlanTemplate{candidate}); err == nil {
				t.Fatal("invalid template accepted")
			}
		})
	}
	tooMany := cloneTemplate(valid)
	tooMany.Participants = make([]ParticipantTemplate, maxParticipants+1)
	for index := range tooMany.Participants {
		tooMany.Participants[index] = ParticipantTemplate{Key: "p." + string(rune('a'+index%26)) + string(rune('a'+index/26)), Owner: "owner", Operation: func(context.Context, OwnerCapability) error { return nil }}
	}
	if _, err := NewRegistry([]PlanTemplate{tooMany}); err == nil {
		t.Fatal("participant limit not enforced")
	}
	if _, err := NewRegistry(nil); err == nil {
		t.Fatal("empty registry accepted")
	}
	if _, err := NewRegistry([]PlanTemplate{valid, valid}); err == nil {
		t.Fatal("duplicate template accepted")
	}

	registry, err := NewRegistry([]PlanTemplate{valid})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Bind("missing", nil); err == nil {
		t.Fatal("unknown template accepted")
	}
	if _, err := registry.Bind("test_operation", nil); err == nil {
		t.Fatal("required outbox omission accepted")
	}
	if _, err := (Registry{}).Bind("test_operation", nil); err == nil {
		t.Fatal("zero registry accepted")
	}

	intent := testIntent()
	plan, err := registry.Bind("test_operation", &intent)
	if err != nil {
		t.Fatal(err)
	}
	foreignRegistry, err := NewRegistry([]PlanTemplate{cloneTemplate(valid)})
	if err != nil {
		t.Fatal(err)
	}
	foreignBackend := &fakeBackend{}
	foreignCoordinator := newTestCoordinator(foreignBackend, foreignRegistry, &fakeAppender{backend: foreignBackend}, nil, nil)
	if _, err := foreignCoordinator.Execute(context.Background(), plan); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("foreign plan error = %v", err)
	}
	_, _, beginCalls, _, _, _ := foreignBackend.snapshot()
	if beginCalls != 0 {
		t.Fatal("foreign plan reached Begin")
	}
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
			registry, err := NewRegistry([]PlanTemplate{registeredTestPlan(backend, controls, OutboxRequired)})
			if err != nil {
				t.Fatal(err)
			}
			intent := testIntent()
			plan, err := registry.Bind("test_operation", &intent)
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

func TestCancellationBeforeBeginAndDeadlineAfterParticipantFailClosed(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "deadline"}[deadline], func(t *testing.T) {
			backend := &fakeBackend{}
			registry, err := NewRegistry([]PlanTemplate{registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := registry.Bind("test_operation", nil)
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

func cloneTemplate(source PlanTemplate) PlanTemplate {
	result := source
	result.Participants = make([]ParticipantTemplate, len(source.Participants))
	for index, participant := range source.Participants {
		result.Participants[index] = participant
		result.Participants[index].After = append([]string(nil), participant.After...)
	}
	return result
}

func TestConfigurationRejectsNilDependencies(t *testing.T) {
	backend := &fakeBackend{}
	registry, err := NewRegistry([]PlanTemplate{registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)})
	if err != nil {
		t.Fatal(err)
	}
	var typedNilBackend *fakeBackend
	var typedNilAppender *fakeAppender
	for _, configuration := range []Configuration{
		{Registry: registry, Outbox: &fakeAppender{backend: backend}},
		{Backend: backend, Registry: registry},
		{Backend: typedNilBackend, Registry: registry, Outbox: &fakeAppender{backend: backend}},
		{Backend: backend, Registry: registry, Outbox: typedNilAppender},
		{Backend: backend, Registry: Registry{}, Outbox: &fakeAppender{backend: backend}},
	} {
		if _, err := NewCoordinator(configuration); ErrorCodeOf(err) != CodeInvalidContract {
			t.Fatalf("invalid configuration error = %v", err)
		}
	}
}

func TestReservedHandoffTemplatesAreFrozenAtCoordinatorConstruction(t *testing.T) {
	backend := &fakeBackend{}
	registry := minimalRegistry(t, backend)
	coordinator := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil)

	if _, err := registry.Bind(finalReadTemplateKey, nil); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("caller registry gained reserved template: %v", err)
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
		if !ok || len(template.participants) != 1 {
			t.Fatalf("reserved template %q missing or open-ended", check.key)
		}
		participant := template.participants[0]
		if participant.Owner != check.owner || participant.Operation == nil || participant.logicalAuthorizationAudit != check.logicalAudit ||
			participant.durableEffectHandoff != check.durable || template.outboxPolicy != check.policy {
			t.Fatalf("reserved template %q drifted: %#v", check.key, template)
		}
	}

	conflict := PlanTemplate{
		ContractVersion: ContractVersionV1,
		Key:             finalReadTemplateKey,
		Participants: []ParticipantTemplate{{
			Key: "caller_override", Owner: "caller", Operation: func(context.Context, OwnerCapability) error { return nil },
		}},
		OutboxPolicy: OutboxOptional,
	}
	conflictingRegistry, err := NewRegistry([]PlanTemplate{conflict})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(Configuration{
		Backend: backend, Registry: conflictingRegistry, Outbox: &fakeAppender{backend: backend},
	}); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("caller replaced reserved handoff template: %v", err)
	}
}

func FuzzTemplateIdentifiersFailClosed(f *testing.F) {
	f.Add("operation", "participant", "owner")
	f.Add("UPPER", "participant", "owner")
	f.Add("operation", "../escape", "owner")
	f.Fuzz(func(t *testing.T, operation, participant, owner string) {
		template := PlanTemplate{
			ContractVersion: ContractVersionV1,
			Key:             operation,
			Participants: []ParticipantTemplate{{
				Key: participant, Owner: owner, Operation: func(context.Context, OwnerCapability) error { return nil },
			}},
			OutboxPolicy: OutboxOptional,
		}
		_, err := NewRegistry([]PlanTemplate{template})
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
	template := registeredTestPlan(backend, make([]participantControl, 3), OutboxRequired)
	actual := planFixture{ContractVersion: template.ContractVersion, Key: template.Key, OutboxPolicy: template.OutboxPolicy}
	for _, participant := range template.Participants {
		actual.Participants = append(actual.Participants, participantFixture{
			Key: participant.Key, Owner: participant.Owner, After: append([]string{}, participant.After...), DeclaresWrite: participant.DeclaresWrite,
		})
	}
	if !reflect.DeepEqual(actual, fixture) {
		t.Fatalf("registered plan fixture drifted\nactual: %#v\nfixture: %#v", actual, fixture)
	}
}
