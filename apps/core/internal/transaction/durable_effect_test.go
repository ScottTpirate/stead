package transaction

import (
	"context"
	"reflect"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

type fakeDurablePreparation struct {
	backend       *fakeBackend
	intent        outbox.ValidatedIntent
	calls         int
	fail          bool
	panic         bool
	zero          bool
	skipOperation bool
	version       string
	opaque        []byte
}

func (preparation *fakeDurablePreparation) Prepare(ctx context.Context, port OperationPort[*DurableEffectOperation], issuer DurableEffectIssuer) (DurableEffectPreparation, error) {
	preparation.calls++
	if preparation.panic {
		panic("injected durable handoff panic")
	}
	if preparation.fail {
		return DurableEffectPreparation{}, errInjected
	}
	if !preparation.skipOperation {
		if err := port.Execute(ctx); err != nil {
			return DurableEffectPreparation{}, err
		}
	}
	if preparation.zero {
		return DurableEffectPreparation{Intent: preparation.intent}, nil
	}
	version := preparation.version
	if version == "" {
		version = DurableEffectHandoffV1
	}
	opaque := preparation.opaque
	if opaque == nil {
		opaque = []byte("opaque-ws06-durable-result")
	}
	durableReceipt, err := issuer.BindValidated(version, opaque)
	if err != nil {
		return DurableEffectPreparation{}, err
	}
	return DurableEffectPreparation{Receipt: durableReceipt, Intent: preparation.intent}, nil
}

func TestDurableEffectHandoffCommitsIntentBeforeReceiptAndPerformsNoEffect(t *testing.T) {
	backend := &fakeBackend{}
	preparation := &fakeDurablePreparation{backend: backend, intent: testIntent()}
	appender := &fakeAppender{backend: backend}
	coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), appender, nil, preparation)
	receipt, report, err := coordinator.PrepareDurableEffect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.state == nil || !receipt.validFor(receipt.state.seal) || preparation.calls != 1 || appender.callCount() != 1 {
		valid := receipt.state != nil && receipt.validFor(receipt.state.seal)
		t.Fatalf("receipt valid=%t prepare=%d append=%d", valid, preparation.calls, appender.callCount())
	}
	calls, committed, _, _, _, _ := backend.snapshot()
	wantCalls := []string{"begin", "durable_effect_preparation", "outbox", "commit"}
	wantCommitted := []string{"durable_effect_preparation", "outbox"}
	if !reflect.DeepEqual(calls, wantCalls) || !reflect.DeepEqual(committed, wantCommitted) {
		t.Fatalf("durable order drifted: calls=%v committed=%v", calls, committed)
	}
	wantReport := Report{BeginCalls: 1, ParticipantCalls: 1, DeclaredWriteParticipantCalls: 1, OutboxParticipantCalls: 1, OutboxAppendCalls: 1, CommitCalls: 1, DurableEffectHandoffs: 1}
	if report != wantReport || report.ProviderCalls != 0 || report.NATSWaits != 0 || report.OpenFGACalls != 0 {
		t.Fatalf("report=%#v", report)
	}
}

func TestDurableEffectFailuresReturnNoReceiptAndRollback(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeDurablePreparation, *fakeAppender, *fakeBackend)
		wantCode  ErrorCode
	}{
		{"owner error", func(value *fakeDurablePreparation, _ *fakeAppender, _ *fakeBackend) { value.fail = true }, CodeParticipantFailed},
		{"owner panic", func(value *fakeDurablePreparation, _ *fakeAppender, _ *fakeBackend) { value.panic = true }, CodeParticipantFailed},
		{"zero receipt", func(value *fakeDurablePreparation, _ *fakeAppender, _ *fakeBackend) { value.zero = true }, CodeParticipantFailed},
		{"missing operation execution", func(value *fakeDurablePreparation, _ *fakeAppender, _ *fakeBackend) { value.skipOperation = true }, CodeParticipantFailed},
		{"wrong version", func(value *fakeDurablePreparation, _ *fakeAppender, _ *fakeBackend) {
			value.version = DurableEffectHandoffV1 + ".unknown"
		}, CodeParticipantFailed},
		{"empty receipt", func(value *fakeDurablePreparation, _ *fakeAppender, _ *fakeBackend) { value.opaque = []byte{} }, CodeParticipantFailed},
		{"invalid intent", func(value *fakeDurablePreparation, _ *fakeAppender, _ *fakeBackend) {
			value.intent = outbox.ValidatedIntent{}
		}, CodeParticipantFailed},
		{"outbox failure", func(_ *fakeDurablePreparation, appender *fakeAppender, _ *fakeBackend) { appender.fail = true }, CodeOutboxFailed},
		{"commit failure", func(_ *fakeDurablePreparation, _ *fakeAppender, backend *fakeBackend) { backend.failCommit = true }, CodeCommitFailed},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeBackend{}
			preparation := &fakeDurablePreparation{backend: backend, intent: testIntent()}
			appender := &fakeAppender{backend: backend}
			testCase.configure(preparation, appender, backend)
			coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), appender, nil, preparation)
			receipt, report, err := coordinator.PrepareDurableEffect(context.Background())
			if ErrorCodeOf(err) != testCase.wantCode || receipt.state != nil || report.Retries != 0 {
				t.Fatalf("error=%v code=%s receipt=%#v report=%#v", err, ErrorCodeOf(err), receipt, report)
			}
			_, committed, beginCalls, _, rollbackCalls, _ := backend.snapshot()
			if beginCalls != 1 || rollbackCalls != 1 || len(committed) != 0 {
				t.Fatalf("begin=%d rollback=%d committed=%v", beginCalls, rollbackCalls, committed)
			}
		})
	}
	backend := &fakeBackend{}
	var typedNil *fakeDurablePreparation
	coordinator := newTestCoordinator(backend, minimalRegistry(t, backend), &fakeAppender{backend: backend}, nil, typedNil)
	if receipt, _, err := coordinator.PrepareDurableEffect(context.Background()); ErrorCodeOf(err) != CodeDurableHandoffFail || receipt.state != nil {
		t.Fatalf("typed-nil result=%#v error=%v", receipt, err)
	}
	_, _, beginCalls, _, _, _ := backend.snapshot()
	if beginCalls != 0 {
		t.Fatal("typed-nil durable port reached Begin")
	}
}

func TestDurableReceiptIsOpaqueImmutableAndVersionStrict(t *testing.T) {
	issuer := newDurableEffectIssuer()
	source := []byte("opaque")
	receipt, err := issuer.BindValidated(DurableEffectHandoffV1, source)
	if err != nil {
		t.Fatal(err)
	}
	seal := issuer.state.seal
	if !issuer.accept(receipt) {
		t.Fatal("issued durable receipt was not accepted")
	}
	issuer.close()
	if receipt.validFor(seal) || !receipt.activate(seal) || !receipt.validFor(seal) || receipt.activate(seal) {
		t.Fatal("durable receipt lifecycle drifted")
	}
	digest := receipt.Digest()
	source[0] ^= 0xff
	copy := receipt.OpaqueCopy()
	copy[0] ^= 0xff
	if receipt.Digest() != digest || !receipt.validFor(seal) || receipt.HandoffVersion() != DurableEffectHandoffV1 {
		t.Fatal("durable receipt was mutable")
	}
	if (DurableEffectReceipt{}).validFor(seal) {
		t.Fatal("zero durable receipt verified")
	}
	late := newDurableEffectIssuer()
	if _, err := late.BindValidated(DurableEffectHandoffV1+".unknown", []byte("opaque")); err == nil {
		t.Fatal("unknown durable version accepted")
	}
	if _, err := late.BindValidated(DurableEffectHandoffV1, nil); err == nil {
		t.Fatal("empty durable handoff accepted")
	}
	late.close()
	if _, err := late.BindValidated(DurableEffectHandoffV1, []byte("late")); err == nil {
		t.Fatal("expired durable issuer accepted value")
	}
}
