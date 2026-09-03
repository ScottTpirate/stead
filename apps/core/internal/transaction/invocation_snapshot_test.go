package transaction

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

type snapshotPointerValue struct {
	Name string
}

type snapshotCompositeValue struct {
	Pointer    *snapshotPointerValue
	Items      []string
	Attributes map[string]string
}

type snapshotAllShapes struct {
	Flag       bool
	Integer    int64
	Unsigned   uint64
	Ratio      float64
	Text       string
	Pointer    *string
	NilPointer *string
	Bytes      []byte
	Values     []snapshotPointerValue
	NilSlice   []string
	Array      [2]int
	Mapping    map[int]*string
	NilMap     map[string]string
	Nested     snapshotPointerValue
}

type snapshotCustomCodec []byte

func (snapshotCustomCodec) MarshalJSON() ([]byte, error) { return []byte(`"custom"`), nil }
func (*snapshotCustomCodec) UnmarshalJSON([]byte) error  { return nil }

var _ json.Marshaler = snapshotCustomCodec{}

type snapshotHiddenState struct {
	Values []string
	hidden string
}

type snapshotTaggedState struct {
	Values []string `json:"values"`
}

type snapshotBlankTaggedState struct {
	Values []string `json:""`
}

type snapshotEmbeddedState struct {
	*snapshotPointerValue
}

func executeSnapshotMutationTest[T any](t *testing.T, value T, mutate func(), render func(T) string) []string {
	t.Helper()
	backend := &fakeBackend{}
	operation := passthroughOperationForTest(backend, "work", render)
	template, contract, err := NewPlanContract(
		ContractVersionV1,
		"snapshot_mutation",
		[]TypedParticipant[T]{{Key: "write", DeclaresWrite: true, Operation: operation}},
		OutboxOptional,
	)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, value, nil)
	if err != nil {
		t.Fatal(err)
	}
	mutate()
	if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	_, committed, _, _, _, _ := backend.snapshot()
	return committed
}

func TestBindSnapshotsPointerSliceAndMapBeforeCallerCanMutateThem(t *testing.T) {
	t.Run("pointer", func(t *testing.T) {
		value := &snapshotPointerValue{Name: "authorized"}
		committed := executeSnapshotMutationTest(t, value, func() { value.Name = "substituted" }, func(snapshot *snapshotPointerValue) string { return snapshot.Name })
		if !reflect.DeepEqual(committed, []string{"authorized"}) {
			t.Fatalf("pointer snapshot committed = %v", committed)
		}
	})

	t.Run("slice", func(t *testing.T) {
		value := []string{"authorized"}
		committed := executeSnapshotMutationTest(t, value, func() { value[0] = "substituted" }, func(snapshot []string) string { return snapshot[0] })
		if !reflect.DeepEqual(committed, []string{"authorized"}) {
			t.Fatalf("slice snapshot committed = %v", committed)
		}
	})

	t.Run("map", func(t *testing.T) {
		value := map[string]string{"scope": "authorized"}
		committed := executeSnapshotMutationTest(t, value, func() { value["scope"] = "substituted" }, func(snapshot map[string]string) string { return snapshot["scope"] })
		if !reflect.DeepEqual(committed, []string{"authorized"}) {
			t.Fatalf("map snapshot committed = %v", committed)
		}
	})
}

func TestInvocationSnapshotRoundTripsAllSupportedReferenceShapes(t *testing.T) {
	text := "pointer"
	original := &snapshotAllShapes{
		Flag:     true,
		Integer:  -42,
		Unsigned: 42,
		Ratio:    1.25,
		Text:     "text",
		Pointer:  &text,
		Bytes:    []byte{0, 1, 2, 255},
		Values:   []snapshotPointerValue{{Name: "first"}, {Name: "second"}},
		Array:    [2]int{3, 4},
		Mapping:  map[int]*string{7: &text},
		Nested:   snapshotPointerValue{Name: "nested"},
	}
	profile, err := newInvocationSnapshotProfile[*snapshotAllShapes]()
	if err != nil || !profile.referenceBearing {
		t.Fatalf("snapshot profile = %#v, %v", profile, err)
	}
	snapshot, err := captureImmutableInvocation(profile, original)
	if err != nil {
		t.Fatal(err)
	}
	first, err := snapshot.view()
	if err != nil || !reflect.DeepEqual(first, original) {
		t.Fatalf("first snapshot = %#v, %v", first, err)
	}
	first.Pointer = new(string)
	first.Bytes[0] = 99
	first.Values[0].Name = "changed"
	first.Mapping[7] = new(string)
	second, err := snapshot.view()
	if err != nil || !reflect.DeepEqual(second, original) {
		t.Fatalf("second snapshot aliased first: %#v, %v", second, err)
	}

	corrupt := snapshot
	corrupt.encoded = append([]byte(nil), snapshot.encoded...)
	corrupt.encoded[0] ^= 0xff
	if _, err := corrupt.view(); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("corrupt snapshot error = %v", err)
	}
	corrupt = snapshot
	corrupt.digest = [32]byte{}
	if _, err := corrupt.view(); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("wrong digest error = %v", err)
	}
}

func TestInvocationSnapshotRejectsUnsupportedTypeProfiles(t *testing.T) {
	assertRejected := func(name string, err error) {
		t.Helper()
		if ErrorCodeOf(err) != CodeInvalidContract {
			t.Fatalf("%s profile error = %v", name, err)
		}
	}
	_, err := newInvocationSnapshotProfile[chan struct{}]()
	assertRejected("channel", err)
	_, err = newInvocationSnapshotProfile[func()]()
	assertRejected("function", err)
	_, err = newInvocationSnapshotProfile[complex64]()
	assertRejected("complex", err)
	_, err = newInvocationSnapshotProfile[any]()
	assertRejected("interface", err)
	_, err = newInvocationSnapshotProfile[uintptr]()
	assertRejected("uintptr", err)
	_, err = newInvocationSnapshotProfile[map[float64]string]()
	assertRejected("map key", err)
	_, err = newInvocationSnapshotProfile[*snapshotCustomCodec]()
	assertRejected("custom codec", err)
	_, err = newInvocationSnapshotProfile[*snapshotHiddenState]()
	assertRejected("hidden state", err)
	_, err = newInvocationSnapshotProfile[*snapshotTaggedState]()
	assertRejected("tagged state", err)
	_, err = newInvocationSnapshotProfile[*snapshotBlankTaggedState]()
	assertRejected("blank tagged state", err)
	_, err = newInvocationSnapshotProfile[*snapshotEmbeddedState]()
	assertRejected("embedded state", err)
}

func TestInvocationSnapshotRejectsInvalidOrExcessiveRuntimeValues(t *testing.T) {
	t.Run("not a number", func(t *testing.T) {
		profile, err := newInvocationSnapshotProfile[*snapshotAllShapes]()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := captureImmutableInvocation(profile, &snapshotAllShapes{Ratio: math.NaN()}); ErrorCodeOf(err) != CodeInvalidPlan {
			t.Fatalf("NaN snapshot error = %v", err)
		}
	})

	t.Run("encoded expansion", func(t *testing.T) {
		profile, err := newInvocationSnapshotProfile[*snapshotPointerValue]()
		if err != nil {
			t.Fatal(err)
		}
		value := &snapshotPointerValue{Name: strings.Repeat("\x00", maxInvocationSnapshotBytes/5)}
		if _, err := captureImmutableInvocation(profile, value); ErrorCodeOf(err) != CodeInvalidPlan {
			t.Fatalf("expanded snapshot error = %v", err)
		}
	})

	t.Run("node count", func(t *testing.T) {
		profile, err := newInvocationSnapshotProfile[[]string]()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := captureImmutableInvocation(profile, make([]string, maxInvocationSnapshotNodes)); ErrorCodeOf(err) != CodeInvalidPlan {
			t.Fatalf("node-limited snapshot error = %v", err)
		}
	})
}

func TestInvocationSnapshotDefensiveValidationBranches(t *testing.T) {
	if _, err := snapshotTypeContainsReferences(nil, make(map[reflect.Type]bool)); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("nil type error = %v", err)
	}
	arrayType := reflect.TypeFor[[2]string]()
	if referenceBearing, err := snapshotTypeContainsReferences(arrayType, make(map[reflect.Type]bool)); err != nil || referenceBearing {
		t.Fatalf("array profile = %t, %v", referenceBearing, err)
	}
	if referenceBearing, err := snapshotTypeContainsReferences(arrayType, map[reflect.Type]bool{arrayType: true}); err != nil || !referenceBearing {
		t.Fatalf("recursive profile = %t, %v", referenceBearing, err)
	}
	if validateSerializedSnapshotType(nil, make(map[reflect.Type]bool)) ||
		validateSerializedSnapshotType(reflect.TypeFor[complex64](), make(map[reflect.Type]bool)) {
		t.Fatal("unsupported serialized type accepted")
	}

	budget := &snapshotBudget{}
	if err := budget.consume(-1); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("negative budget error = %v", err)
	}
	if err := validateSnapshotValue(reflect.Value{}, 0, &snapshotBudget{}, make(map[snapshotVisit]bool)); err != nil {
		t.Fatalf("invalid reflect value error = %v", err)
	}
	if err := validateSnapshotValue(reflect.ValueOf(make(chan struct{})), 0, &snapshotBudget{}, make(map[snapshotVisit]bool)); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("unsupported runtime value error = %v", err)
	}
	if err := validateSnapshotValue(reflect.ValueOf(make([]byte, maxInvocationSnapshotNodes)), 0, &snapshotBudget{}, make(map[snapshotVisit]bool)); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("byte-node budget error = %v", err)
	}
	if err := validateSnapshotValue(reflect.ValueOf([]string{strings.Repeat("x", maxInvocationSnapshotBytes+1)}), 0, &snapshotBudget{}, make(map[snapshotVisit]bool)); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("slice-element budget error = %v", err)
	}

	malformed := immutableInvocationSnapshot[*snapshotPointerValue]{
		profile: invocationSnapshotProfile{referenceBearing: true},
		encoded: []byte("{"),
	}
	malformed.digest = sha256.Sum256(malformed.encoded)
	if _, err := malformed.view(); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("malformed snapshot error = %v", err)
	}
}

func TestEveryParticipantAndDeferredIntentReceivesIndependentSnapshotView(t *testing.T) {
	render := func(value *snapshotCompositeValue) string {
		return fmt.Sprintf("%s|%s|%s", value.Pointer.Name, value.Items[0], value.Attributes["scope"])
	}
	backend := &fakeBackend{}
	firstBackend, err := NewBackendOperation(backend.backendContract(), "authorization", func(ctx context.Context, session Session, value *snapshotCompositeValue) error {
		return backend.stage(ctx, session, "authorization", "authorized:"+render(value))
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewRegisteredOperation(firstBackend, func(ctx context.Context, port OperationPort[*snapshotCompositeValue], value *snapshotCompositeValue) error {
		if err := port.Execute(ctx); err != nil {
			return err
		}
		value.Pointer.Name = "participant-mutated"
		value.Items[0] = "participant-mutated"
		value.Attributes["scope"] = "participant-mutated"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	second := passthroughOperationForTest(backend, "work", func(value *snapshotCompositeValue) string {
		return "written:" + render(value)
	})
	template, contract, err := NewPlanContract(
		ContractVersionV1,
		"independent_snapshot_views",
		[]TypedParticipant[*snapshotCompositeValue]{
			{Key: "authorize", DeclaresWrite: true, Operation: first},
			{Key: "write", After: []string{"authorize"}, DeclaresWrite: true, Operation: second},
		},
		OutboxRequired,
	)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	value := &snapshotCompositeValue{
		Pointer:    &snapshotPointerValue{Name: "resource-a"},
		Items:      []string{"item-a"},
		Attributes: map[string]string{"scope": "scope-a"},
	}
	deferredObserved := ""
	plan, err := contract.bindImmutable(registry, value, nil, func(snapshot *snapshotCompositeValue) *outbox.ValidatedIntent {
		deferredObserved = render(snapshot)
		intent := testIntent()
		return &intent
	})
	if err != nil {
		t.Fatal(err)
	}
	value.Pointer.Name = "caller-mutated"
	value.Items[0] = "caller-mutated"
	value.Attributes["scope"] = "caller-mutated"

	if _, err := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil).Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	wantView := "resource-a|item-a|scope-a"
	_, committed, _, _, _, _ := backend.snapshot()
	wantCommitted := []string{"authorized:" + wantView, "written:" + wantView, "outbox"}
	if !reflect.DeepEqual(committed, wantCommitted) || deferredObserved != wantView {
		t.Fatalf("snapshot views split: committed=%v deferred=%q", committed, deferredObserved)
	}
}

func TestCoordinatorOwnedResultCarriersCannotUseThePublicBindingPath(t *testing.T) {
	backend := &fakeBackend{}
	template, contract := registeredTestPlan(backend, make([]participantControl, 1), OutboxOptional)
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := newTestCoordinator(backend, registry, &fakeAppender{backend: backend}, nil, nil)
	if _, err := coordinator.finalReadContract.Bind(coordinator.registry, &FinalAuthorizationAuditOperation{}, nil); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("public result-carrier binding error = %v", err)
	}
	if _, err := contract.bindCoordinatorOwned(registry, testInvocation{}, nil); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("caller contract used coordinator binding: %v", err)
	}
}

type snapshotNode struct {
	Next *snapshotNode
}

func TestInvocationSnapshotLimitsAndUnsupportedTypesFailBeforeBegin(t *testing.T) {
	backend := &fakeBackend{}
	operation := passthroughOperationForTest(backend, "work", func(*snapshotPointerValue) string { return "unused" })
	template, contract, err := NewPlanContract(
		ContractVersionV1,
		"bounded_snapshot",
		[]TypedParticipant[*snapshotPointerValue]{{Key: "write", Operation: operation}},
		OutboxOptional,
	)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.Bind(registry, &snapshotPointerValue{Name: strings.Repeat("x", maxInvocationSnapshotBytes+1)}, nil); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("oversize snapshot error = %v", err)
	}

	nodeBackendOperation, err := NewBackendOperation(backend.backendContract(), "work", func(context.Context, Session, *snapshotNode) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	nodeOperation, err := NewRegisteredOperation(nodeBackendOperation, func(ctx context.Context, port OperationPort[*snapshotNode], _ *snapshotNode) error {
		return port.Execute(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeTemplate, nodeContract, err := NewPlanContract(ContractVersionV1, "bounded_depth", []TypedParticipant[*snapshotNode]{{Key: "write", Operation: nodeOperation}}, OutboxOptional)
	if err != nil {
		t.Fatal(err)
	}
	nodeRegistry, err := NewRegistry([]PlanTemplate{nodeTemplate})
	if err != nil {
		t.Fatal(err)
	}
	root := &snapshotNode{}
	cursor := root
	for range maxInvocationSnapshotDepth + 1 {
		cursor.Next = &snapshotNode{}
		cursor = cursor.Next
	}
	if _, err := nodeContract.Bind(nodeRegistry, root, nil); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("deep snapshot error = %v", err)
	}
	cyclic := &snapshotNode{}
	cyclic.Next = cyclic
	if _, err := nodeContract.Bind(nodeRegistry, cyclic, nil); ErrorCodeOf(err) != CodeInvalidPlan {
		t.Fatalf("cyclic snapshot error = %v", err)
	}

	type unsupportedInvocation struct {
		Signal chan struct{}
	}
	unsupportedBackend, err := NewBackendOperation(backend.backendContract(), "work", func(context.Context, Session, unsupportedInvocation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	unsupportedOperation, err := NewRegisteredOperation(unsupportedBackend, func(context.Context, OperationPort[unsupportedInvocation], unsupportedInvocation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewPlanContract(ContractVersionV1, "unsupported_snapshot", []TypedParticipant[unsupportedInvocation]{{Key: "write", Operation: unsupportedOperation}}, OutboxOptional); ErrorCodeOf(err) != CodeInvalidContract {
		t.Fatalf("unsupported snapshot type error = %v", err)
	}
	_, _, beginCalls, _, _, _ := backend.snapshot()
	if beginCalls != 0 {
		t.Fatalf("invalid snapshots reached Begin: %d", beginCalls)
	}
}
