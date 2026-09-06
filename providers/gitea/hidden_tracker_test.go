package gitea

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
)

func trackerPlanFixture(t *testing.T) (*HiddenTrackerAdapter, HiddenTrackerIntent) {
	t.Helper()
	a, err := NewHiddenTrackerAdapter("http://127.0.0.1:13000", "probe-admin", syntheticToken, "019ec4e0-0000-7000-8000-000000000009")
	if err != nil {
		t.Fatal(err)
	}
	return a, HiddenTrackerIntent{EffectID: "019ec4e0-0000-7000-8000-000000000006", OperationID: "019ec4e0-0000-7000-8000-000000000007",
		PlanID: "019ec4e0-0000-7000-8000-000000000008", RequestID: strings.Repeat("a", 32),
		Project: authorization.ResourceRef{Kind: "project", ID: "019ec4e0-0000-7000-8000-000000000005"}, ProviderRevision: 1,
		OriginalDeadline: time.Date(2026, 9, 6, 1, 0, 5, 0, time.UTC), ProviderNotAfter: time.Date(2026, 9, 6, 1, 0, 4, 0, time.UTC)}
}

func TestHiddenTrackerPlanBindsExactSerializedInputAndAllIdentityFields(t *testing.T) {
	a, intent := trackerPlanFixture(t)
	p, err := a.PlanHiddenTracker(intent)
	if err != nil {
		t.Fatal(err)
	}
	b := p.Binding()
	if b.PlanDigest == "" || b.ProviderInstallationID != a.state.installationID || b.CompatibilityProfileID != hiddenTrackerProfile ||
		b.CompatibilityProfileDigest != trackerDigest([]byte(hiddenTrackerContract)) || p.state.name != "stead-tracker-"+intent.Project.ID {
		t.Fatal("missing operation/installation binding")
	}
	// Golden exact bytes make accidental divergence between digest construction
	// and createRepository's shared fixed input immediately observable.
	input, _ := json.Marshal(repositoryCreateInput(p.state.name))
	want := `{"name":"stead-tracker-019ec4e0-0000-7000-8000-000000000005","private":true,"auto_init":true,"default_branch":"main","readme":"Default"}`
	if string(input) != want {
		t.Fatal("fixed tracker input changed")
	}
	for _, mutate := range []func(*HiddenTrackerIntent){
		func(i *HiddenTrackerIntent) { i.EffectID = "019ec4e0-0000-7000-8000-000000000010" },
		func(i *HiddenTrackerIntent) { i.OperationID = "019ec4e0-0000-7000-8000-000000000010" },
		func(i *HiddenTrackerIntent) { i.PlanID = "019ec4e0-0000-7000-8000-000000000010" },
		func(i *HiddenTrackerIntent) { i.RequestID = strings.Repeat("b", 32) },
		func(i *HiddenTrackerIntent) { i.Project.ID = "019ec4e0-0000-7000-8000-000000000010" },
		func(i *HiddenTrackerIntent) { i.ProviderRevision++ },
		func(i *HiddenTrackerIntent) { i.OriginalDeadline = i.OriginalDeadline.Add(time.Nanosecond) },
		func(i *HiddenTrackerIntent) { i.ProviderNotAfter = i.ProviderNotAfter.Add(time.Nanosecond) },
	} {
		other := intent
		mutate(&other)
		changed, err := a.PlanHiddenTracker(other)
		if err != nil || changed.Binding().PlanDigest == b.PlanDigest {
			t.Fatal("input substitution did not change protected digest")
		}
	}
	for _, config := range [][3]string{
		{"http://127.0.0.1:13001", "probe-admin", a.state.installationID},
		{"http://127.0.0.1:13000", "other-admin", a.state.installationID},
		{"http://127.0.0.1:13000", "probe-admin", "019ec4e0-0000-7000-8000-000000000010"},
	} {
		other, err := NewHiddenTrackerAdapter(config[0], config[1], syntheticToken, config[2])
		if err != nil {
			t.Fatal(err)
		}
		changed, err := other.PlanHiddenTracker(intent)
		if err != nil || changed.Binding().PlanDigest == b.PlanDigest {
			t.Fatal("provider target not digest bound")
		}
	}
	// Clock location spelling is not a new logical deadline.
	intent.OriginalDeadline = intent.OriginalDeadline.In(time.FixedZone("unit", -4*60*60))
	intent.ProviderNotAfter = intent.ProviderNotAfter.In(time.FixedZone("unit", -4*60*60))
	canonical, _ := a.PlanHiddenTracker(intent)
	if canonical.Binding().PlanDigest != b.PlanDigest {
		t.Fatal("time encoding destabilized plan")
	}
}

func TestHiddenTrackerInvalidIntentCannotSelectProviderOperation(t *testing.T) {
	a, intent := trackerPlanFixture(t)
	for _, mutate := range []func(*HiddenTrackerIntent){
		func(i *HiddenTrackerIntent) { i.EffectID = "" },
		func(i *HiddenTrackerIntent) { i.OperationID = "" },
		func(i *HiddenTrackerIntent) { i.PlanID = "" },
		func(i *HiddenTrackerIntent) { i.RequestID = "caller-assertion" },
		func(i *HiddenTrackerIntent) { i.Project.Kind = "repository" },
		func(i *HiddenTrackerIntent) { i.Project.ID = "../../anything" },
		func(i *HiddenTrackerIntent) { i.ProviderRevision = 0 },
		func(i *HiddenTrackerIntent) { i.OriginalDeadline = time.Time{} },
		func(i *HiddenTrackerIntent) { i.ProviderNotAfter = time.Time{} },
	} {
		bad := intent
		mutate(&bad)
		if p, err := a.PlanHiddenTracker(bad); p != nil || err == nil {
			t.Fatal("invalid owner input admitted")
		}
	}
	var absent *HiddenTrackerAdapter
	if p, err := absent.PlanHiddenTracker(intent); p != nil || err == nil {
		t.Fatal("nil adapter admitted plan")
	}
	if a, err := NewHiddenTrackerAdapter("http://127.0.0.1:13000", "probe-admin", syntheticToken, "unknown"); a != nil || err == nil {
		t.Fatal("unbound installation admitted")
	}
}

func TestHiddenTrackerOpaqueSurfaceDoesNotExposeRawIOOrReceipt(t *testing.T) {
	for _, value := range []any{HiddenTrackerAdapter{}, HiddenTrackerPlan{}, HiddenTrackerPending{}} {
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).IsExported() {
				t.Fatal("exported protected field")
			}
		}
		if data, err := json.Marshal(value); err != nil || string(data) != "{}" || !strings.Contains(fmt.Sprintf("%#v", value), "[private]") {
			t.Fatal("opaque value disclosed state")
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(&HiddenTrackerAdapter{}), reflect.TypeOf(&HiddenTrackerPlan{}), reflect.TypeOf(&HiddenTrackerPending{})} {
		for _, name := range []string{"Request", "Do", "Run", "Raw", "Client", "Token", "Body", "Repository", "Receipt", "Confirm", "Terminal", "Restore", "UnmarshalJSON"} {
			if _, exists := typ.MethodByName(name); exists {
				t.Fatal("raw I/O or proof bypass method")
			}
		}
	}
	method, ok := reflect.TypeOf(&HiddenTrackerAdapter{}).MethodByName("CreateHiddenTracker")
	if !ok || method.Type.NumIn() != 3 || method.Type.In(1) != reflect.TypeOf(&HiddenTrackerPlan{}) || method.Type.In(2) != reflect.TypeOf(&authorization.EffectExecution{}) {
		t.Fatal("dispatch accepts an arbitrary binding, callback or fake execution interface")
	}
}
