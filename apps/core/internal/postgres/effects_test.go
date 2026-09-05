package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/audit"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

// Storage/serialization fixture only, never a Decision, signed activation,
// execution handle or production authorizing path.
func effectStorageFixture(t *testing.T) (authorization.EffectRecord, classification.Label) {
	t.Helper()
	id := func() string {
		v, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	now := time.Now().UTC()
	target := authorization.ResourceRef{Kind: "project", ID: id()}
	e := authorization.Evidence{DecisionID: strings.Repeat("a", 32), Actor: identity.Principal{Type: "user", ID: id()}, SessionID: id(), InstanceID: id(), OrganizationID: id(), SecurityDomain: "storage-unit-only", Action: authorization.ProjectBackingProvision, Target: target, Relation: "manager", EvaluatorContractVersion: authorization.ProviderMutationEvaluatorContractVersion, DisclosureMode: "request_boundary", EvaluatedAt: now, ExpiresAt: now.Add(time.Second), Revisions: authorization.Revisions{Principal: 1, Authority: 1, Attributes: 1, Groups: 1, TeamBindings: 1, Tuples: 1, Session: 1, Delegation: 1, Task: 1, Runtime: 1, Capability: 1, Resource: 1, Label: 1, ExplicitDeny: 1, Provider: 1, Revocation: 1}}
	b := authorization.EffectBinding{EffectID: id(), OperationID: id(), PlanID: id(), RequestID: strings.Repeat("b", 32), Project: target, ProviderInstallationID: id(), CompatibilityProfileID: "unit-only", CompatibilityProfileDigest: "sha256:" + strings.Repeat("c", 64), PlanDigest: "sha256:" + strings.Repeat("d", 64), ProviderRevision: 1, OriginalDeadline: now.Add(time.Second), ProviderNotAfter: now.Add(time.Second)}
	r := authorization.EffectRecord{Binding: b, Authorization: e, Operation: authorization.CreateHiddenTracker, State: authorization.EffectIssued, Version: 1, IssuedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Second), Process: authorization.EffectProcess{BootID: "12345678-1234-4234-8234-123456789abc", PID: 1, StartTicks: 1, Nonce: strings.Repeat("e", 32)}}
	if r.Validate() != nil {
		t.Fatal("invalid storage fixture")
	}
	return r, classification.Label{ProfileID: "storage-unit", SensitivityLevel: "internal", Version: 1}
}

func TestEffectStoreZeroInvocationsNeverReachDatabase(t *testing.T) {
	store := &Store{}
	for _, err := range []error{store.IssueEffect(context.Background(), nil), store.IssueEffect(context.Background(), &authorization.EffectIssue{}), store.ConsumeEffect(context.Background(), nil), store.ConsumeEffect(context.Background(), &authorization.EffectConsume{}), store.TransitionEffect(context.Background(), nil), store.TransitionEffect(context.Background(), &authorization.EffectTransition{})} {
		if err != authorization.ErrDenied {
			t.Fatal("unsealed invocation admitted")
		}
	}
}

func TestEffectOutboxUsesAuthorizationRouteAndClosedPairs(t *testing.T) {
	r, label := effectStorageFixture(t)
	id, _ := NewID()
	payload, err := audit.EffectEvent(id, r, label)
	if err != nil {
		t.Fatal(err)
	}
	got, resource, subject, err := outboxRoute(payload)
	if err != nil || got != id || resource != r.Binding.Project.ID || subject != audit.EffectEventSubject {
		t.Fatal("Project effect routed as Project domain event")
	}
	for _, mutate := range []func(map[string]any){func(v map[string]any) { v["source"] = "urn:stead:producer:project" }, func(v map[string]any) { v["type"] = "stead.authorization.unknown.v1" }, func(v map[string]any) { v["dataschema"] = "wrong" }, func(v map[string]any) {
		v["data"].(map[string]any)["changed_fields"] = []string{"effect_issued", "effect_terminal"}
	}} {
		var v map[string]any
		_ = json.Unmarshal(payload, &v)
		mutate(v)
		bad, _ := json.Marshal(v)
		if _, _, _, err := outboxRoute(bad); err == nil {
			t.Fatal("invalid event route admitted")
		}
	}
	for _, kind := range []string{"organization", "team", "project"} {
		producer := "organization"
		if kind == "project" {
			producer = "project"
		}
		value := map[string]any{"id": id, "source": "urn:stead:producer:" + producer, "type": "stead." + kind + ".created.v1", "data": map[string]any{"resource": authorization.ResourceRef{Kind: kind, ID: resource}}}
		raw, _ := json.Marshal(value)
		if _, _, route, err := outboxRoute(raw); err != nil || route != "stead."+producer+".changed.v1" {
			t.Fatal("existing closed created-event route changed")
		}
		value["source"] = "urn:stead:producer:authorization"
		raw, _ = json.Marshal(value)
		if _, _, _, err := outboxRoute(raw); err == nil {
			t.Fatal("source/type mismatch routed")
		}
	}
}

func TestEffectStoredJSONAndOriginDoNotMintAuthority(t *testing.T) {
	r, _ := effectStorageFixture(t)
	var decoded authorization.EffectRecord
	if strictEffectJSON(encode(r), &decoded) != nil || !reflect.DeepEqual(decoded, r) {
		t.Fatal("storage roundtrip changed expected CAS")
	}
	for _, bad := range [][]byte{nil, []byte(`{"unknown":true}`), append(encode(r), []byte(` {}`)...), []byte(strings.Repeat(" ", (64<<10)+1))} {
		if strictEffectJSON(bad, &decoded) == nil {
			t.Fatal("invalid stored shape admitted")
		}
	}
	changed := r
	changed.State = authorization.EffectConsumed
	changed.Version++
	if !sameEffectOrigin(r, changed) {
		t.Fatal("local committed lifecycle lost original identity")
	}
	for _, mutate := range []func(*authorization.EffectRecord){func(v *authorization.EffectRecord) { v.Binding.OperationID = v.Binding.EffectID }, func(v *authorization.EffectRecord) { v.Process.Nonce = strings.Repeat("f", 32) }, func(v *authorization.EffectRecord) { v.Authorization.SessionID = v.Authorization.Actor.ID }, func(v *authorization.EffectRecord) { v.Binding.PlanDigest = "sha256:" + strings.Repeat("f", 64) }} {
		changed = r
		mutate(&changed)
		if sameEffectOrigin(r, changed) {
			t.Fatal("foreign operation inherited local bookkeeping provenance")
		}
	}
}

// Reproduces the formerly accepted SQL subset: indexed identities and terminal
// markers are present, but the actor, operation, process and lifetime are not.
func truncatedTerminalRecord(record authorization.EffectRecord) []byte {
	return encode(map[string]any{
		"State": authorization.EffectTerminal, "Version": record.Version,
		"TerminalOutcome": authorization.EffectCanceledBeforeEffect, "TerminalProofDigest": "",
		"Authorization": map[string]any{"SessionID": record.Authorization.SessionID},
		"Binding": map[string]any{"EffectID": record.Binding.EffectID, "OperationID": record.Binding.OperationID,
			"Project": map[string]any{"id": record.Binding.Project.ID}},
	})
}

func caseAliasedTerminalRecord(record authorization.EffectRecord) []byte {
	record.State = authorization.EffectConsumed
	var value map[string]any
	_ = json.Unmarshal(encode(record), &value)
	value["state"] = authorization.EffectTerminal
	value["terminaloutcome"] = authorization.EffectCanceledBeforeEffect
	return encode(value)
}

func TestEffectRowRequiresCompleteRecordIndexesAndLabel(t *testing.T) {
	r, label := effectStorageFixture(t)
	r.State, r.TerminalOutcome, r.Version = authorization.EffectTerminal, authorization.EffectCanceledBeforeEffect, 2
	stored := storedEffectRow{id: r.Binding.EffectID, operationID: r.Binding.OperationID, projectID: r.Binding.Project.ID,
		sessionID: r.Authorization.SessionID, state: string(r.State), version: r.Version, raw: encode(r), labelRaw: encode(label)}
	if _, _, err := stored.decode(); err != nil {
		t.Fatal("complete stored cancellation rejected", err)
	}
	for name, mutate := range map[string]func(*storedEffectRow){
		"truncated_terminal": func(v *storedEffectRow) { v.raw = truncatedTerminalRecord(r) },
		"case_aliased_terminal": func(v *storedEffectRow) {
			consumed := r
			consumed.TerminalOutcome = ""
			v.raw = caseAliasedTerminalRecord(consumed)
		},
		"wrong_effect":    func(v *storedEffectRow) { v.id = r.Binding.OperationID },
		"wrong_operation": func(v *storedEffectRow) { v.operationID = r.Binding.EffectID },
		"wrong_project":   func(v *storedEffectRow) { v.projectID = r.Binding.EffectID },
		"wrong_session":   func(v *storedEffectRow) { v.sessionID = r.Binding.EffectID },
		"wrong_state":     func(v *storedEffectRow) { v.state = string(authorization.EffectIssued) },
		"wrong_version":   func(v *storedEffectRow) { v.version++ },
		"truncated_label": func(v *storedEffectRow) { v.labelRaw = []byte(`{"version":1}`) },
		"wrong_label_revision": func(v *storedEffectRow) {
			changed := label
			changed.Version++
			v.labelRaw = encode(changed)
		},
		"unsupported_label": func(v *storedEffectRow) {
			changed := label
			changed.Compartments = []string{"not-supported-by-native-policy"}
			v.labelRaw = encode(changed)
		},
		"oversize_record": func(v *storedEffectRow) { v.raw = append(v.raw, []byte(strings.Repeat(" ", 64<<10))...) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := stored
			mutate(&changed)
			if _, _, err := changed.decode(); err == nil {
				t.Fatal("invalid complete effect row admitted")
			}
		})
	}
}

func TestEffectStoredJSONExactRecursiveWriterShape(t *testing.T) {
	r, label := effectStorageFixture(t)
	// Serialization-only check, not an issuable lifecycle version. Both values
	// are exactly representable by uint64 but not by float64.
	r.Version = (1 << 53) + 1
	r.Process.StartTicks = (1 << 53) + 3
	var formatted bytes.Buffer
	if json.Indent(&formatted, encode(r), "", "  ") != nil {
		t.Fatal("fixture formatting")
	}
	var roundtrip authorization.EffectRecord
	if strictEffectJSON(formatted.Bytes(), &roundtrip) != nil || !reflect.DeepEqual(roundtrip, r) {
		t.Fatal("JSONB-compatible whitespace or integer identity lost")
	}
	var reordered map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encode(r)))
	decoder.UseNumber()
	if decoder.Decode(&reordered) != nil || strictEffectJSON(encode(reordered), &roundtrip) != nil || !reflect.DeepEqual(roundtrip, r) {
		t.Fatal("JSONB-compatible key reordering changed integer identity")
	}
	for name, mutate := range map[string]func(map[string]any){
		"case_alias": func(v map[string]any) { v["state"] = v["State"] },
		"case_replacement": func(v map[string]any) {
			v["state"] = v["State"]
			delete(v, "State")
		},
		"nested_alias": func(v map[string]any) { v["Process"].(map[string]any)["pid"] = json.Number("1") },
		"nested_actor_alias": func(v map[string]any) {
			v["Authorization"].(map[string]any)["Actor"].(map[string]any)["Type"] = "user"
		},
		"missing_zero_field": func(v map[string]any) { delete(v, "TerminalProofDigest") },
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			decoder := json.NewDecoder(bytes.NewReader(encode(r)))
			decoder.UseNumber()
			if decoder.Decode(&value) != nil {
				t.Fatal("fixture decoding")
			}
			mutate(value)
			if strictEffectJSON(encode(value), &roundtrip) == nil {
				t.Fatal("non-writer recursive field shape accepted")
			}
		})
	}
	for _, raw := range [][]byte{
		[]byte(`{"profile_id":"storage-unit","sensitivity_level":"internal","version":1,"Version":1}`),
		[]byte(`{"profile_id":"storage-unit","sensitivity_level":"internal","version":1,"compartments":null}`),
		[]byte(`{"profile_id":"storage-unit","sensitivity_level":"internal","version":1,"compartments":[]}`),
	} {
		if strictEffectJSON(raw, &label) == nil {
			t.Fatal("non-writer label alias or omitted dimension accepted")
		}
	}
}
