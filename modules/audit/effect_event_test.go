package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

// A serialization fixture only. This record is not a signed activation,
// committed effect, provider result, or live User authorization.
func effectEventFixture() (string, authorization.EffectRecord, classification.Label) {
	ids := []string{
		"019ec4e0-0000-7000-8000-000000000001", "019ec4e0-0000-7000-8000-000000000002",
		"019ec4e0-0000-7000-8000-000000000003", "019ec4e0-0000-7000-8000-000000000004",
		"019ec4e0-0000-7000-8000-000000000005", "019ec4e0-0000-7000-8000-000000000006",
		"019ec4e0-0000-7000-8000-000000000007", "019ec4e0-0000-7000-8000-000000000008",
		"019ec4e0-0000-7000-8000-000000000009", "019ec4e0-0000-7000-8000-00000000000a",
	}
	now := time.Date(2026, 9, 5, 20, 0, 0, 0, time.UTC)
	ref := authorization.ResourceRef{Kind: "project", ID: ids[4]}
	e := authorization.Evidence{DecisionID: strings.Repeat("a", 32), Actor: identity.Principal{Type: "user", ID: ids[0]},
		SessionID: ids[1], InstanceID: ids[2], OrganizationID: ids[3], Target: ref, Action: authorization.ProjectBackingProvision,
		Relation: "manager", SecurityDomain: "synthetic-unit", EvaluatorContractVersion: authorization.ProviderMutationEvaluatorContractVersion,
		DisclosureMode: "request_boundary", EvaluatedAt: now, ExpiresAt: now.Add(time.Second),
		Revisions: authorization.Revisions{Principal: 1, Authority: 1, Attributes: 1, Groups: 1, TeamBindings: 1, Tuples: 1,
			Session: 1, Delegation: 1, Task: 1, Runtime: 1, Capability: 1, Resource: 1, Label: 1, ExplicitDeny: 1, Provider: 1, Revocation: 1}}
	binding := authorization.EffectBinding{EffectID: ids[5], OperationID: ids[6], PlanID: ids[7], RequestID: strings.Repeat("b", 32), Project: ref,
		ProviderInstallationID: ids[8], CompatibilityProfileID: "unit-only", CompatibilityProfileDigest: "sha256:" + strings.Repeat("c", 64),
		PlanDigest: "sha256:" + strings.Repeat("d", 64), ProviderRevision: 1, OriginalDeadline: now.Add(time.Second), ProviderNotAfter: now.Add(time.Second)}
	record := authorization.EffectRecord{Binding: binding, Authorization: e, Operation: authorization.CreateHiddenTracker,
		State: authorization.EffectIssued, Version: 1, IssuedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Second),
		Process: authorization.EffectProcess{BootID: "12345678-1234-4234-8234-123456789abc", PID: 1, StartTicks: 1, Nonce: strings.Repeat("e", 32)}}
	return ids[9], record, classification.Label{ProfileID: "unit", SensitivityLevel: "internal", Version: 1}
}

func TestEffectEventCanonicalClosedLifecycleAndRouting(t *testing.T) {
	id, record, label := effectEventFixture()
	for _, state := range []authorization.EffectState{authorization.EffectIssued, authorization.EffectConsumed, authorization.EffectReconciling, authorization.EffectTerminal} {
		record.State = state
		if state == authorization.EffectTerminal {
			record.TerminalOutcome = authorization.EffectCanceledBeforeEffect
		}
		encoded, err := EffectEvent(id, record, label)
		if err != nil {
			t.Fatal(err)
		}
		eventID, projectID, err := DecodeEffectEvent(encoded)
		if err != nil || eventID != id || projectID != record.Binding.Project.ID || EffectEventSubject != "stead.authorization.changed.v1" {
			t.Fatal("lifecycle event lost identity or authorization route")
		}
		for _, protected := range []string{record.Binding.ProviderInstallationID, record.Binding.CompatibilityProfileDigest, record.Binding.PlanDigest, record.Process.Nonce, "TerminalProof", "SessionID"} {
			if bytes.Contains(encoded, []byte(protected)) {
				t.Fatal("protected evidence escaped into event")
			}
		}
	}
}

func TestEffectEventRejectsMismatchedAndNoncanonicalInputs(t *testing.T) {
	id, record, label := effectEventFixture()
	encoded, err := EffectEvent(id, record, label)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*createdEvent){
		func(v *createdEvent) { v.Source = "urn:stead:producer:project" },
		func(v *createdEvent) { v.Type = "stead.project.created.v1" },
		func(v *createdEvent) { v.DataSchema += ".unknown" },
		func(v *createdEvent) { v.Data.ChangedFields = []string{"effect_issued", "effect_terminal"} },
		func(v *createdEvent) { v.Data.ChangedFields = []string{"completed"} },
		func(v *createdEvent) { v.Data.Actor.Actor.Type = "service_account" },
		func(v *createdEvent) { v.Data.Resource.Kind = "team" },
		func(v *createdEvent) { v.Data.Container.ID = record.Binding.Project.ID },
		func(v *createdEvent) { v.Data.Actor.CorrelationID = "caller-selected" },
		func(v *createdEvent) { v.Data.IdempotencyKey = record.Binding.EffectID + ":18446744073709551616" },
		func(v *createdEvent) { v.Data.IdempotencyKey = record.Binding.EffectID + ":01" },
		func(v *createdEvent) { v.Data.Label.Version = 0 },
		func(v *createdEvent) { v.Data.Label.Categories = []string{"restricted"} },
	} {
		var value createdEvent
		_ = json.Unmarshal(encoded, &value)
		mutate(&value)
		bad, _ := json.Marshal(value)
		if _, _, err := DecodeEffectEvent(bad); err == nil {
			t.Fatal("mismatched event admitted")
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), encoded...), ' '), append([]byte(`{"id":"duplicate",`), encoded[1:]...), bytes.Replace(encoded, []byte(`"id":`), []byte(`"ID":`), 1), []byte("{\"x\":\"\xff\"}"), []byte(strings.Repeat(" ", (64<<10)+1))} {
		if _, _, err := DecodeEffectEvent(bad); err == nil {
			t.Fatal("noncanonical event admitted")
		}
	}
	label.Version++
	if _, err := EffectEvent(id, record, label); err == nil {
		t.Fatal("foreign label revision admitted")
	}
}

func TestEffectEventDoesNotReduceUnsupportedLabelsOrRepairInvalidText(t *testing.T) {
	for _, mutate := range []func(*authorization.EffectRecord, *classification.Label){
		func(_ *authorization.EffectRecord, l *classification.Label) {
			l.HandlingRegimes = []string{"restricted"}
		},
		func(_ *authorization.EffectRecord, l *classification.Label) { l.Categories = []string{"restricted"} },
		func(_ *authorization.EffectRecord, l *classification.Label) { l.Compartments = []string{"restricted"} },
		func(_ *authorization.EffectRecord, l *classification.Label) {
			l.DisseminationControls = []string{"restricted"}
		},
		func(_ *authorization.EffectRecord, l *classification.Label) { l.ReleasableTo = []string{"restricted"} },
		func(_ *authorization.EffectRecord, l *classification.Label) {
			l.ExportControls = []string{"restricted"}
		},
		func(_ *authorization.EffectRecord, l *classification.Label) { l.Originator = "restricted" },
		func(_ *authorization.EffectRecord, l *classification.Label) { l.ClassificationAuthority = "restricted" },
		func(_ *authorization.EffectRecord, l *classification.Label) {
			l.DeclassificationOrReviewInstructions = "restricted"
		},
		func(r *authorization.EffectRecord, l *classification.Label) {
			l.DerivationSources = []classification.ResourceRef{{Kind: "project", ID: r.Binding.Project.ID}}
		},
		func(_ *authorization.EffectRecord, l *classification.Label) { l.ProfileID = "\xff" },
		func(_ *authorization.EffectRecord, l *classification.Label) { l.SensitivityLevel = "\xff" },
		func(r *authorization.EffectRecord, _ *classification.Label) { r.Authorization.SecurityDomain = "\xff" },
	} {
		id, record, label := effectEventFixture()
		mutate(&record, &label)
		if _, err := EffectEvent(id, record, label); err == nil {
			t.Fatal("unsupported label dimension or lossy text admitted")
		}
	}
}

func FuzzDecodeEffectEvent(f *testing.F) {
	id, record, label := effectEventFixture()
	encoded, _ := EffectEvent(id, record, label)
	f.Add(encoded)
	f.Add([]byte(`{"type":"stead.authorization.effect_changed.v1"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		event, project, err := DecodeEffectEvent(input)
		if err == nil && (!identity.ValidID(event) || !identity.ValidID(project)) {
			t.Fatal("invalid routing identity admitted")
		}
	})
}
