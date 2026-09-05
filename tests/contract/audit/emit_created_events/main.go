// This executable emits synthetic inputs through the actual Go event producer
// for the existing JSON Schema gate. It is not a runtime/bootstrap activation.
package main

import (
	"encoding/json"
	"github.com/ScottTpirate/stead/modules/audit"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"os"
	"strings"
	"time"
)

func main() {
	events := []json.RawMessage{}
	for _, kind := range []string{"organization", "team", "project"} {
		resource := organization.Resource{ID: "019ed5bf-0000-7000-8000-000000000001", Kind: kind, OrganizationID: "019ed5bf-0000-7000-8000-000000000001", Version: 1, CreatedAt: time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC), CreatedBy: identity.Principal{Type: "user", ID: "019ed5bf-0000-7000-8000-000000000002"}, Label: classification.Label{ProfileID: "local", SensitivityLevel: "internal", Version: 1}}
		data, err := audit.CreatedEvent("019ed5bf-0000-7000-8000-000000000003", resource, "schema-fixture-001", "synthetic-test-domain", "schema-fixture-request")
		if err != nil {
			panic(err)
		}
		events = append(events, data)
	}
	// Closed synthetic lifecycle records exercise the actual WS-07 encoder and
	// complete AsyncAPI/OWGP schemas; they do not mint a permit or activation.
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	id := func(suffix string) string { return "019ed5bf-0000-7000-8000-0000000000" + suffix }
	project := authorization.ResourceRef{Kind: "project", ID: id("01")}
	evidence := authorization.Evidence{DecisionID: strings.Repeat("a", 32), Actor: identity.Principal{Type: "user", ID: id("02")},
		SessionID: id("03"), InstanceID: id("04"), OrganizationID: id("05"), Target: project,
		Action: authorization.ProjectBackingProvision, Relation: "manager", SecurityDomain: "synthetic-test-domain",
		EvaluatorContractVersion: authorization.ProviderMutationEvaluatorContractVersion, DisclosureMode: "request_boundary",
		EvaluatedAt: now, ExpiresAt: now.Add(time.Second),
		Revisions: authorization.Revisions{Principal: 1, Authority: 1, Attributes: 1, Groups: 1, TeamBindings: 1, Tuples: 1,
			Session: 1, Delegation: 1, Task: 1, Runtime: 1, Capability: 1, Resource: 1, Label: 1, ExplicitDeny: 1, Provider: 1, Revocation: 1}}
	record := authorization.EffectRecord{Authorization: evidence, Operation: authorization.CreateHiddenTracker,
		Binding: authorization.EffectBinding{EffectID: id("06"), OperationID: id("07"), PlanID: id("08"), RequestID: strings.Repeat("b", 32),
			Project: project, ProviderInstallationID: id("09"), CompatibilityProfileID: "unit-only",
			CompatibilityProfileDigest: "sha256:" + strings.Repeat("c", 64), PlanDigest: "sha256:" + strings.Repeat("d", 64),
			ProviderRevision: 1, OriginalDeadline: now.Add(time.Second), ProviderNotAfter: now.Add(time.Second)},
		Process:  authorization.EffectProcess{BootID: "12345678-1234-4234-8234-123456789abc", PID: 1, StartTicks: 1, Nonce: strings.Repeat("e", 32)},
		IssuedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Second)}
	for index, state := range []authorization.EffectState{authorization.EffectIssued, authorization.EffectConsumed, authorization.EffectReconciling, authorization.EffectTerminal} {
		record.State, record.Version = state, uint64(index+1)
		if state == authorization.EffectTerminal {
			record.TerminalOutcome = authorization.EffectCanceledBeforeEffect
		}
		data, err := audit.EffectEvent(id([]string{"0a", "0b", "0c", "0d"}[index]), record, classification.Label{ProfileID: "local", SensitivityLevel: "internal", Version: 1})
		if err != nil {
			panic(err)
		}
		events = append(events, data)
	}
	if err := json.NewEncoder(os.Stdout).Encode(events); err != nil {
		panic(err)
	}
}
