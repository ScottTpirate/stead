package classification

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ScottTpirate/stead/modules/identity"
)

func evaluatorFixture(t *testing.T) (*Evaluator, Label, identity.SessionRecord) {
	t.Helper()
	profile, err := os.ReadFile("../authorization/contract/profile-commercial.json")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := os.ReadFile("../authorization/contract/deployment-local.json")
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := CompileValidatedProfile(profile, domain)
	if err != nil {
		t.Fatal(err)
	}
	label := Label{ProfileID: evaluator.profile.ID, SensitivityLevel: "internal", Version: 1}
	session := identity.SessionRecord{SecurityDomain: evaluator.domain.ID, Authority: "stead_local_identity", NetworkZone: "loopback", ClassificationCeilings: map[string]string{evaluator.profile.ID: "internal"}}
	return evaluator, label, session
}

// Exercise the profile rules themselves, not only fixed local-policy rows.
// Matching rules deny unsupported semantic requirements; unrelated rules must
// not silently alter an otherwise valid sensitivity-only label.
func TestNativeClassificationSemanticRuleBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, rules string
		denied      bool
	}{
		{"implication", `{"implications":[{"when_all":[{"dimension":"sensitivity","id":"internal"}],"require_all":[{"dimension":"sensitivity","id":"public"}]}]}`, true},
		{"unrelated-implication", `{"implications":[{"when_all":[{"dimension":"sensitivity","id":"restricted"}],"require_all":[{"dimension":"sensitivity","id":"public"}]}]}`, false},
		{"incompatibility", `{"incompatibilities":[{"all_of":[{"dimension":"sensitivity","id":"internal"}]}]}`, true},
		{"unrelated-incompatibility", `{"incompatibilities":[{"all_of":[{"dimension":"sensitivity","id":"restricted"}]}]}`, false},
		{"sensitivity-constraint", `{"sensitivity_constraints":[{"when_any":[{"dimension":"sensitivity","id":"internal"}],"allowed_sensitivity_levels":["public"]}]}`, true},
		{"unrelated-constraint", `{"sensitivity_constraints":[{"when_any":[{"dimension":"sensitivity","id":"restricted"}],"allowed_sensitivity_levels":["public"]}]}`, false},
		{"dimension", `{"dimension_requirements":[{"when_all":[{"dimension":"sensitivity","id":"internal"}]}]}`, true},
		{"unrelated-dimension", `{"dimension_requirements":[{"when_all":[{"dimension":"sensitivity","id":"restricted"}]}]}`, false},
		{"context", `{"context_requirements":[{"when_all":[{"dimension":"sensitivity","id":"internal"}]}]}`, true},
		{"unrelated-context", `{"context_requirements":[{"when_all":[{"dimension":"sensitivity","id":"restricted"}]}]}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			evaluator, label, session := evaluatorFixture(t)
			if err := json.Unmarshal([]byte(test.rules), &evaluator.profile.Semantics); err != nil {
				t.Fatal(err)
			}
			result, err := evaluator.Evaluate(label, session)
			if test.denied {
				if err != ErrDenied || result.DenialReason != "profile_handling_denied" {
					t.Fatal("matching semantic requirement was ignored", result, err)
				}
			} else if err != nil || result.Marking != "Internal" {
				t.Fatal("unrelated requirement changed allow", result, err)
			}
		})
	}
}

func TestNativeClassificationFacts(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		change       func(*Label, *identity.SessionRecord)
	}{
		{"allowed", "", func(*Label, *identity.SessionRecord) {}},
		{"ceiling", "ceiling_exceeded", func(l *Label, _ *identity.SessionRecord) { l.SensitivityLevel = "restricted" }},
		{"unknown-level", "ceiling_exceeded", func(l *Label, _ *identity.SessionRecord) { l.SensitivityLevel = "unknown" }},
		{"compartment", "compartment_missing", func(l *Label, _ *identity.SessionRecord) { l.Compartments = []string{"need"} }},
		{"dissemination", "dissemination_denied", func(l *Label, _ *identity.SessionRecord) { l.DisseminationControls = []string{"limit"} }},
		{"affiliation", "affiliation_denied", func(l *Label, _ *identity.SessionRecord) { l.ReleasableTo = []string{"organization"} }},
		{"category", "profile_handling_denied", func(l *Label, _ *identity.SessionRecord) { l.Categories = []string{"unknown"} }},
		{"handling", "profile_handling_denied", func(l *Label, _ *identity.SessionRecord) { l.HandlingRegimes = []string{"unknown"} }},
		{"authority", "trusted_attribute_invalid", func(_ *Label, s *identity.SessionRecord) { s.Authority = "untrusted" }},
		{"network", "context_denied", func(_ *Label, s *identity.SessionRecord) { s.NetworkZone = "public" }},
		{"domain", "context_denied", func(_ *Label, s *identity.SessionRecord) { s.SecurityDomain = "other" }},
		{"unknown-profile", "context_denied", func(l *Label, _ *identity.SessionRecord) { l.ProfileID = "unknown" }},
		{"missing-revision", "context_denied", func(l *Label, _ *identity.SessionRecord) { l.Version = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			evaluator, label, session := evaluatorFixture(t)
			test.change(&label, &session)
			result, err := evaluator.Evaluate(label, session)
			if (err == nil) != (test.reason == "") || result.DenialReason != test.reason {
				t.Fatalf("unexpected classifier result: %+v %v", result, err)
			}
		})
	}
}
