package classification

import (
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
