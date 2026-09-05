package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
	fixedmodel "github.com/ScottTpirate/stead/policies/openfga"
)

// These unit fixtures are never embedded, accepted by the public source gate,
// or emitted as installer evidence. The real installer runs the reviewed
// native row/mutation/dependency commands; this fake tests its capture parser.
type localUnitRunner struct {
	template LocalTemplateManifest
	now      time.Time
	calls    int
	fail     bool
}

func (runner *localUnitRunner) Run(_ context.Context, request LocalCheckRequest) (LocalCheckCapture, error) {
	runner.calls++
	if runner.fail {
		return LocalCheckCapture{}, errors.New("test runner failure")
	}
	var spec LocalCheckSpec
	for _, candidate := range runner.template.Core.Checks {
		if candidate.ID == request.ID {
			spec = candidate
		}
	}
	report := LocalCheckReport{SchemaVersion: "1.0.0", CheckID: request.ID, SubjectDigest: request.SubjectDigest, SourceRevision: request.SourceRevision, SourceTree: request.SourceTree, Total: len(spec.Cases), Passed: len(spec.Cases), Cases: []LocalCheckCase{}}
	for _, id := range spec.Cases {
		report.Cases = append(report.Cases, LocalCheckCase{ID: id, Passed: true})
	}
	data, _ := json.Marshal(report)
	return LocalCheckCapture{Stdout: data, Stderr: []byte{}, StartedAt: runner.now, FinishedAt: runner.now.Add(time.Millisecond)}, nil
}

func localUnitTemplate() LocalTemplateManifest {
	digest := "sha256:" + strings.Repeat("1", 64)
	core := LocalTemplateCore{SourceRevision: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40), GoVersion: runtime.Version(), DependencyLockDigest: digest, PublicOrigin: "https://localhost:18443", OpenFGAURL: "http://127.0.0.1:18080", SecurityDomain: LocalDevelopmentSecurityDomain, ValiditySeconds: 86400, AllowedSubstitutions: append([]string{}, localSubstitutionFields...)}
	for _, path := range localSourceFiles {
		core.Files = append(core.Files, LocalTemplateFile{Path: path, Digest: digest})
	}
	for _, id := range []string{"policy-conformance", "critical-mutations", "dependency-review", "offline-verification"} {
		rate := 100
		if id == "critical-mutations" {
			rate = 90
		}
		core.Checks = append(core.Checks, LocalCheckSpec{ID: id, Cases: []string{"unit-parser-case"}, RequiredRate: rate})
	}
	core.Checks[0].Cases = LocalPolicyDecisionCaseIDs()
	manifest := LocalTemplateManifest{SchemaVersion: "1.0.0", Status: "approved", Core: core}
	for _, role := range []string{"architecture-contract-owner", "qa", "security"} {
		manifest.Reviews = append(manifest.Reviews, LocalTemplateReview{Role: role, ReviewerID: "unit-" + role, SourceRevision: core.SourceRevision, CoreDigest: LocalTemplateCoreDigest(core), RecordPath: localReviewPath, RecordDigest: digest, Disposition: "accept"})
	}
	return manifest
}

func localUnitWorkflow(t *testing.T) *policyrelease.ObservedWorkflow {
	t.Helper()
	retained := []policyrelease.LifecycleEvent{}
	workflow, err := policyrelease.NewObservedWorkflow(policyrelease.LifecycleContext{OperationID: "unit-local", CorrelationID: "unit-local", CausationID: "unit-local"}, policyrelease.LifecycleObserverFunc(func(event policyrelease.LifecycleEvent) (policyrelease.LifecycleAcknowledgement, error) {
		retained = append(retained, event)
		return policyrelease.AcknowledgeLifecycleEvent(event), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func localUnitDraft(t *testing.T) (*LocalDevelopmentDraft, *localUnitRunner) {
	t.Helper()
	now := time.Now().UTC()
	template := localUnitTemplate()
	runner := &localUnitRunner{template: template, now: now}
	modelJSON, err := fixedmodel.ModelJSON()
	if err != nil {
		t.Fatal(err)
	}
	model := &ModelReceipt{storeID: modelID, modelID: modelID, sourceDigest: policyrelease.SHA256Digest(modelJSON)}
	config := LocalDevelopmentConfig{InstallationID: instanceID, PublicOrigin: template.Core.PublicOrigin, OpenFGAURL: template.Core.OpenFGAURL, InstallerID: "stead-local-development-installer", Now: now, LocalDevelopment: true, Runner: runner, Workflow: localUnitWorkflow(t)}
	draft, err := prepareLocalDraft(config, template, nil, model)
	if err != nil {
		t.Fatal(err)
	}
	return draft, runner
}

func TestLocalDerivationRoundTripUsesRealSignaturesAndProductionRejects(t *testing.T) {
	draft, runner := localUnitDraft(t)
	artifacts, err := draft.Finalize(context.Background())
	if err != nil {
		t.Fatalf("round trip: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	if runner.calls != 4 || !artifacts.Activation.valid || artifacts.Anchor.Binding.EvidenceKind != "local-development-derivation-v1" || draft.key != nil {
		t.Fatal("missing local evidence or key retained")
	}
	if _, err := draft.Finalize(context.Background()); err != ErrDenied {
		t.Fatal("reused compiler/key")
	}
	if _, err := policyrelease.ParseDSSEEnvelope(artifacts.DerivationEnvelope); err == nil {
		t.Fatal("production accepted development envelope")
	}
	if _, _, err := localUnitWorkflow(t).ValidateActivationArchive(artifacts.Archive); err == nil {
		t.Fatal("production accepted development evidence")
	}
	input := LocalDevelopmentLoadInput{Archive: artifacts.Archive, DerivationEnvelope: artifacts.DerivationEnvelope, TrustedKeys: artifacts.TrustedKeys, Anchor: artifacts.Anchor, Now: runner.now, LocalDevelopment: true, Workflow: localUnitWorkflow(t)}
	if _, err := verifyLocalDevelopment(input, draft.template, draft.model); err != nil {
		t.Fatal("restart failed")
	}
	for name, mutate := range map[string]func(*LocalDevelopmentLoadInput){
		"non-local":           func(i *LocalDevelopmentLoadInput) { i.LocalDevelopment = false },
		"expired":             func(i *LocalDevelopmentLoadInput) { i.Now = i.Now.Add(24 * time.Hour) },
		"anchor-rewound":      func(i *LocalDevelopmentLoadInput) { i.Anchor.PolicyTimeHighWater = i.Now.Add(-time.Second) },
		"wrong-instance":      func(i *LocalDevelopmentLoadInput) { i.Anchor.Binding.InstallationID = userID },
		"wrong-evidence-kind": func(i *LocalDevelopmentLoadInput) { i.Anchor.Binding.EvidenceKind = "" },
		"archive-corrupt":     func(i *LocalDevelopmentLoadInput) { i.Archive = append([]byte{}, i.Archive...); i.Archive[0] ^= 1 },
		"foreign-root": func(i *LocalDevelopmentLoadInput) {
			i.TrustedKeys = append([]TrustedKey{}, i.TrustedKeys...)
			i.TrustedKeys[0].CustodianID = "other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := input
			mutate(&changed)
			if _, err := verifyLocalDevelopment(changed, draft.template, draft.model); err != ErrDenied {
				t.Fatal("unsafe local activation accepted")
			}
		})
	}
}

func TestLocalDevelopmentPublicEntryRejectsUnreviewedTemplate(t *testing.T) {
	if _, err := loadLocalTemplate(context.Background(), "."); err != ErrDenied {
		t.Fatal("pending template admitted")
	}
	if _, err := PrepareLocalDevelopment(context.Background(), LocalDevelopmentConfig{}); err != ErrDenied {
		t.Fatal("implicit local mode admitted")
	}
	if _, err := LoadLocalDevelopment(context.Background(), LocalDevelopmentLoadInput{}); err != ErrDenied {
		t.Fatal("production admitted development")
	}
}

func TestLocalCapturedEvidenceRequiresExactResultsAndThreshold(t *testing.T) {
	draft, runner := localUnitDraft(t)
	spec := draft.template.Core.Checks[0]
	capture, err := draft.runCheck(context.Background(), spec, draft.subject, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*policyrelease.LocalDevelopmentCheckEvidence){
		"nonzero-exit": func(c *policyrelease.LocalDevelopmentCheckEvidence) { c.ExitCode = 1 },
		"wrong-subject": func(c *policyrelease.LocalDevelopmentCheckEvidence) {
			c.SubjectDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"before-issue": func(c *policyrelease.LocalDevelopmentCheckEvidence) {
			c.StartedAt = runner.now.Add(-time.Second).Format(time.RFC3339)
		},
		"after-expiry": func(c *policyrelease.LocalDevelopmentCheckEvidence) {
			c.FinishedAt = runner.now.Add(24 * time.Hour).Format(time.RFC3339)
		},
		"empty": func(c *policyrelease.LocalDevelopmentCheckEvidence) { c.Stdout = "" },
		"unknown-field": func(c *policyrelease.LocalDevelopmentCheckEvidence) {
			c.Stdout = `{"injected":true,` + c.Stdout[1:]
		},
		"duplicate-field": func(c *policyrelease.LocalDevelopmentCheckEvidence) {
			c.Stdout = `{"schema_version":"1.0.0",` + c.Stdout[1:]
		},
		"false-pass-count": func(c *policyrelease.LocalDevelopmentCheckEvidence) {
			var r LocalCheckReport
			json.Unmarshal([]byte(c.Stdout), &r)
			r.Cases[0].Passed = false
			c.Stdout = string(mustJSON(r))
		},
		"missing-case": func(c *policyrelease.LocalDevelopmentCheckEvidence) {
			var r LocalCheckReport
			json.Unmarshal([]byte(c.Stdout), &r)
			r.Cases = nil
			c.Stdout = string(mustJSON(r))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := capture
			mutate(&changed)
			if validateLocalCheck(draft.template, spec, draft.subject, changed, draft.manifest.IssuedAt, draft.manifest.ExpiresAt) != ErrDenied {
				t.Fatal("untrustworthy capture admitted")
			}
		})
	}
	runner.fail = true
	if _, err := draft.Finalize(context.Background()); err == nil {
		t.Fatal("runner failure signed")
	}
	if draft.key != nil {
		t.Fatal("failed signing key retained")
	}
}

func TestLocalTemplateBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*LocalTemplateManifest){
		"missing-review":      func(m *LocalTemplateManifest) { m.Reviews = m.Reviews[:2] },
		"same-reviewer":       func(m *LocalTemplateManifest) { m.Reviews[1].ReviewerID = m.Reviews[0].ReviewerID },
		"wrong-review-source": func(m *LocalTemplateManifest) { m.Reviews[0].SourceRevision = strings.Repeat("c", 40) },
		"network-broadened":   func(m *LocalTemplateManifest) { m.Core.OpenFGAURL = "http://0.0.0.0:18080" },
		"policy-substitution": func(m *LocalTemplateManifest) {
			m.Core.AllowedSubstitutions = append(m.Core.AllowedSubstitutions, "rules")
		},
		"renewal-window":       func(m *LocalTemplateManifest) { m.Core.ValiditySeconds = 86401 },
		"mutation-weakened":    func(m *LocalTemplateManifest) { m.Core.Checks[1].RequiredRate = 89 },
		"conformance-weakened": func(m *LocalTemplateManifest) { m.Core.Checks[0].RequiredRate = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			m := localUnitTemplate()
			mutate(&m)
			if validateLocalTemplate(m) != ErrDenied {
				t.Fatal("template boundary changed")
			}
		})
	}
}
