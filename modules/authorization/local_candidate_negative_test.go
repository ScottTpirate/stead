package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

// These candidates use real signatures and pass the shared canonical archive
// and content schema validator. They must still fail the central local-template
// semantic checks. Unit parser receipts here are not installer evidence.
func TestLocalResignedCandidatesRejectSemanticChanges(t *testing.T) {
	for _, name := range []string{"profile-marking", "required-context", "missing-report-output", "failed-conformance-report"} {
		t.Run(name, func(t *testing.T) {
			draft, runner := localUnitDraft(t)
			switch name {
			case "profile-marking":
				for index := range draft.files {
					if draft.files[index].Path == "payload/profile.json" {
						original := draft.files[index].Content
						changed := bytes.Replace(original, []byte(`"display_text": "Internal"`), []byte(`"display_text": "Unreviewed marking"`), 1)
						if bytes.Equal(changed, original) {
							t.Fatal("profile fixture mutation absent")
						}
						draft.files[index].Content = changed
						draft.manifest.Profiles[0].Digest = policyrelease.SHA256Digest(changed)
					}
				}
				refreshLocalUnitIndex(t, draft)
			case "required-context":
				draft.manifest.RequiredContextIDs = []string{"local-metadata", "local-session"}
			}
			evidence := policyrelease.LocalDevelopmentEvidenceV1{SchemaVersion: "1.0.0", Kind: "local-development-derivation", TemplateDigest: jsonDigest(draft.template), SubstitutionsDigest: policyrelease.SHA256Digest(draft.substitutions), SourceRevision: draft.template.Core.SourceRevision, SourceTree: draft.template.Core.SourceTree, DependencyLockDigest: draft.template.Core.DependencyLockDigest, InstallerIdentity: draft.config.InstallerID, Reports: []policyrelease.LocalDevelopmentCheckEvidence{}}
			for _, spec := range draft.template.Core.Checks[:3] {
				capture, err := draft.runCheck(context.Background(), spec, draft.subject, nil)
				if err != nil {
					t.Fatal(err)
				}
				evidence.Reports = append(evidence.Reports, capture)
			}
			if name == "missing-report-output" {
				evidence.Reports[0].Stdout = ""
			}
			if name == "failed-conformance-report" {
				var report LocalCheckReport
				if json.Unmarshal([]byte(evidence.Reports[0].Stdout), &report) != nil {
					t.Fatal("fixture report decode")
				}
				report.Cases[0].Passed = false
				report.Passed--
				report.Failed++
				evidence.Reports[0].Stdout = string(mustJSON(report))
			}
			unsigned, err := draft.config.Workflow.PrepareLocalDevelopment(draft.manifest, draft.files, evidence, draft.substitutions)
			if err != nil {
				t.Fatalf("semantic fixture did not reach valid shared schema: %s %v", policyrelease.ErrorCode(err), err)
			}
			envelope, err := localSign(policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, draft.key, draft.keys[0].KeyID)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := policyrelease.ParseDSSEEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := verifySignatures(parsed, draft.keys, 1, false, runner.now); err != nil {
				t.Fatal("candidate signature not valid", err)
			}
			archive, err := draft.config.Workflow.FinalizeLocalDevelopment(unsigned, envelope)
			if err != nil {
				t.Fatal("canonical candidate archive failed", err)
			}
			if _, _, err := localUnitWorkflow(t).ValidateLocalDevelopmentArchive(archive); err != nil {
				t.Fatal("candidate failed shared structural/schema validation", err)
			}
			if _, err := checkLocalCandidate(draft.template, archive, localUnitWorkflow(t), runner.now); err != ErrDenied {
				t.Fatal("signed semantic change admitted")
			}
		})
	}
}

func refreshLocalUnitIndex(t *testing.T, draft *LocalDevelopmentDraft) {
	t.Helper()
	byPath := map[string][]byte{}
	for _, file := range draft.files {
		byPath[file.Path] = file.Content
	}
	for i := range draft.files {
		if draft.files[i].Path != draft.manifest.PolicyContentIndexPath {
			continue
		}
		var index policyrelease.PolicyContentIndexV1
		if json.Unmarshal(draft.files[i].Content, &index) != nil {
			t.Fatal("fixture content index")
		}
		for n := range index.Entries {
			index.Entries[n].Digest = policyrelease.SHA256Digest(byPath[index.Entries[n].Path])
		}
		draft.files[i].Content = mustJSON(index)
		draft.subject = jsonDigest(struct{ TemplateDigest, SubstitutionsDigest, PolicyBundleID string }{jsonDigest(draft.template), policyrelease.SHA256Digest(draft.substitutions), policyrelease.SHA256Digest(draft.files[i].Content)})
		return
	}
	t.Fatal("fixture content index missing")
}
