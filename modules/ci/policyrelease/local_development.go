package policyrelease

import (
	"bytes"
	"sort"
	"strings"
)

const LocalDevelopmentDerivationPayloadType = "application/vnd.stead.local-development-policy-derivation.v1+json"
const LocalDevelopmentSubstitutionsPath = "evidence/local-development-substitutions.json"

// LocalDevelopmentEvidenceV1 is presented installation evidence, not release
// reviews. WS-06 independently verifies the compiled-in reviewed template and
// every captured result. Production evidence parsing rejects this schema.
type LocalDevelopmentEvidenceV1 struct {
	SchemaVersion        string                          `json:"schema_version"`
	Kind                 string                          `json:"kind"`
	TemplateDigest       string                          `json:"template_digest"`
	SubstitutionsDigest  string                          `json:"substitutions_digest"`
	SourceRevision       string                          `json:"source_revision"`
	SourceTree           string                          `json:"source_tree"`
	DependencyLockDigest string                          `json:"dependency_lock_digest"`
	InstallerIdentity    string                          `json:"installer_identity"`
	Reports              []LocalDevelopmentCheckEvidence `json:"reports"`
}

type LocalDevelopmentCheckEvidence struct {
	CheckID       string `json:"check_id"`
	SubjectDigest string `json:"subject_digest"`
	Stdout        string `json:"stdout"`
	Stderr        string `json:"stderr"`
	ExitCode      int    `json:"exit_code"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
}

func validateLocalDevelopmentEvidence(unsigned UnsignedActivation) error {
	var evidence LocalDevelopmentEvidenceV1
	if err := decodeStrict(unsigned.EvidenceManifestBytes, &evidence); err != nil {
		return err
	}
	if evidence.SchemaVersion != "1.0.0" || evidence.Kind != "local-development-derivation" || evidence.SourceRevision != unsigned.Manifest.SourceRevision || evidence.DependencyLockDigest != unsigned.Manifest.DependencyLockDigest || len(evidence.Reports) != 3 {
		return contractError("invalid_local_development_evidence", "evidence", nil)
	}
	for _, digest := range []string{evidence.TemplateDigest, evidence.SubstitutionsDigest} {
		if !digestPattern.MatchString(digest) {
			return contractError("invalid_local_development_evidence", "evidence", nil)
		}
	}
	if err := validateImmutableRevision("evidence.source_tree", evidence.SourceTree); err != nil {
		return err
	}
	if err := validateIdentifier("evidence.installer_identity", evidence.InstallerIdentity); err != nil {
		return err
	}
	canonical, err := marshalCanonical(evidence)
	if err != nil || !bytes.Equal(canonical, unsigned.EvidenceManifestBytes) {
		return contractError("noncanonical_local_development_evidence", "evidence", err)
	}
	found := false
	for _, file := range unsigned.Files {
		if !strings.HasPrefix(file.Path, "evidence/") || file.Path == evidenceManifestPath {
			continue
		}
		if file.Path != LocalDevelopmentSubstitutionsPath || found || file.MediaType != "application/json" || SHA256Digest(file.Content) != evidence.SubstitutionsDigest {
			return contractError("unbound_local_development_evidence", "evidence", nil)
		}
		found = true
	}
	if !found {
		return contractError("missing_local_development_substitutions", "evidence", nil)
	}
	return nil
}

// PrepareLocalDevelopment reuses the canonical manifest, content index, full
// profile/domain/trust schemas, signing request and limits. Only the separate
// approved local evidence form replaces production per-artifact review claims.
// Its output remains untrusted and cannot be passed through production release
// or archive validation; WS-06 establishes local eligibility independently.
func (workflow *ObservedWorkflow) PrepareLocalDevelopment(input ManifestInput, payload []File, evidence LocalDevelopmentEvidenceV1, substitutions []byte) (UnsignedActivation, error) {
	if err := workflow.beginOperation(); err != nil {
		return UnsignedActivation{}, err
	}
	defer workflow.active.Store(false)
	unsigned, operationErr := prepareLocalDevelopment(input, payload, evidence, substitutions)
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowActivation, LifecycleStagePrepareUnsigned, localDevelopmentFacts(unsigned), operationErr)
	if err := workflow.observe(event); err != nil {
		return UnsignedActivation{}, err
	}
	return unsigned, operationErr
}

func prepareLocalDevelopment(input ManifestInput, files []File, evidence LocalDevelopmentEvidenceV1, substitutions []byte) (UnsignedActivation, error) {
	if err := validateManifestInput(input); err != nil {
		return UnsignedActivation{}, err
	}
	evidenceBytes, err := marshalCanonical(evidence)
	if err != nil {
		return UnsignedActivation{}, err
	}
	evidenceFiles := []File{{Path: evidenceManifestPath, MediaType: "application/vnd.stead.policy-evidence.v1+json", Content: evidenceBytes}, {Path: LocalDevelopmentSubstitutionsPath, MediaType: "application/json", Content: substitutions}}
	if err := preflightBuildFiles(files, evidenceFiles); err != nil {
		return UnsignedActivation{}, err
	}
	payload := map[string]File{}
	all := []File{}
	for _, file := range files {
		if err := validateArtifactFile(file, "payload"); err != nil {
			return UnsignedActivation{}, err
		}
		if _, exists := payload[file.Path]; exists {
			return UnsignedActivation{}, contractError("duplicate_file", "payload", nil)
		}
		payload[file.Path] = copyFile(file)
		all = append(all, copyFile(file))
	}
	requirements := map[string]profileMappingEvidenceRequirement{}
	var entries []PolicyContentIndexEntryV1
	bindings, profiles, err := validateAndSortBindings(input, payload, requirements, &entries)
	if err != nil {
		return UnsignedActivation{}, err
	}
	index := payload[input.PolicyContentIndexPath]
	if err := validatePolicyContentIndex(index, entries); err != nil {
		return UnsignedActivation{}, err
	}
	all = append(all, evidenceFiles...)
	sort.Slice(all, func(i, j int) bool { return all[i].Path < all[j].Path })
	manifest := PolicyActivationManifestV1{
		SchemaVersion: "1.0.0", ArtifactFormat: ActivationFormatV1,
		PolicyBundleID: SHA256Digest(index.Content), PolicyContentIndexPath: input.PolicyContentIndexPath,
		ContractBindings: bindings, Profiles: profiles, OpenFGAModel: input.OpenFGAModel, DeploymentPolicy: input.DeploymentPolicy,
		EvaluatorContractVersion: input.EvaluatorContractVersion, SupportedSteadVersions: mustSorted(input.SupportedSteadVersions),
		RequiredContextIDs: mustSorted(input.RequiredContextIDs), ReasonCodeIDs: mustSorted(input.ReasonCodeIDs), ObligationIDs: mustSorted(input.ObligationIDs), ExplicitDenyIDs: mustSorted(input.ExplicitDenyIDs),
		Files: manifestFileList(all), SourceRevision: input.SourceRevision, DependencyLockDigest: input.DependencyLockDigest,
		BuildRecipeVersion: input.BuildRecipeVersion, EvidenceManifestDigest: SHA256Digest(evidenceBytes), IssuedAt: input.IssuedAt.Format("2006-01-02T15:04:05Z07:00"), ExpiresAt: input.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		Trust: input.Trust, CompatiblePredecessorActivationSetIDs: sortedDigests(input.CompatiblePredecessorActivationSetIDs), RollbackConstraints: mustSorted(input.RollbackConstraints),
	}
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		return UnsignedActivation{}, err
	}
	request, requestBytes, err := makeSigningRequest("policy_activation_manifest", ActivationManifestPayloadType, manifestBytes, input)
	if err != nil {
		return UnsignedActivation{}, err
	}
	unsigned := UnsignedActivation{Manifest: manifest, ManifestPayload: manifestBytes, ActivationSetID: SHA256Digest(manifestBytes), PolicyBundleID: manifest.PolicyBundleID, EvidenceManifestBytes: evidenceBytes, EvidenceManifestDigest: SHA256Digest(evidenceBytes), Files: all, SigningRequest: request, SigningRequestBytes: requestBytes}
	if err := validateUnsignedActivationMode(unsigned, true); err != nil {
		return UnsignedActivation{}, err
	}
	return unsigned, nil
}

func localDevelopmentFacts(unsigned UnsignedActivation) LifecycleFacts {
	return LifecycleFacts{SourceRevision: unsigned.Manifest.SourceRevision, DependencyLockDigest: unsigned.Manifest.DependencyLockDigest, ActivationSetID: unsigned.ActivationSetID, PolicyBundleID: unsigned.PolicyBundleID, EvidenceManifestDigest: unsigned.EvidenceManifestDigest, ThresholdResult: LifecycleThresholdNotEvaluated}
}

func (workflow *ObservedWorkflow) FinalizeLocalDevelopment(unsigned UnsignedActivation, envelope []byte) ([]byte, error) {
	if err := workflow.beginOperation(); err != nil {
		return nil, err
	}
	defer workflow.active.Store(false)
	operationErr := validateUnsignedActivationMode(unsigned, true)
	if operationErr == nil {
		_, operationErr = validateExpectedEnvelope(envelope, unsigned.ManifestPayload, ActivationManifestPayloadType)
	}
	var archive []byte
	if operationErr == nil {
		archive, operationErr = writeArchive(envelope, unsigned.Files)
	}
	if operationErr == nil {
		_, operationErr = validateArchive(archive, envelope, unsigned.Manifest.Files)
	}
	facts := localDevelopmentFacts(unsigned)
	if operationErr == nil {
		facts.ArchiveDigest = SHA256Digest(archive)
		facts.SignedEnvelopeDigest = SHA256Digest(envelope)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowActivation, LifecycleStageFinalizeActivationArchive, facts, operationErr)
	if err := workflow.observe(event); err != nil {
		return nil, err
	}
	return archive, operationErr
}

func (workflow *ObservedWorkflow) ValidateLocalDevelopmentArchive(archive []byte) (UnsignedActivation, []byte, error) {
	if err := workflow.beginOperation(); err != nil {
		return UnsignedActivation{}, nil, err
	}
	defer workflow.active.Store(false)
	unsigned, envelope, operationErr := decodeActivationArchiveMode(archive, true)
	facts := LifecycleFacts{}
	if operationErr == nil {
		facts = localDevelopmentFacts(unsigned)
		facts.ArchiveDigest = SHA256Digest(archive)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowActivation, LifecycleStageValidateArchive, facts, operationErr)
	if err := workflow.observe(event); err != nil {
		return UnsignedActivation{}, nil, err
	}
	return unsigned, envelope, operationErr
}
