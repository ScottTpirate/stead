package policyrelease

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	securityProfileMediaType = "application/vnd.stead.security-profile.v0.1+json"
	conformanceEvidencePath  = "evidence/conformance-result.json"
)

var (
	profileIDPattern          = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	stableIDPattern           = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	vocabularyPattern         = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,127}$`)
	termIDPattern             = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,127}(?:/[A-Za-z][A-Za-z0-9_]{0,127})?$`)
	semanticVersionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	profilePayloadPathPattern = regexp.MustCompile(`^(policies|tests)/[A-Za-z0-9_./-]+$`)
	profileTestIDPattern      = regexp.MustCompile(`^T-[A-Z0-9-]+$`)
)

var (
	profileTermDimensions = map[string]bool{
		"sensitivity": true, "handling_regime": true, "category": true,
		"compartment_namespace": true, "dissemination_control": true,
		"releasability_group": true, "export_control": true,
	}
	monotoneRestrictionDimensions = map[string]bool{
		"handling_regime": true, "category": true, "compartment_namespace": true,
		"dissemination_control": true, "export_control": true,
	}
)

type profileScopeV01 struct {
	Summary           string   `json:"summary"`
	CoverageStatement string   `json:"coverage_statement"`
	Limitations       []string `json:"limitations"`
}

type profileSourceV01 struct {
	SourceKind          string `json:"source_kind"`
	SourceID            string `json:"source_id"`
	Title               string `json:"title"`
	URI                 string `json:"uri"`
	SourceVersionOrDate string `json:"source_version_or_date"`
	RetrievedAt         string `json:"retrieved_at,omitempty"`
	SnapshotDigest      string `json:"snapshot_digest,omitempty"`
	PayloadPath         string `json:"payload_path,omitempty"`
	MappedScope         string `json:"mapped_scope"`
}

type profileCategoryV01 struct {
	ID            string   `json:"id"`
	Subcategories []string `json:"subcategories"`
}

type profileExportControlV01 struct {
	ID          string   `json:"id"`
	DisplayText string   `json:"display_text"`
	SourceIDs   []string `json:"source_ids"`
}

type profileNormalizationV01 struct {
	IdentifierCase string `json:"identifier_case"`
	SetOrder       string `json:"set_order"`
	UnknownValue   string `json:"unknown_value"`
}

type profileLoweringApprovalV01 struct {
	MinimumApprovers       int  `json:"minimum_approvers"`
	DistinctApprovers      bool `json:"distinct_approvers"`
	HumanApproversRequired bool `json:"human_approvers_required"`
}

type profileTermV01 struct {
	Dimension string `json:"dimension"`
	ID        string `json:"id"`
}

type profileImplicationV01 struct {
	RuleID     string           `json:"rule_id"`
	WhenAll    []profileTermV01 `json:"when_all"`
	RequireAll []profileTermV01 `json:"require_all"`
}

type profileIncompatibilityV01 struct {
	RuleID string           `json:"rule_id"`
	AllOf  []profileTermV01 `json:"all_of"`
}

type profileSensitivityConstraintV01 struct {
	RuleID                   string           `json:"rule_id"`
	WhenAny                  []profileTermV01 `json:"when_any"`
	AllowedSensitivityLevels []string         `json:"allowed_sensitivity_levels"`
}

type profileDimensionRequirementV01 struct {
	RuleID                     string           `json:"rule_id"`
	WhenAll                    []profileTermV01 `json:"when_all"`
	RequiredNonemptyDimensions []string         `json:"required_nonempty_dimensions"`
}

type profileContextRequirementV01 struct {
	RuleID                string           `json:"rule_id"`
	WhenAll               []profileTermV01 `json:"when_all"`
	RequirementType       string           `json:"requirement_type"`
	TrustedAttributeNames []string         `json:"trusted_attribute_names"`
	AuthorityClasses      []string         `json:"authority_classes"`
}

type profileCoverageV01 struct {
	TestID         string `json:"test_id"`
	EvidencePath   string `json:"evidence_path"`
	EvidenceDigest string `json:"evidence_digest"`
}

type profileMappingProvenanceV01 struct {
	MappingVersion string               `json:"mapping_version"`
	SourceRevision string               `json:"source_revision"`
	ProducedBy     string               `json:"produced_by"`
	ReviewedAt     string               `json:"reviewed_at"`
	TestedCoverage []profileCoverageV01 `json:"tested_coverage"`
}

type profileRegistryMappingV01 struct {
	MappingID         string                      `json:"mapping_id"`
	Dimension         string                      `json:"dimension"`
	InternalID        string                      `json:"internal_id"`
	SourceID          string                      `json:"source_id"`
	ExternalID        string                      `json:"external_id"`
	MappingProvenance profileMappingProvenanceV01 `json:"mapping_provenance"`
}

type profileSemanticsV01 struct {
	RuleContract           string                            `json:"rule_contract"`
	Representability       string                            `json:"representability"`
	UnmappedBehavior       string                            `json:"unmapped_behavior"`
	Implications           []profileImplicationV01           `json:"implications"`
	Incompatibilities      []profileIncompatibilityV01       `json:"incompatibilities"`
	SensitivityConstraints []profileSensitivityConstraintV01 `json:"sensitivity_constraints"`
	DimensionRequirements  []profileDimensionRequirementV01  `json:"dimension_requirements"`
	ContextRequirements    []profileContextRequirementV01    `json:"context_requirements"`
	RegistryMappings       []profileRegistryMappingV01       `json:"registry_mappings"`
}

type profileMarkingV01 struct {
	ID          string `json:"id"`
	DisplayText string `json:"display_text"`
}

type profilePresentationV01 struct {
	RendererID            string              `json:"renderer_id"`
	RendererVersion       string              `json:"renderer_version"`
	TextAuthoritative     bool                `json:"text_authoritative"`
	ColorSupplementalOnly bool                `json:"color_supplemental_only"`
	SensitivityMarkings   []profileMarkingV01 `json:"sensitivity_markings"`
	RequiredSurfaces      []string            `json:"required_surfaces"`
	ActionWarnings        []string            `json:"action_warnings"`
}

type profileBundleSigningV01 struct {
	Required            bool   `json:"required"`
	Format              string `json:"format"`
	MaterializationGate string `json:"materialization_gate"`
}

type securityProfileDocumentV01 struct {
	ProfileID               string                     `json:"profile_id"`
	Version                 string                     `json:"version"`
	ProfilePurpose          string                     `json:"profile_purpose"`
	Scope                   profileScopeV01            `json:"scope"`
	AuthoritativeSources    []profileSourceV01         `json:"authoritative_sources"`
	SensitivityOrder        []string                   `json:"sensitivity_order"`
	HandlingRegimes         []string                   `json:"handling_regimes"`
	AllowedCategories       []profileCategoryV01       `json:"allowed_categories"`
	AllowedCompartments     []string                   `json:"allowed_compartments"`
	DisseminationControls   []string                   `json:"dissemination_controls"`
	ReleasabilityGroups     []string                   `json:"releasability_groups"`
	ExportControls          []profileExportControlV01  `json:"export_controls"`
	Normalization           profileNormalizationV01    `json:"normalization"`
	Dominance               string                     `json:"dominance"`
	Join                    string                     `json:"join"`
	ReleasableToJoin        string                     `json:"releasable_to_join"`
	CrossProfileComposition string                     `json:"cross_profile_composition"`
	Lowering                string                     `json:"lowering"`
	LoweringApproval        profileLoweringApprovalV01 `json:"lowering_approval"`
	Semantics               profileSemanticsV01        `json:"semantics"`
	Presentation            profilePresentationV01     `json:"presentation"`
	BundleSigning           profileBundleSigningV01    `json:"bundle_signing"`
}

type deploymentScopeV01 struct {
	Summary     string   `json:"summary"`
	Limitations []string `json:"limitations"`
}

type deploymentProfileCeilingV01 struct {
	ProfileVersion        string `json:"profile_version"`
	ClassificationCeiling string `json:"classification_ceiling"`
}

type deploymentStorageV01 struct {
	Providers         []string `json:"providers"`
	EncryptionProfile string   `json:"encryption_profile"`
	Residency         []string `json:"residency"`
}

type deploymentBackupV01 struct {
	Enabled           bool     `json:"enabled"`
	Domains           []string `json:"domains"`
	EncryptionProfile string   `json:"encryption_profile"`
}

type deploymentRunnerV01 struct {
	Pools         []string `json:"pools"`
	Ephemeral     bool     `json:"ephemeral"`
	AllowedImages []string `json:"allowed_images"`
}

type deploymentNetworkV01 struct {
	Zones        []string `json:"zones"`
	EgressPolicy string   `json:"egress_policy"`
}

type deploymentAssuranceV01 struct {
	PolicySignatureThreshold       int    `json:"policy_signature_threshold"`
	DistinctSigningCustodians      bool   `json:"distinct_signing_custodians"`
	TrustRecoveryApprovalThreshold int    `json:"trust_recovery_approval_threshold"`
	DistinctTrustRecoveryApprovers bool   `json:"distinct_trust_recovery_approvers"`
	LoweringApprovalThreshold      int    `json:"lowering_approval_threshold"`
	DistinctLoweringApprovers      bool   `json:"distinct_lowering_approvers"`
	HumanLoweringApproversRequired bool   `json:"human_lowering_approvers_required"`
	ApprovedCryptographicBoundary  string `json:"approved_cryptographic_boundary"`
	ValidatedCryptoModuleRequired  bool   `json:"validated_cryptographic_module_required"`
	EvidenceProfile                string `json:"evidence_profile"`
}

type deploymentPolicyDocumentV01 struct {
	DomainID                    string                                 `json:"domain_id"`
	Version                     string                                 `json:"version"`
	PolicyPurpose               string                                 `json:"policy_purpose"`
	Scope                       deploymentScopeV01                     `json:"scope"`
	LabelProfileCeilings        map[string]deploymentProfileCeilingV01 `json:"label_profile_ceilings"`
	DisclosureRevocationMode    string                                 `json:"disclosure_revocation_mode"`
	TrustedAttributeAuthorities []string                               `json:"trusted_attribute_authorities"`
	ApprovedProfileBridges      []struct{}                             `json:"approved_profile_bridges"`
	AllowedIntegrations         []string                               `json:"allowed_integrations"`
	AllowedNotificationChannels []string                               `json:"allowed_notification_channels"`
	Storage                     deploymentStorageV01                   `json:"storage"`
	Backup                      deploymentBackupV01                    `json:"backup"`
	Runner                      deploymentRunnerV01                    `json:"runner"`
	Network                     deploymentNetworkV01                   `json:"network"`
	Assurance                   deploymentAssuranceV01                 `json:"assurance"`
}

type trustSetKeyV1 struct {
	CustodianID   string `json:"custodian_id"`
	KeyID         string `json:"key_id"`
	NotAfter      string `json:"not_after"`
	NotBefore     string `json:"not_before"`
	Purpose       string `json:"purpose"`
	SPKIDERBase64 string `json:"spki_der_base64"`
	Status        string `json:"status"`
}

type trustSetDocumentV1 struct {
	DeploymentPolicyDigest  string          `json:"deployment_policy_digest"`
	DeploymentPolicyID      string          `json:"deployment_policy_id"`
	DeploymentPolicyVersion string          `json:"deployment_policy_version"`
	Epoch                   uint64          `json:"epoch"`
	Keys                    []trustSetKeyV1 `json:"keys"`
	PreviousTrustSetID      *string         `json:"previous_trust_set_id"`
	RecoveryKeyReference    string          `json:"recovery_key_reference"`
	SchemaVersion           string          `json:"schema_version"`
	SignatureThreshold      int             `json:"signature_threshold"`
}

type conformanceEvidenceV01 struct {
	AgentIntersection            string `json:"agent_intersection"`
	CriticalMutationScorePercent int    `json:"critical_mutation_score_percent"`
	DecisionRowsCoveredPercent   int    `json:"decision_rows_covered_percent"`
	DeterministicReplay          string `json:"deterministic_replay"`
	ExplicitDeny                 string `json:"explicit_deny"`
	LabelLattice                 string `json:"label_lattice"`
	ProviderBypass               string `json:"provider_bypass"`
}

type licenseEvidenceDependencyV01 struct {
	Approval  string `json:"approval"`
	Component string `json:"component"`
	License   string `json:"license"`
}

type licenseEvidenceV01 struct {
	Decision            string                         `json:"decision"`
	Dependencies        []licenseEvidenceDependencyV01 `json:"dependencies"`
	UnknownOrDisallowed int                            `json:"unknown_or_disallowed"`
}

type slsaSubjectV1 struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type slsaExternalParametersV1 struct {
	DependencyLockDigest string `json:"dependencyLockDigest"`
	SourceRevision       string `json:"sourceRevision"`
}

type slsaInternalParametersV1 struct {
	NetworkAccess bool `json:"networkAccess"`
}

type slsaBuildDefinitionV1 struct {
	BuildType          string                   `json:"buildType"`
	ExternalParameters slsaExternalParametersV1 `json:"externalParameters"`
	InternalParameters slsaInternalParametersV1 `json:"internalParameters"`
}

type slsaBuilderV1 struct {
	ID string `json:"id"`
}

type slsaRunDetailsV1 struct {
	Builder slsaBuilderV1 `json:"builder"`
}

type slsaPredicateV1 struct {
	BuildDefinition slsaBuildDefinitionV1 `json:"buildDefinition"`
	RunDetails      slsaRunDetailsV1      `json:"runDetails"`
}

type slsaProvenanceEvidenceV1 struct {
	Type          string          `json:"_type"`
	Subject       []slsaSubjectV1 `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     slsaPredicateV1 `json:"predicate"`
}

type spdxCreationInfoV301 struct {
	ID          string   `json:"@id"`
	Type        string   `json:"type"`
	CreatedBy   []string `json:"createdBy"`
	SpecVersion string   `json:"specVersion"`
	Created     string   `json:"created"`
}

type spdxSoftwareAgentV301 struct {
	Type         string `json:"type"`
	SPDXID       string `json:"spdxId"`
	CreationInfo string `json:"creationInfo"`
	Name         string `json:"name"`
}

type spdxDocumentV301 struct {
	Type               string   `json:"type"`
	SPDXID             string   `json:"spdxId"`
	CreationInfo       string   `json:"creationInfo"`
	RootElement        []string `json:"rootElement"`
	Element            []string `json:"element"`
	ProfileConformance []string `json:"profileConformance"`
}

type spdxSBOMV301 struct {
	Type             string   `json:"type"`
	SPDXID           string   `json:"spdxId"`
	CreationInfo     string   `json:"creationInfo"`
	RootElement      []string `json:"rootElement"`
	Element          []string `json:"element"`
	SoftwareSBOMType []string `json:"software_sbomType"`
}

type spdxPackageV301 struct {
	Type                   string `json:"type"`
	SPDXID                 string `json:"spdxId"`
	CreationInfo           string `json:"creationInfo"`
	Name                   string `json:"name"`
	SoftwarePackageVersion string `json:"software_packageVersion"`
}

type spdxEvidenceV301 struct {
	Context string           `json:"@context"`
	Graph   []map[string]any `json:"@graph"`
}

type vulnerabilityEvidenceV01 struct {
	Decision              string `json:"decision"`
	ScannerDatabaseDigest string `json:"scanner_database_digest"`
	UnknownCriticalOrHigh int    `json:"unknown_critical_or_high"`
}

type evidenceSpec struct {
	mediaType string
	validate  func([]byte) (ConformanceClaims, error)
}

var evidenceSpecs = map[string]evidenceSpec{
	"evidence/sbom.spdx.json":            {"application/spdx+json", validateSPDXEvidence},
	"evidence/provenance.json":           {"application/vnd.in-toto+json", validateProvenanceEvidence},
	conformanceEvidencePath:              {"application/vnd.stead.policy-conformance.v1+json", validateConformanceEvidence},
	"evidence/license-result.json":       {"application/vnd.stead.policy-license-result.v1+json", validateLicenseEvidence},
	"evidence/vulnerability-result.json": {"application/vnd.stead.policy-vulnerability.v1+json", validateVulnerabilityEvidence},
}

func nonemptyText(value string) bool {
	return value != "" && len(value) <= 2048 && utf8.ValidString(value)
}

func validateUniqueStrings(field string, values []string, minimum int, pattern *regexp.Regexp) error {
	if len(values) < minimum || len(values) > MaxArchiveFiles {
		return contractError("schema_array_cardinality", field, nil)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !nonemptyText(value) || (pattern != nil && !pattern.MatchString(value)) {
			return contractError("schema_value_mismatch", field, nil)
		}
		if _, duplicate := seen[value]; duplicate {
			return contractError("schema_duplicate_value", field, nil)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateSchemaStrings(field string, values []string, minimum int, nonempty bool, pattern *regexp.Regexp) error {
	if len(values) < minimum || len(values) > MaxArchiveFiles {
		return contractError("schema_array_cardinality", field, nil)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !utf8.ValidString(value) || len(value) > 2048 || (nonempty && value == "") || (pattern != nil && !pattern.MatchString(value)) {
			return contractError("schema_value_mismatch", field, nil)
		}
		if _, duplicate := seen[value]; duplicate {
			return contractError("schema_duplicate_value", field, nil)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateProfileTerms(field string, terms []profileTermV01, minimum int, allowedDimensions map[string]bool) error {
	if len(terms) < minimum || len(terms) > MaxArchiveFiles {
		return contractError("schema_array_cardinality", field, nil)
	}
	seen := make(map[string]struct{}, len(terms))
	for _, term := range terms {
		if !allowedDimensions[term.Dimension] || !termIDPattern.MatchString(term.ID) {
			return contractError("security_profile_term_mismatch", field, nil)
		}
		key := term.Dimension + "\x00" + term.ID
		if _, duplicate := seen[key]; duplicate {
			return contractError("schema_duplicate_value", field, nil)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateProfileRuleSemantics(document securityProfileDocumentV01, field string) error {
	for _, rule := range document.Semantics.Implications {
		if !stableIDPattern.MatchString(rule.RuleID) || validateProfileTerms(field+".implications.when_all", rule.WhenAll, 1, profileTermDimensions) != nil || validateProfileTerms(field+".implications.require_all", rule.RequireAll, 1, monotoneRestrictionDimensions) != nil {
			return contractError("security_profile_rule_mismatch", field+".implications", nil)
		}
	}
	for _, rule := range document.Semantics.Incompatibilities {
		if !stableIDPattern.MatchString(rule.RuleID) || validateProfileTerms(field+".incompatibilities.all_of", rule.AllOf, 2, profileTermDimensions) != nil {
			return contractError("security_profile_rule_mismatch", field+".incompatibilities", nil)
		}
	}
	for _, rule := range document.Semantics.SensitivityConstraints {
		if !stableIDPattern.MatchString(rule.RuleID) || validateProfileTerms(field+".sensitivity_constraints.when_any", rule.WhenAny, 1, profileTermDimensions) != nil || validateUniqueStrings(field+".sensitivity_constraints.allowed_sensitivity_levels", rule.AllowedSensitivityLevels, 1, vocabularyPattern) != nil {
			return contractError("security_profile_rule_mismatch", field+".sensitivity_constraints", nil)
		}
	}
	requiredDimensions := map[string]bool{"handling_regime": true, "category": true, "compartment_namespace": true, "dissemination_control": true, "releasability_group": true, "export_control": true}
	for _, rule := range document.Semantics.DimensionRequirements {
		if !stableIDPattern.MatchString(rule.RuleID) || validateProfileTerms(field+".dimension_requirements.when_all", rule.WhenAll, 1, profileTermDimensions) != nil || len(rule.RequiredNonemptyDimensions) == 0 {
			return contractError("security_profile_rule_mismatch", field+".dimension_requirements", nil)
		}
		seen := make(map[string]struct{}, len(rule.RequiredNonemptyDimensions))
		for _, dimension := range rule.RequiredNonemptyDimensions {
			if !requiredDimensions[dimension] {
				return contractError("security_profile_rule_mismatch", field+".dimension_requirements", nil)
			}
			if _, duplicate := seen[dimension]; duplicate {
				return contractError("schema_duplicate_value", field+".dimension_requirements", nil)
			}
			seen[dimension] = struct{}{}
		}
	}
	requirementTypes := map[string]bool{"verified_unexpired_presence": true, "audience_membership": true, "registry_membership": true, "export_authorization": true}
	for _, rule := range document.Semantics.ContextRequirements {
		if !stableIDPattern.MatchString(rule.RuleID) || validateProfileTerms(field+".context_requirements.when_all", rule.WhenAll, 1, profileTermDimensions) != nil || !requirementTypes[rule.RequirementType] || validateUniqueStrings(field+".context_requirements.trusted_attribute_names", rule.TrustedAttributeNames, 1, stableIDPattern) != nil || validateUniqueStrings(field+".context_requirements.authority_classes", rule.AuthorityClasses, 1, stableIDPattern) != nil {
			return contractError("security_profile_rule_mismatch", field+".context_requirements", nil)
		}
	}
	for _, mapping := range document.Semantics.RegistryMappings {
		provenance := mapping.MappingProvenance
		if !stableIDPattern.MatchString(mapping.MappingID) || !profileTermDimensions[mapping.Dimension] || !termIDPattern.MatchString(mapping.InternalID) || !stableIDPattern.MatchString(mapping.SourceID) || mapping.ExternalID == "" || len(mapping.ExternalID) > 512 || !utf8.ValidString(mapping.ExternalID) || !semanticVersionPattern.MatchString(provenance.MappingVersion) || !nonemptyText(provenance.SourceRevision) || !stableIDPattern.MatchString(provenance.ProducedBy) {
			return contractError("security_profile_registry_mapping_mismatch", field+".registry_mappings", nil)
		}
		if _, err := time.Parse(time.RFC3339, provenance.ReviewedAt); err != nil || len(provenance.TestedCoverage) == 0 || len(provenance.TestedCoverage) > MaxArchiveFiles {
			return contractError("security_profile_registry_mapping_mismatch", field+".registry_mappings", nil)
		}
		for _, coverage := range provenance.TestedCoverage {
			if !profileTestIDPattern.MatchString(coverage.TestID) || !profilePayloadPathPattern.MatchString(coverage.EvidencePath) || validateDigest("profile.mapping.evidence_digest", coverage.EvidenceDigest) != nil {
				return contractError("security_profile_registry_mapping_mismatch", field+".registry_mappings", nil)
			}
		}
	}
	return nil
}

func requireObjectFields(raw json.RawMessage, field string, required ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, contractError("schema_object_required", field, nil)
	}
	for _, name := range required {
		if _, present := object[name]; !present {
			return nil, contractError("schema_required_field_missing", field+"."+name, nil)
		}
	}
	return object, nil
}

func requireObjectArray(raw json.RawMessage, field string, required ...string) ([]map[string]json.RawMessage, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, contractError("schema_array_required", field, nil)
	}
	objects := make([]map[string]json.RawMessage, len(items))
	for index, item := range items {
		object, err := requireObjectFields(item, field, required...)
		if err != nil {
			return nil, err
		}
		objects[index] = object
	}
	return objects, nil
}

func requireTermArrays(objects []map[string]json.RawMessage, field string, names ...string) error {
	for _, object := range objects {
		for _, name := range names {
			if _, err := requireObjectArray(object[name], field+"."+name, "dimension", "id"); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireSecurityProfileSchemaFields(data []byte) error {
	root, err := requireObjectFields(data, "security_profile",
		"profile_id", "version", "profile_purpose", "scope", "authoritative_sources",
		"sensitivity_order", "handling_regimes", "allowed_categories", "allowed_compartments",
		"dissemination_controls", "releasability_groups", "export_controls", "normalization",
		"dominance", "join", "releasable_to_join", "cross_profile_composition", "lowering",
		"lowering_approval", "semantics", "presentation", "bundle_signing")
	if err != nil {
		return err
	}
	for _, nested := range []struct {
		name     string
		required []string
	}{
		{"scope", []string{"summary", "coverage_statement", "limitations"}},
		{"normalization", []string{"identifier_case", "set_order", "unknown_value"}},
		{"lowering_approval", []string{"minimum_approvers", "distinct_approvers", "human_approvers_required"}},
		{"semantics", []string{"rule_contract", "representability", "unmapped_behavior", "implications", "incompatibilities", "sensitivity_constraints", "dimension_requirements", "context_requirements", "registry_mappings"}},
		{"presentation", []string{"renderer_id", "renderer_version", "text_authoritative", "color_supplemental_only", "sensitivity_markings", "required_surfaces", "action_warnings"}},
		{"bundle_signing", []string{"required", "format", "materialization_gate"}},
	} {
		if _, err := requireObjectFields(root[nested.name], "security_profile."+nested.name, nested.required...); err != nil {
			return err
		}
	}
	sources, err := requireObjectArray(root["authoritative_sources"], "security_profile.authoritative_sources", "source_kind", "source_id", "title", "uri", "source_version_or_date", "mapped_scope")
	if err != nil {
		return err
	}
	for _, source := range sources {
		var kind string
		if err := json.Unmarshal(source["source_kind"], &kind); err != nil {
			return contractError("security_profile_source_mismatch", "security_profile.authoritative_sources", nil)
		}
		if kind == "authoritative_snapshot" {
			for _, name := range []string{"retrieved_at", "snapshot_digest", "payload_path"} {
				if _, present := source[name]; !present {
					return contractError("schema_required_field_missing", "security_profile.authoritative_sources."+name, nil)
				}
			}
		} else if kind == "reference" {
			for _, name := range []string{"retrieved_at", "snapshot_digest", "payload_path"} {
				if _, present := source[name]; present {
					return contractError("security_profile_source_mismatch", "security_profile.authoritative_sources", nil)
				}
			}
		}
	}
	if _, err := requireObjectArray(root["allowed_categories"], "security_profile.allowed_categories", "id", "subcategories"); err != nil {
		return err
	}
	if _, err := requireObjectArray(root["export_controls"], "security_profile.export_controls", "id", "display_text", "source_ids"); err != nil {
		return err
	}
	semantics, _ := requireObjectFields(root["semantics"], "security_profile.semantics")
	implications, err := requireObjectArray(semantics["implications"], "security_profile.semantics.implications", "rule_id", "when_all", "require_all")
	if err != nil {
		return err
	}
	if err := requireTermArrays(implications, "security_profile.semantics.implications", "when_all", "require_all"); err != nil {
		return err
	}
	incompatibilities, err := requireObjectArray(semantics["incompatibilities"], "security_profile.semantics.incompatibilities", "rule_id", "all_of")
	if err != nil {
		return err
	}
	if err := requireTermArrays(incompatibilities, "security_profile.semantics.incompatibilities", "all_of"); err != nil {
		return err
	}
	sensitivity, err := requireObjectArray(semantics["sensitivity_constraints"], "security_profile.semantics.sensitivity_constraints", "rule_id", "when_any", "allowed_sensitivity_levels")
	if err != nil {
		return err
	}
	if err := requireTermArrays(sensitivity, "security_profile.semantics.sensitivity_constraints", "when_any"); err != nil {
		return err
	}
	dimensions, err := requireObjectArray(semantics["dimension_requirements"], "security_profile.semantics.dimension_requirements", "rule_id", "when_all", "required_nonempty_dimensions")
	if err != nil {
		return err
	}
	if err := requireTermArrays(dimensions, "security_profile.semantics.dimension_requirements", "when_all"); err != nil {
		return err
	}
	contexts, err := requireObjectArray(semantics["context_requirements"], "security_profile.semantics.context_requirements", "rule_id", "when_all", "requirement_type", "trusted_attribute_names", "authority_classes")
	if err != nil {
		return err
	}
	if err := requireTermArrays(contexts, "security_profile.semantics.context_requirements", "when_all"); err != nil {
		return err
	}
	mappings, err := requireObjectArray(semantics["registry_mappings"], "security_profile.semantics.registry_mappings", "mapping_id", "dimension", "internal_id", "source_id", "external_id", "mapping_provenance")
	if err != nil {
		return err
	}
	for _, mapping := range mappings {
		provenance, err := requireObjectFields(mapping["mapping_provenance"], "security_profile.semantics.registry_mappings.mapping_provenance", "mapping_version", "source_revision", "produced_by", "reviewed_at", "tested_coverage")
		if err != nil {
			return err
		}
		if _, err := requireObjectArray(provenance["tested_coverage"], "security_profile.semantics.registry_mappings.tested_coverage", "test_id", "evidence_path", "evidence_digest"); err != nil {
			return err
		}
	}
	presentation, _ := requireObjectFields(root["presentation"], "security_profile.presentation")
	if _, err := requireObjectArray(presentation["sensitivity_markings"], "security_profile.presentation.sensitivity_markings", "id", "display_text"); err != nil {
		return err
	}
	return nil
}

func requireDeploymentPolicySchemaFields(data []byte) error {
	root, err := requireObjectFields(data, "deployment_policy",
		"domain_id", "version", "policy_purpose", "scope", "label_profile_ceilings",
		"disclosure_revocation_mode", "trusted_attribute_authorities", "approved_profile_bridges",
		"allowed_integrations", "allowed_notification_channels", "storage", "backup", "runner", "network", "assurance")
	if err != nil {
		return err
	}
	for _, nested := range []struct {
		name     string
		required []string
	}{
		{"scope", []string{"summary", "limitations"}},
		{"storage", []string{"providers", "encryption_profile", "residency"}},
		{"backup", []string{"enabled", "domains", "encryption_profile"}},
		{"runner", []string{"pools", "ephemeral", "allowed_images"}},
		{"network", []string{"zones", "egress_policy"}},
		{"assurance", []string{"policy_signature_threshold", "distinct_signing_custodians", "trust_recovery_approval_threshold", "distinct_trust_recovery_approvers", "lowering_approval_threshold", "distinct_lowering_approvers", "human_lowering_approvers_required", "approved_cryptographic_boundary", "validated_cryptographic_module_required", "evidence_profile"}},
	} {
		if _, err := requireObjectFields(root[nested.name], "deployment_policy."+nested.name, nested.required...); err != nil {
			return err
		}
	}
	var ceilings map[string]json.RawMessage
	if err := json.Unmarshal(root["label_profile_ceilings"], &ceilings); err != nil || ceilings == nil {
		return contractError("schema_object_required", "deployment_policy.label_profile_ceilings", nil)
	}
	for _, ceiling := range ceilings {
		if _, err := requireObjectFields(ceiling, "deployment_policy.label_profile_ceilings.entry", "profile_version", "classification_ceiling"); err != nil {
			return err
		}
	}
	return nil
}

func requireTrustSetSchemaFields(data []byte) error {
	root, err := requireObjectFields(data, "trust_set",
		"deployment_policy_digest", "deployment_policy_id", "deployment_policy_version",
		"epoch", "keys", "previous_trust_set_id", "recovery_key_reference",
		"schema_version", "signature_threshold")
	if err != nil {
		return err
	}
	_, err = requireObjectArray(root["keys"], "trust_set.keys",
		"custodian_id", "key_id", "not_after", "not_before", "purpose",
		"spki_der_base64", "status")
	return err
}

func validateTrustSetDocument(payloadFile, envelopeFile File, trust TrustBinding, policy DeploymentPolicyBinding) error {
	if payloadFile.MediaType != "application/json" || envelopeFile.MediaType != "application/json" {
		return contractError("bound_media_type_mismatch", "trust_set", nil)
	}
	var document trustSetDocumentV1
	if err := decodeStrict(payloadFile.Content, &document); err != nil {
		return err
	}
	if err := requireTrustSetSchemaFields(payloadFile.Content); err != nil {
		return err
	}
	if document.SchemaVersion != "1.0.0" || document.DeploymentPolicyID != policy.PolicyID ||
		document.DeploymentPolicyVersion != policy.Version || document.DeploymentPolicyDigest != policy.Digest ||
		document.Epoch != trust.TrustEpoch || document.SignatureThreshold != policy.PolicySignatureThreshold ||
		len(document.Keys) < document.SignatureThreshold || len(document.Keys) > MaxEnvelopeSignatures ||
		!nonemptyText(document.RecoveryKeyReference) {
		return contractError("trust_set_binding_mismatch", "trust_set", nil)
	}
	if document.PreviousTrustSetID != nil {
		if err := validateDigest("trust_set.previous_trust_set_id", *document.PreviousTrustSetID); err != nil {
			return err
		}
	}
	seenKeyIDs := make(map[string]struct{}, len(document.Keys))
	for _, key := range document.Keys {
		if !digestPattern.MatchString(key.KeyID) || !identifierPattern.MatchString(key.CustodianID) ||
			key.Purpose != ReleaseKeyPurpose || (key.Status != "active" && key.Status != "revoked" && key.Status != "retired") {
			return contractError("trust_set_key_mismatch", "trust_set.keys", nil)
		}
		if _, duplicate := seenKeyIDs[key.KeyID]; duplicate {
			return contractError("duplicate_trust_set_key_id", "trust_set.keys", nil)
		}
		seenKeyIDs[key.KeyID] = struct{}{}
		notBefore, beforeErr := time.Parse(time.RFC3339, key.NotBefore)
		notAfter, afterErr := time.Parse(time.RFC3339, key.NotAfter)
		if beforeErr != nil || afterErr != nil || !notBefore.Before(notAfter) {
			return contractError("trust_set_key_validity_mismatch", "trust_set.keys", nil)
		}
		if _, err := decodeCanonicalBase64("trust_set.keys.spki_der_base64", key.SPKIDERBase64, 2048); err != nil {
			return err
		}
	}
	if _, err := validateExpectedEnvelope(envelopeFile.Content, payloadFile.Content, TrustSetPayloadType); err != nil {
		return err
	}
	return nil
}

func validateSecurityProfileDocument(file File, binding ProfileBinding) error {
	if binding.SchemaID != SecurityProfileSchemaID {
		return contractError("unsupported_security_profile_schema", "profile.schema_id", nil)
	}
	if file.MediaType != securityProfileMediaType {
		return contractError("bound_media_type_mismatch", binding.Path, nil)
	}
	var document securityProfileDocumentV01
	if err := decodeStrict(file.Content, &document); err != nil {
		return err
	}
	if err := requireSecurityProfileSchemaFields(file.Content); err != nil {
		return err
	}
	if document.ProfileID != binding.ProfileID || document.Version != binding.Version {
		return contractError("security_profile_identity_mismatch", binding.Path, nil)
	}
	if !profileIDPattern.MatchString(document.ProfileID) || document.Version != "1.0.0" {
		return contractError("unsupported_security_profile_identity", binding.Path, nil)
	}
	purposes := map[string]bool{"starter_reference": true, "maintained_internal": true, "external_regime_mapping": true, "test_fixture": true}
	if !purposes[document.ProfilePurpose] || !nonemptyText(document.Scope.Summary) || !nonemptyText(document.Scope.CoverageStatement) || validateUniqueStrings("profile.scope.limitations", document.Scope.Limitations, 1, nil) != nil {
		return contractError("security_profile_schema_mismatch", binding.Path, nil)
	}
	if err := validateUniqueStrings("profile.sensitivity_order", document.SensitivityOrder, 1, vocabularyPattern); err != nil {
		return err
	}
	for field, values := range map[string][]string{
		"profile.handling_regimes":       document.HandlingRegimes,
		"profile.allowed_compartments":   document.AllowedCompartments,
		"profile.dissemination_controls": document.DisseminationControls,
		"profile.releasability_groups":   document.ReleasabilityGroups,
	} {
		if err := validateUniqueStrings(field, values, 0, vocabularyPattern); err != nil {
			return err
		}
	}
	sourcesByID := make(map[string]profileSourceV01, len(document.AuthoritativeSources))
	for _, source := range document.AuthoritativeSources {
		parsed, err := url.ParseRequestURI(source.URI)
		if err != nil || parsed.Scheme == "" || !stableIDPattern.MatchString(source.SourceID) || !nonemptyText(source.Title) || !nonemptyText(source.SourceVersionOrDate) || !nonemptyText(source.MappedScope) {
			return contractError("security_profile_source_mismatch", binding.Path, nil)
		}
		if source.SourceKind != "reference" && source.SourceKind != "authoritative_snapshot" {
			return contractError("security_profile_source_mismatch", binding.Path, nil)
		}
		if _, duplicate := sourcesByID[source.SourceID]; duplicate {
			return contractError("schema_duplicate_value", "profile.authoritative_sources", nil)
		}
		sourcesByID[source.SourceID] = source
		if source.SourceKind == "reference" && (source.RetrievedAt != "" || source.SnapshotDigest != "" || source.PayloadPath != "") {
			return contractError("security_profile_source_mismatch", binding.Path, nil)
		}
		if source.SourceKind == "authoritative_snapshot" && (source.RetrievedAt == "" || validateDigest("profile.snapshot_digest", source.SnapshotDigest) != nil || !profilePayloadPathPattern.MatchString(source.PayloadPath)) {
			return contractError("security_profile_source_mismatch", binding.Path, nil)
		}
		if source.SourceKind == "authoritative_snapshot" {
			if _, err := time.Parse(time.RFC3339, source.RetrievedAt); err != nil {
				return contractError("security_profile_source_mismatch", binding.Path, nil)
			}
		}
	}
	if document.ProfilePurpose == "external_regime_mapping" {
		if len(document.AuthoritativeSources) == 0 || len(document.Semantics.RegistryMappings) == 0 {
			return contractError("security_profile_external_mapping_incomplete", binding.Path, nil)
		}
		for _, source := range document.AuthoritativeSources {
			if source.SourceKind != "authoritative_snapshot" {
				return contractError("security_profile_external_mapping_requires_snapshots", binding.Path, nil)
			}
		}
	}
	if document.Normalization != (profileNormalizationV01{IdentifierCase: "exact", SetOrder: "lexicographic", UnknownValue: "deny"}) ||
		document.Dominance != "profile_partial_order_v1" || document.Join != "least_upper_bound_plus_union_of_handling_restrictions" ||
		document.ReleasableToJoin != "intersection_fail_on_empty" || document.CrossProfileComposition != "deny_without_signed_approved_bridge" ||
		document.Lowering != "deny_by_default_authorized_reasoned_audited" || document.LoweringApproval.MinimumApprovers < 1 || !document.LoweringApproval.DistinctApprovers {
		return contractError("security_profile_semantics_mismatch", binding.Path, nil)
	}
	if document.Semantics.RuleContract != "stead.security-profile-rules.v1" || document.Semantics.Representability != "closed_profile_semantics_v1" || document.Semantics.UnmappedBehavior != "deny" {
		return contractError("security_profile_semantics_mismatch", binding.Path, nil)
	}
	for _, category := range document.AllowedCategories {
		if !vocabularyPattern.MatchString(category.ID) || validateUniqueStrings("profile.allowed_categories.subcategories", category.Subcategories, 0, vocabularyPattern) != nil {
			return contractError("security_profile_vocabulary_mismatch", binding.Path, nil)
		}
	}
	for _, control := range document.ExportControls {
		if !vocabularyPattern.MatchString(control.ID) || !nonemptyText(control.DisplayText) || validateUniqueStrings("profile.export_controls.source_ids", control.SourceIDs, 0, stableIDPattern) != nil {
			return contractError("security_profile_vocabulary_mismatch", binding.Path, nil)
		}
	}
	if err := validateProfileRuleSemantics(document, "profile.semantics"); err != nil {
		return err
	}
	seenMappings := make(map[string]struct{}, len(document.Semantics.RegistryMappings))
	for _, mapping := range document.Semantics.RegistryMappings {
		if _, duplicate := seenMappings[mapping.MappingID]; duplicate {
			return contractError("schema_duplicate_value", "profile.semantics.registry_mappings", nil)
		}
		seenMappings[mapping.MappingID] = struct{}{}
		source, present := sourcesByID[mapping.SourceID]
		if !present || source.SourceKind != "authoritative_snapshot" || mapping.MappingProvenance.SourceRevision != source.SourceVersionOrDate {
			return contractError("security_profile_registry_mapping_source_mismatch", "profile.semantics.registry_mappings", nil)
		}
		seenCoverage := make(map[string]struct{}, len(mapping.MappingProvenance.TestedCoverage))
		for _, coverage := range mapping.MappingProvenance.TestedCoverage {
			key := coverage.TestID + "\x00" + coverage.EvidencePath
			if _, duplicate := seenCoverage[key]; duplicate {
				return contractError("schema_duplicate_value", "profile.semantics.registry_mappings.tested_coverage", nil)
			}
			seenCoverage[key] = struct{}{}
		}
	}
	if !stableIDPattern.MatchString(document.Presentation.RendererID) || !semanticVersionPattern.MatchString(document.Presentation.RendererVersion) || !document.Presentation.TextAuthoritative || !document.Presentation.ColorSupplementalOnly || len(document.Presentation.SensitivityMarkings) == 0 {
		return contractError("security_profile_presentation_mismatch", binding.Path, nil)
	}
	for _, marking := range document.Presentation.SensitivityMarkings {
		if !vocabularyPattern.MatchString(marking.ID) || !nonemptyText(marking.DisplayText) {
			return contractError("security_profile_presentation_mismatch", binding.Path, nil)
		}
	}
	if err := validateSchemaStrings("profile.presentation.required_surfaces", document.Presentation.RequiredSurfaces, 0, true, nil); err != nil {
		return err
	}
	allowedSurfaces := map[string]bool{"badge": true, "top_banner": true, "bottom_banner": true, "document": true, "print": true, "export": true, "session_indicator": true}
	for _, surface := range document.Presentation.RequiredSurfaces {
		if !allowedSurfaces[surface] {
			return contractError("security_profile_presentation_mismatch", binding.Path, nil)
		}
	}
	if err := validateSchemaStrings("profile.presentation.action_warnings", document.Presentation.ActionWarnings, 0, true, nil); err != nil {
		return err
	}
	allowedWarnings := map[string]bool{"copy": true, "download": true, "export": true, "print": true, "share": true}
	for _, warning := range document.Presentation.ActionWarnings {
		if !allowedWarnings[warning] {
			return contractError("security_profile_presentation_mismatch", binding.Path, nil)
		}
	}
	if !document.BundleSigning.Required || document.BundleSigning.Format != ActivationFormatV1 || document.BundleSigning.MaterializationGate != "RG-08-SECURITY" || binding.SigningFormat != document.BundleSigning.Format {
		return contractError("unsupported_profile_signing_format", binding.Path, nil)
	}
	return nil
}

func profileArtifactRequirements(file File) (map[string]string, map[string]string, error) {
	var document securityProfileDocumentV01
	if err := decodeStrict(file.Content, &document); err != nil {
		return nil, nil, err
	}
	snapshots := make(map[string]string)
	evidence := make(map[string]string)
	for _, source := range document.AuthoritativeSources {
		if source.SourceKind != "authoritative_snapshot" {
			continue
		}
		archivePath := "payload/" + source.PayloadPath
		if err := validatePath(archivePath, false); err != nil {
			return nil, nil, contractError("security_profile_artifact_path_mismatch", "profile.authoritative_sources", nil)
		}
		if prior, exists := snapshots[archivePath]; exists && prior != source.SnapshotDigest {
			return nil, nil, contractError("security_profile_artifact_digest_conflict", "profile.authoritative_sources", nil)
		}
		snapshots[archivePath] = source.SnapshotDigest
	}
	for _, mapping := range document.Semantics.RegistryMappings {
		for _, coverage := range mapping.MappingProvenance.TestedCoverage {
			archivePath := "evidence/" + coverage.EvidencePath
			if err := validatePath(archivePath, false); err != nil {
				return nil, nil, contractError("security_profile_artifact_path_mismatch", "profile.semantics.registry_mappings", nil)
			}
			if prior, exists := evidence[archivePath]; exists && prior != coverage.EvidenceDigest {
				return nil, nil, contractError("security_profile_artifact_digest_conflict", "profile.semantics.registry_mappings", nil)
			}
			evidence[archivePath] = coverage.EvidenceDigest
		}
	}
	return snapshots, evidence, nil
}

func validateDeploymentPolicyDocument(file File, binding DeploymentPolicyBinding, profiles []ProfileBinding) error {
	if binding.SchemaID != DeploymentPolicySchemaID || file.MediaType != "application/json" {
		return contractError("unsupported_deployment_policy_schema", binding.Path, nil)
	}
	var document deploymentPolicyDocumentV01
	if err := decodeStrict(file.Content, &document); err != nil {
		return err
	}
	if err := requireDeploymentPolicySchemaFields(file.Content); err != nil {
		return err
	}
	if document.DomainID != binding.PolicyID || document.Version != binding.Version || !stableIDPattern.MatchString(document.DomainID) || document.Version != "1.0.0" {
		return contractError("deployment_policy_identity_mismatch", binding.Path, nil)
	}
	purposes := map[string]bool{"starter_reference": true, "maintained_deployment": true, "test_fixture": true}
	if !purposes[document.PolicyPurpose] || !nonemptyText(document.Scope.Summary) || validateUniqueStrings("deployment.scope.limitations", document.Scope.Limitations, 1, nil) != nil || len(document.ApprovedProfileBridges) != 0 {
		return contractError("deployment_policy_schema_mismatch", binding.Path, nil)
	}
	if document.DisclosureRevocationMode != binding.DisclosureRevocationMode || len(document.LabelProfileCeilings) != len(profiles) {
		return contractError("deployment_policy_profile_binding_mismatch", binding.Path, nil)
	}
	for _, profile := range profiles {
		ceiling, ok := document.LabelProfileCeilings[profile.ProfileID]
		if !ok || ceiling.ProfileVersion != profile.Version || !nonemptyText(ceiling.ClassificationCeiling) {
			return contractError("deployment_policy_profile_binding_mismatch", binding.Path, nil)
		}
	}
	for profileID := range document.LabelProfileCeilings {
		if !profileIDPattern.MatchString(profileID) {
			return contractError("deployment_policy_profile_binding_mismatch", binding.Path, nil)
		}
	}
	if err := validateUniqueStrings("deployment.trusted_attribute_authorities", document.TrustedAttributeAuthorities, 1, nil); err != nil {
		return err
	}
	if err := validateUniqueStrings("deployment.storage.providers", document.Storage.Providers, 1, nil); err != nil {
		return err
	}
	if err := validateUniqueStrings("deployment.storage.residency", document.Storage.Residency, 1, nil); err != nil {
		return err
	}
	for field, values := range map[string][]string{
		"deployment.allowed_integrations":          document.AllowedIntegrations,
		"deployment.allowed_notification_channels": document.AllowedNotificationChannels,
		"deployment.backup.domains":                document.Backup.Domains,
		"deployment.runner.pools":                  document.Runner.Pools,
		"deployment.runner.allowed_images":         document.Runner.AllowedImages,
	} {
		if err := validateSchemaStrings(field, values, 0, false, nil); err != nil {
			return err
		}
	}
	if err := validateUniqueStrings("deployment.network.zones", document.Network.Zones, 1, nil); err != nil {
		return err
	}
	if !nonemptyText(document.Storage.EncryptionProfile) || !nonemptyText(document.Backup.EncryptionProfile) || !nonemptyText(document.Assurance.ApprovedCryptographicBoundary) || !nonemptyText(document.Assurance.EvidenceProfile) {
		return contractError("deployment_policy_schema_mismatch", binding.Path, nil)
	}
	if document.Network.EgressPolicy != "deny_all" && document.Network.EgressPolicy != "allowlisted" && document.Network.EgressPolicy != "managed" {
		return contractError("deployment_policy_schema_mismatch", binding.Path, nil)
	}
	want := deploymentAssuranceV01{
		PolicySignatureThreshold: binding.PolicySignatureThreshold, DistinctSigningCustodians: binding.DistinctSigningCustodians,
		TrustRecoveryApprovalThreshold: binding.TrustRecoveryApprovalThreshold, DistinctTrustRecoveryApprovers: binding.DistinctTrustRecoveryApprovers,
		LoweringApprovalThreshold: binding.LoweringApprovalThreshold, DistinctLoweringApprovers: binding.DistinctLoweringApprovers,
		HumanLoweringApproversRequired: binding.HumanLoweringApproversRequired, ApprovedCryptographicBoundary: binding.ApprovedCryptographicBoundary,
		ValidatedCryptoModuleRequired: binding.ValidatedCryptoModuleRequired, EvidenceProfile: binding.EvidenceProfile,
	}
	if document.Assurance != want {
		return contractError("deployment_policy_assurance_binding_mismatch", binding.Path, nil)
	}
	return nil
}

func validateConformanceEvidence(data []byte) (ConformanceClaims, error) {
	var report conformanceEvidenceV01
	if err := decodeStrict(data, &report); err != nil {
		return ConformanceClaims{}, err
	}
	claims := ConformanceClaims{
		DecisionRowsCoveredPercent: report.DecisionRowsCoveredPercent, CriticalMutationScorePercent: report.CriticalMutationScorePercent,
		ClaimedDeterministicReplay: report.DeterministicReplay, ClaimedLabelLattice: report.LabelLattice,
		ClaimedExplicitDeny: report.ExplicitDeny, ClaimedAgentIntersection: report.AgentIntersection, ClaimedProviderBypass: report.ProviderBypass,
	}
	if err := validateConformance(claims); err != nil {
		return ConformanceClaims{}, err
	}
	return claims, nil
}

func validAbsoluteURI(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.IsAbs()
}

func exactStringSet(values []string, expected map[string]struct{}) bool {
	if len(values) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		if _, present := expected[value]; !present {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validateSPDXEvidence(data []byte) (ConformanceClaims, error) {
	var report spdxEvidenceV301
	if err := decodeStrict(data, &report); err != nil {
		return ConformanceClaims{}, err
	}
	if report.Context != "https://spdx.org/rdf/3.0.1/spdx-context.jsonld" || len(report.Graph) < 5 || len(report.Graph) > MaxArchiveFiles {
		return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
	}
	var creation *spdxCreationInfoV301
	var agent *spdxSoftwareAgentV301
	var document *spdxDocumentV301
	var sbom *spdxSBOMV301
	packages := make([]spdxPackageV301, 0, len(report.Graph)-4)
	identities := make(map[string]struct{}, len(report.Graph))
	registerIdentity := func(identity string) bool {
		if !validAbsoluteURI(identity) {
			return false
		}
		if _, duplicate := identities[identity]; duplicate {
			return false
		}
		identities[identity] = struct{}{}
		return true
	}
	for _, graphItem := range report.Graph {
		kind, ok := graphItem["type"].(string)
		if !ok {
			return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
		}
		encoded, err := json.Marshal(graphItem)
		if err != nil {
			return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
		}
		switch kind {
		case "CreationInfo":
			if creation != nil {
				return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
			}
			var item spdxCreationInfoV301
			if err := decodeStrict(encoded, &item); err != nil {
				return ConformanceClaims{}, err
			}
			creation = &item
		case "SoftwareAgent":
			if agent != nil {
				return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
			}
			var item spdxSoftwareAgentV301
			if err := decodeStrict(encoded, &item); err != nil || !registerIdentity(item.SPDXID) {
				return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
			}
			agent = &item
		case "SpdxDocument":
			if document != nil {
				return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
			}
			var item spdxDocumentV301
			if err := decodeStrict(encoded, &item); err != nil || !registerIdentity(item.SPDXID) {
				return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
			}
			document = &item
		case "software_Sbom":
			if sbom != nil {
				return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
			}
			var item spdxSBOMV301
			if err := decodeStrict(encoded, &item); err != nil || !registerIdentity(item.SPDXID) {
				return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
			}
			sbom = &item
		case "software_Package":
			var item spdxPackageV301
			if err := decodeStrict(encoded, &item); err != nil || !registerIdentity(item.SPDXID) {
				return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
			}
			packages = append(packages, item)
		default:
			return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
		}
	}
	if creation == nil || agent == nil || document == nil || sbom == nil || len(packages) == 0 {
		return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
	}
	created, timeErr := time.Parse(time.RFC3339, creation.Created)
	if creation.Type != "CreationInfo" || !strings.HasPrefix(creation.ID, "_:") || len(creation.ID) < 3 || creation.SpecVersion != "3.0.1" || timeErr != nil || created.UTC().Format(time.RFC3339) != creation.Created || len(creation.CreatedBy) != 1 || creation.CreatedBy[0] != agent.SPDXID {
		return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
	}
	if agent.Type != "SoftwareAgent" || agent.CreationInfo != creation.ID || !stableIDPattern.MatchString(agent.Name) || document.Type != "SpdxDocument" || document.CreationInfo != creation.ID || sbom.Type != "software_Sbom" || sbom.CreationInfo != creation.ID {
		return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
	}
	packageIDs := make(map[string]struct{}, len(packages))
	for _, item := range packages {
		if item.Type != "software_Package" || item.CreationInfo != creation.ID || !stableIDPattern.MatchString(item.Name) || !nonemptyText(item.SoftwarePackageVersion) {
			return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
		}
		packageIDs[item.SPDXID] = struct{}{}
	}
	documentElements := make(map[string]struct{}, len(packageIDs)+2)
	documentElements[agent.SPDXID] = struct{}{}
	documentElements[sbom.SPDXID] = struct{}{}
	for identity := range packageIDs {
		documentElements[identity] = struct{}{}
	}
	if !exactStringSet(document.RootElement, map[string]struct{}{sbom.SPDXID: {}}) || !exactStringSet(document.Element, documentElements) || !exactStringSet(document.ProfileConformance, map[string]struct{}{"core": {}, "software": {}}) || !exactStringSet(sbom.RootElement, packageIDs) || !exactStringSet(sbom.Element, packageIDs) || !exactStringSet(sbom.SoftwareSBOMType, map[string]struct{}{"build": {}}) {
		return ConformanceClaims{}, contractError("spdx_evidence_schema_mismatch", "evidence/sbom.spdx.json", nil)
	}
	return ConformanceClaims{}, nil
}

func validateProvenanceEvidence(data []byte) (ConformanceClaims, error) {
	var report slsaProvenanceEvidenceV1
	if err := decodeStrict(data, &report); err != nil {
		return ConformanceClaims{}, err
	}
	if report.Type != "https://in-toto.io/Statement/v1" || report.PredicateType != "https://slsa.dev/provenance/v1" || len(report.Subject) == 0 || len(report.Subject) > MaxArchiveFiles || !validAbsoluteURI(report.Predicate.BuildDefinition.BuildType) || !validAbsoluteURI(report.Predicate.RunDetails.Builder.ID) || !nonemptyText(report.Predicate.BuildDefinition.ExternalParameters.SourceRevision) || validateDigest("provenance.dependency_lock_digest", report.Predicate.BuildDefinition.ExternalParameters.DependencyLockDigest) != nil || report.Predicate.BuildDefinition.InternalParameters.NetworkAccess {
		return ConformanceClaims{}, contractError("provenance_evidence_schema_mismatch", "evidence/provenance.json", nil)
	}
	seenSubjects := make(map[string]struct{}, len(report.Subject))
	for _, subject := range report.Subject {
		sha256Value, present := subject.Digest["sha256"]
		if !nonemptyText(subject.Name) || len(subject.Digest) != 1 || !present || validateDigest("provenance.subject.digest.sha256", "sha256:"+sha256Value) != nil {
			return ConformanceClaims{}, contractError("provenance_evidence_schema_mismatch", "evidence/provenance.json", nil)
		}
		if _, duplicate := seenSubjects[subject.Name]; duplicate {
			return ConformanceClaims{}, contractError("provenance_evidence_schema_mismatch", "evidence/provenance.json", nil)
		}
		seenSubjects[subject.Name] = struct{}{}
	}
	return ConformanceClaims{}, nil
}

func validateLicenseEvidence(data []byte) (ConformanceClaims, error) {
	var report licenseEvidenceV01
	if err := decodeStrict(data, &report); err != nil {
		return ConformanceClaims{}, err
	}
	if report.Decision != "pass" || report.UnknownOrDisallowed != 0 || len(report.Dependencies) == 0 || len(report.Dependencies) > MaxArchiveFiles {
		return ConformanceClaims{}, contractError("license_evidence_schema_mismatch", "evidence/license-result.json", nil)
	}
	for _, item := range report.Dependencies {
		if !stableIDPattern.MatchString(item.Approval) || !stableIDPattern.MatchString(item.Component) || !stableIDPattern.MatchString(strings.ToLower(item.License)) {
			return ConformanceClaims{}, contractError("license_evidence_schema_mismatch", "evidence/license-result.json", nil)
		}
	}
	return ConformanceClaims{}, nil
}

func validateVulnerabilityEvidence(data []byte) (ConformanceClaims, error) {
	var report vulnerabilityEvidenceV01
	if err := decodeStrict(data, &report); err != nil {
		return ConformanceClaims{}, err
	}
	if report.Decision != "pass" || report.UnknownCriticalOrHigh != 0 || validateDigest("vulnerability.scanner_database_digest", report.ScannerDatabaseDigest) != nil {
		return ConformanceClaims{}, contractError("vulnerability_evidence_schema_mismatch", "evidence/vulnerability-result.json", nil)
	}
	return ConformanceClaims{}, nil
}

func validateTypedEvidenceFile(file File) (ConformanceClaims, error) {
	spec, ok := evidenceSpecs[file.Path]
	if !ok {
		return ConformanceClaims{}, contractError("unknown_evidence_path", file.Path, nil)
	}
	if file.MediaType != spec.mediaType {
		return ConformanceClaims{}, contractError("evidence_media_type_mismatch", file.Path, nil)
	}
	return spec.validate(file.Content)
}

func sortedEvidencePaths() []string {
	paths := make([]string, 0, len(evidenceSpecs))
	for pathValue := range evidenceSpecs {
		paths = append(paths, pathValue)
	}
	sort.Strings(paths)
	return paths
}
