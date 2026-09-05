package authorization

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

// ActivationBinding is the complete immutable selection shared by the
// authoritative PostgreSQL pointer and independently retained host anchor.
// Its digest is a comparison convenience, never signature authority.
type ActivationBinding struct {
	ActivationSetID                  string `json:"activation_set_id"`
	SignedEnvelopeDigest             string `json:"signed_envelope_digest"`
	ArchiveDigest                    string `json:"archive_digest"`
	ReleaseAttestationID             string `json:"release_attestation_id"`
	ReleaseAttestationEnvelopeDigest string `json:"release_attestation_envelope_digest"`
	PolicyBundleID                   string `json:"policy_bundle_id"`
	OpenFGAModelID                   string `json:"openfga_model_id"`
	OpenFGAStoreID                   string `json:"openfga_store_id"`
	ModelSourceDigest                string `json:"openfga_model_source_digest"`
	DeploymentPolicyID               string `json:"deployment_policy_id"`
	DeploymentPolicyVersion          string `json:"deployment_policy_version"`
	DeploymentPolicyDigest           string `json:"deployment_policy_digest"`
	DisclosureMode                   string `json:"disclosure_revocation_mode"`
	AssuranceResultDigest            string `json:"evaluated_assurance_result_digest"`
	EvaluatorContractVersion         string `json:"evaluator_contract_version"`
	TrustSetID                       string `json:"trust_set_id"`
	TrustEnvelopeDigest              string `json:"trust_set_envelope_digest"`
	TrustEpoch                       uint64 `json:"trust_epoch"`
	ActivationSequence               uint64 `json:"activation_sequence"`
	ActivationEpoch                  uint64 `json:"activation_epoch"`
}

func (binding ActivationBinding) Digest() string {
	data, _ := json.Marshal(binding)
	return policyrelease.SHA256Digest(data)
}

type AnchorState struct {
	Binding             ActivationBinding `json:"binding"`
	PolicyTimeHighWater time.Time         `json:"policy_time_high_water"`
	PolicyTimeRevision  uint64            `json:"policy_time_revision"`
}

// AnchorReader returns independently retained current activation/time state;
// a database backup or a stale in-memory configuration is not an implementation.
type AnchorReader interface {
	Read(context.Context) (AnchorState, error)
}

// CompareMax is called by the registered final-fence participant inside its
// final logical operation. Time may advance even if the SQL transaction later
// rolls back: it cannot be rolled back with application state.
type PolicyTimeAnchor interface {
	AnchorReader
	CompareMax(context.Context, ActivationBinding, time.Time) (AnchorState, error)
}
