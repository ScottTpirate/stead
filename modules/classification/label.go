// Package classification evaluates signed, deployment-bound security labels.
package classification

// Label is the closed OWGP SecurityLabelValue. Version is the label revision,
// not the version of its signed profile. Empty or unknown dimensions never
// acquire permissive semantics.
type Label struct {
	ProfileID                            string        `json:"profile_id"`
	SensitivityLevel                     string        `json:"sensitivity_level"`
	Version                              uint64        `json:"version"`
	HandlingRegimes                      []string      `json:"handling_regimes,omitempty"`
	Categories                           []string      `json:"categories,omitempty"`
	Compartments                         []string      `json:"compartments,omitempty"`
	DisseminationControls                []string      `json:"dissemination_controls,omitempty"`
	ReleasableTo                         []string      `json:"releasable_to,omitempty"`
	ExportControls                       []string      `json:"export_controls,omitempty"`
	Originator                           string        `json:"originator,omitempty"`
	ClassificationAuthority              string        `json:"classification_authority,omitempty"`
	DeclassificationOrReviewInstructions string        `json:"declassification_or_review_instructions,omitempty"`
	DerivationSources                    []ResourceRef `json:"derivation_sources,omitempty"`
}

type ResourceRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Copy prevents a caller from mutating a decision's snapshotted label.
func (label Label) Copy() Label {
	label.HandlingRegimes = append([]string(nil), label.HandlingRegimes...)
	label.Categories = append([]string(nil), label.Categories...)
	label.Compartments = append([]string(nil), label.Compartments...)
	label.DisseminationControls = append([]string(nil), label.DisseminationControls...)
	label.ReleasableTo = append([]string(nil), label.ReleasableTo...)
	label.ExportControls = append([]string(nil), label.ExportControls...)
	label.DerivationSources = append([]ResourceRef(nil), label.DerivationSources...)
	return label
}
