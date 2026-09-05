package authorization

import (
	"encoding/json"
	"slices"

	"github.com/ScottTpirate/stead/modules/classification"
)

type localProfileMetadata struct {
	ProfileID        string   `json:"profile_id"`
	Version          string   `json:"version"`
	SensitivityOrder []string `json:"sensitivity_order"`
}

// The reviewed local template contains exactly one profile document. Selection
// uses the artifact's typed role, never a privileged reference profile name.
func localProfileTemplate() (string, []byte, localProfileMetadata, error) {
	entries, err := contracts.ReadDir("contract")
	if err != nil {
		return "", nil, localProfileMetadata{}, ErrDenied
	}
	var path string
	var content []byte
	var profile localProfileMetadata
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := contracts.ReadFile("contract/" + entry.Name())
		if err != nil {
			return "", nil, localProfileMetadata{}, ErrDenied
		}
		var candidate localProfileMetadata
		if json.Unmarshal(data, &candidate) != nil {
			continue
		}
		if candidate.ProfileID == "" {
			continue
		}
		if path != "" {
			return "", nil, localProfileMetadata{}, ErrDenied
		}
		path = "contract/" + entry.Name()
		content = data
		profile = candidate
	}
	if path == "" || profile.Version == "" || len(profile.SensitivityOrder) == 0 {
		return "", nil, localProfileMetadata{}, ErrDenied
	}
	return path, content, profile, nil
}

func localProfileContractPath() string { path, _, _, _ := localProfileTemplate(); return path }

// LocalBootstrapDefaults returns initial canonical metadata from the verified
// fixed local policy. It is not a grant and does not bypass fresh authorization.
func (activation *VerifiedActivation) LocalBootstrapDefaults() (classification.Label, map[string]string, error) {
	if activation == nil || !activation.valid || activation.binding.EvidenceKind != "local-development-derivation-v1" {
		return classification.Label{}, nil, ErrDenied
	}
	_, _, profile, err := localProfileTemplate()
	if err != nil || !slices.Contains(profile.SensitivityOrder, "internal") {
		return classification.Label{}, nil, ErrDenied
	}
	data, _ := contracts.ReadFile("contract/deployment-local.json")
	var domain struct {
		Ceilings map[string]struct {
			Version string `json:"profile_version"`
			Level   string `json:"classification_ceiling"`
		} `json:"label_profile_ceilings"`
	}
	if json.Unmarshal(data, &domain) != nil || len(domain.Ceilings) != 1 {
		return classification.Label{}, nil, ErrDenied
	}
	ceiling, present := domain.Ceilings[profile.ProfileID]
	if !present || ceiling.Version != profile.Version || !slices.Contains(profile.SensitivityOrder, ceiling.Level) {
		return classification.Label{}, nil, ErrDenied
	}
	return classification.Label{ProfileID: profile.ProfileID, SensitivityLevel: "internal", Version: 1}, map[string]string{profile.ProfileID: ceiling.Level}, nil
}
