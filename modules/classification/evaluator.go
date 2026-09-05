package classification

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/ScottTpirate/stead/modules/identity"
)

var ErrDenied = errors.New("classification not permitted")

// Evaluator is the sensitivity-only local metadata slice. Unsupported label
// restrictions are denied, never silently ignored. CompileValidatedProfile
// consumes documents whose complete schemas were already checked by the
// policy-release consumer. Only the central signed-activation verifier can
// turn this evaluator into an authorizing Coordinator.
type Evaluator struct {
	profile profileDocument
	domain  domainDocument
}
type term struct {
	Dimension string `json:"dimension"`
	ID        string `json:"id"`
}
type profileDocument struct {
	ID          string   `json:"profile_id"`
	Version     string   `json:"version"`
	Purpose     string   `json:"profile_purpose"`
	Sensitivity []string `json:"sensitivity_order"`
	Semantics   struct {
		Contract         string `json:"rule_contract"`
		Representability string `json:"representability"`
		Unmapped         string `json:"unmapped_behavior"`
		Implications     []struct {
			When    []term `json:"when_all"`
			Require []term `json:"require_all"`
		} `json:"implications"`
		Incompatibilities []struct {
			All []term `json:"all_of"`
		} `json:"incompatibilities"`
		Constraints []struct {
			When    []term   `json:"when_any"`
			Allowed []string `json:"allowed_sensitivity_levels"`
		} `json:"sensitivity_constraints"`
		Dimensions []struct {
			When []term `json:"when_all"`
		} `json:"dimension_requirements"`
		Contexts []struct {
			When []term `json:"when_all"`
		} `json:"context_requirements"`
	} `json:"semantics"`
	Presentation struct {
		Renderer string `json:"renderer_id"`
		Version  string `json:"renderer_version"`
		Text     bool   `json:"text_authoritative"`
		Markings []struct {
			ID   string `json:"id"`
			Text string `json:"display_text"`
		} `json:"sensitivity_markings"`
	} `json:"presentation"`
}
type domainDocument struct {
	ID       string `json:"domain_id"`
	Version  string `json:"version"`
	Purpose  string `json:"policy_purpose"`
	Mode     string `json:"disclosure_revocation_mode"`
	Ceilings map[string]struct {
		Version string `json:"profile_version"`
		Level   string `json:"classification_ceiling"`
	} `json:"label_profile_ceilings"`
	Authorities []string          `json:"trusted_attribute_authorities"`
	Bridges     []json.RawMessage `json:"approved_profile_bridges"`
	Network     struct {
		Zones []string `json:"zones"`
	} `json:"network"`
}

func CompileValidatedProfile(profileJSON, domainJSON []byte) (*Evaluator, error) {
	var evaluator Evaluator
	if json.Unmarshal(profileJSON, &evaluator.profile) != nil || json.Unmarshal(domainJSON, &evaluator.domain) != nil {
		return nil, ErrDenied
	}
	p, d := evaluator.profile, evaluator.domain
	if p.ID == "" || p.Version == "" || p.Purpose == "test_fixture" || d.Purpose == "test_fixture" || len(p.Sensitivity) == 0 || len(d.Ceilings) != 1 || d.Mode != "request_boundary" || len(d.Bridges) != 0 || p.Semantics.Contract != "stead.security-profile-rules.v1" || p.Semantics.Representability != "closed_profile_semantics_v1" || p.Semantics.Unmapped != "deny" || p.Presentation.Renderer != "stead.security_markings.v1" || p.Presentation.Version != "1.0.0" || !p.Presentation.Text {
		return nil, ErrDenied
	}
	ceiling, ok := d.Ceilings[p.ID]
	if !ok || ceiling.Version != p.Version || !slices.Contains(p.Sensitivity, ceiling.Level) {
		return nil, ErrDenied
	}
	return &evaluator, nil
}

type Result struct {
	Marking     string
	Obligations []string
}

func (evaluator *Evaluator) Evaluate(label Label, session identity.SessionRecord) (Result, error) {
	if evaluator == nil || label.ProfileID != evaluator.profile.ID || label.Version == 0 || session.SecurityDomain != evaluator.domain.ID || !slices.Contains(evaluator.domain.Authorities, session.Authority) || !slices.Contains(evaluator.domain.Network.Zones, session.NetworkZone) {
		return Result{}, ErrDenied
	}
	// There are no trusted compartment/handling/export assertions on bootstrap
	// sessions. No restricted label is reduced to a sensitivity-only label.
	if len(label.HandlingRegimes)+len(label.Categories)+len(label.Compartments)+len(label.DisseminationControls)+len(label.ReleasableTo)+len(label.ExportControls)+len(label.DerivationSources) != 0 || label.Originator != "" || label.ClassificationAuthority != "" || label.DeclassificationOrReviewInstructions != "" {
		return Result{}, ErrDenied
	}
	levels := evaluator.profile.Sensitivity
	rank := slices.Index(levels, label.SensitivityLevel)
	sessionRank := slices.Index(levels, session.ClassificationCeilings[label.ProfileID])
	deploymentRank := slices.Index(levels, evaluator.domain.Ceilings[label.ProfileID].Level)
	if rank < 0 || sessionRank < 0 || deploymentRank < 0 || rank > sessionRank || rank > deploymentRank {
		return Result{}, ErrDenied
	}
	present := func(value term) bool { return value.Dimension == "sensitivity" && value.ID == label.SensitivityLevel }
	all := func(terms []term) bool {
		for _, value := range terms {
			if !present(value) {
				return false
			}
		}
		return true
	}
	for _, rule := range evaluator.profile.Semantics.Implications {
		if all(rule.When) && !all(rule.Require) {
			return Result{}, ErrDenied
		}
	}
	for _, rule := range evaluator.profile.Semantics.Incompatibilities {
		if all(rule.All) {
			return Result{}, ErrDenied
		}
	}
	for _, rule := range evaluator.profile.Semantics.Constraints {
		for _, value := range rule.When {
			if present(value) && !slices.Contains(rule.Allowed, label.SensitivityLevel) {
				return Result{}, ErrDenied
			}
		}
	}
	for _, rule := range evaluator.profile.Semantics.Dimensions {
		if all(rule.When) {
			return Result{}, ErrDenied
		}
	}
	for _, rule := range evaluator.profile.Semantics.Contexts {
		if all(rule.When) {
			return Result{}, ErrDenied
		}
	}
	for _, marking := range evaluator.profile.Presentation.Markings {
		if marking.ID == label.SensitivityLevel && marking.Text != "" {
			return Result{Marking: marking.Text, Obligations: []string{"display_marking", "audit_access"}}, nil
		}
	}
	return Result{}, ErrDenied
}
