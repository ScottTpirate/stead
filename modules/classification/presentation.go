package classification

type Marking struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}
type SecurityPresentation struct {
	ProfileID             string    `json:"profile_id"`
	ProfileVersion        string    `json:"profile_version"`
	PolicyBundleID        string    `json:"policy_bundle_id"`
	LabelRevision         string    `json:"label_revision"`
	RendererID            string    `json:"renderer_id"`
	RendererVersion       string    `json:"renderer_version"`
	Markings              []Marking `json:"markings"`
	RequiredSurfaces      []string  `json:"required_surfaces"`
	WarningActions        []string  `json:"warning_actions"`
	TextAuthoritative     bool      `json:"text_authoritative"`
	ColorSupplementalOnly bool      `json:"color_supplemental_only"`
}

func (presentation SecurityPresentation) Copy() SecurityPresentation {
	presentation.Markings = append([]Marking(nil), presentation.Markings...)
	presentation.RequiredSurfaces = append([]string(nil), presentation.RequiredSurfaces...)
	presentation.WarningActions = append([]string(nil), presentation.WarningActions...)
	return presentation
}
