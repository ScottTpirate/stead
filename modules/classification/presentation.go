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
	// These fields are required JSON arrays. A nil destination would turn a
	// valid empty source array into null when the copied presentation is sent.
	presentation.Markings = append([]Marking{}, presentation.Markings...)
	presentation.RequiredSurfaces = append([]string{}, presentation.RequiredSurfaces...)
	presentation.WarningActions = append([]string{}, presentation.WarningActions...)
	return presentation
}
