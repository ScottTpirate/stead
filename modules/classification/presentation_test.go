package classification

import (
	"encoding/json"
	"testing"
)

func TestPresentationCopyPreservesRequiredJSONArrays(t *testing.T) {
	presentation := SecurityPresentation{
		Markings:         []Marking{{Kind: "sensitivity", Text: "Internal"}},
		RequiredSurfaces: []string{},
		WarningActions:   []string{},
	}
	copy := presentation.Copy().Copy()
	encoded, err := json.Marshal(copy)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"required_surfaces", "warning_actions"} {
		if string(fields[field]) != "[]" {
			t.Fatalf("copied %s = %s, want required empty JSON array", field, fields[field])
		}
	}
	copy.Markings[0].Text = "Changed"
	if presentation.Markings[0].Text != "Internal" {
		t.Fatal("copied markings alias original presentation")
	}
}

func TestPresentationCopyDetachesSurfaceAndWarningArrays(t *testing.T) {
	presentation := SecurityPresentation{RequiredSurfaces: []string{"badge"}, WarningActions: []string{"download"}}
	copy := presentation.Copy()
	copy.RequiredSurfaces[0] = "top_banner"
	copy.WarningActions[0] = "export"
	if presentation.RequiredSurfaces[0] != "badge" || presentation.WarningActions[0] != "download" {
		t.Fatal("copied presentation aliases original arrays")
	}
}
