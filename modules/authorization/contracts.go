package authorization

import (
	"bytes"
	"embed"
	"encoding/json"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

const EvaluatorContractVersion = "stead-native-local-metadata-v1"

// These are generated original Stead runtime contracts, not test fixtures.
// The native ABI supports these exact schema/table semantics. Future compiled
// semantics require an explicit new ABI; unknown signed rules cannot allow.
//
//go:embed contract/*.json
var contracts embed.FS

func RuntimeContractFiles() []policyrelease.File {
	files := []policyrelease.File{}
	for _, name := range []string{"input-schema.json", "output-schema.json", "decision-table.json", "registries.json"} {
		data, _ := contracts.ReadFile("contract/" + name)
		files = append(files, policyrelease.File{Path: "payload/" + name, MediaType: "application/json", Content: data})
	}
	return files
}

func equivalentJSON(a, b []byte) bool {
	var first, second any
	if decodeClosed(a, &first) != nil || decodeClosed(b, &second) != nil {
		return false
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	return bytes.Equal(left, right)
}
func supportedContracts(unsigned policyrelease.UnsignedActivation) bool {
	if unsigned.Manifest.EvaluatorContractVersion != EvaluatorContractVersion {
		return false
	}
	expected := map[string][]byte{}
	for _, pair := range []struct{ role, path string }{{"input_schema", "input-schema.json"}, {"output_schema", "output-schema.json"}, {"decision_table", "decision-table.json"}, {"registries", "registries.json"}} {
		expected[pair.role], _ = contracts.ReadFile("contract/" + pair.path)
	}
	files := map[string][]byte{}
	for _, file := range unsigned.Files {
		files[file.Path] = file.Content
	}
	for _, binding := range unsigned.Manifest.ContractBindings {
		if !equivalentJSON(files[binding.Path], expected[binding.Role]) {
			return false
		}
	}
	var registry struct {
		Required    []string `json:"required_context_ids"`
		Reasons     []string `json:"reason_code_ids"`
		Obligations []string `json:"obligation_ids"`
		Denies      []string `json:"explicit_deny_ids"`
		Version     string   `json:"schema_version"`
	}
	if decodeClosed(expected["registries"], &registry) != nil {
		return false
	}
	actual, _ := json.Marshal(struct{ Required, Reasons, Obligations, Denies []string }{unsigned.Manifest.RequiredContextIDs, unsigned.Manifest.ReasonCodeIDs, unsigned.Manifest.ObligationIDs, unsigned.Manifest.ExplicitDenyIDs})
	want, _ := json.Marshal(struct{ Required, Reasons, Obligations, Denies []string }{registry.Required, registry.Reasons, registry.Obligations, registry.Denies})
	return bytes.Equal(actual, want)
}
