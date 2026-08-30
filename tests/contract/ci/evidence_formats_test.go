package ci_test

import (
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func spdxGraphElement(t testing.TB, document map[string]any, kind string) map[string]any {
	t.Helper()
	graph, ok := document["@graph"].([]any)
	if !ok {
		t.Fatal("SPDX fixture graph missing")
	}
	for _, candidate := range graph {
		element, ok := candidate.(map[string]any)
		if ok && element["type"] == kind {
			return element
		}
	}
	t.Fatalf("SPDX fixture element %s missing", kind)
	return nil
}

// CICD-004: the closed pre-signing evidence profile admits an actual SPDX
// 3.0.1 JSON document and SLSA provenance v1 in-toto statement, then rejects
// structural or semantic substitutions without becoming a general parser.
func TestSPDXThreeEvidenceAdmissionIsClosed(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(map[string]any)
		code   string
	}{
		{"wrong context", func(document map[string]any) { document["@context"] = "https://spdx.org/rdf/3.0.0/spdx-context.jsonld" }, "spdx_evidence_schema_mismatch"},
		{"empty graph", func(document map[string]any) { document["@graph"] = []any{} }, "spdx_evidence_schema_mismatch"},
		{"unknown graph type", func(document map[string]any) {
			spdxGraphElement(t, document, "software_Package")["type"] = "future_Package"
		}, "spdx_evidence_schema_mismatch"},
		{"missing graph type", func(document map[string]any) { delete(spdxGraphElement(t, document, "software_Package"), "type") }, "spdx_evidence_schema_mismatch"},
		{"duplicate agent", func(document map[string]any) {
			document["@graph"] = append(document["@graph"].([]any), spdxGraphElement(t, document, "SoftwareAgent"))
		}, "spdx_evidence_schema_mismatch"},
		{"wrong spec version", func(document map[string]any) { spdxGraphElement(t, document, "CreationInfo")["specVersion"] = "3.0.0" }, "spdx_evidence_schema_mismatch"},
		{"noncanonical creation time", func(document map[string]any) {
			spdxGraphElement(t, document, "CreationInfo")["created"] = "2026-08-30T08:00:00-04:00"
		}, "spdx_evidence_schema_mismatch"},
		{"invalid agent IRI", func(document map[string]any) {
			spdxGraphElement(t, document, "SoftwareAgent")["spdxId"] = "relative-agent"
		}, "spdx_evidence_schema_mismatch"},
		{"package creation mismatch", func(document map[string]any) {
			spdxGraphElement(t, document, "software_Package")["creationInfo"] = "_:other"
		}, "spdx_evidence_schema_mismatch"},
		{"empty package version", func(document map[string]any) {
			spdxGraphElement(t, document, "software_Package")["software_packageVersion"] = ""
		}, "spdx_evidence_schema_mismatch"},
		{"document root mismatch", func(document map[string]any) { spdxGraphElement(t, document, "SpdxDocument")["rootElement"] = []any{} }, "spdx_evidence_schema_mismatch"},
		{"document profile mismatch", func(document map[string]any) {
			spdxGraphElement(t, document, "SpdxDocument")["profileConformance"] = []any{"core"}
		}, "spdx_evidence_schema_mismatch"},
		{"SBOM element mismatch", func(document map[string]any) { spdxGraphElement(t, document, "software_Sbom")["element"] = []any{} }, "spdx_evidence_schema_mismatch"},
		{"unknown package member", func(document map[string]any) { spdxGraphElement(t, document, "software_Package")["future"] = true }, "spdx_evidence_schema_mismatch"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			mutateEvidenceReport(t, &input, "evidence/sbom.spdx.json", testCase.mutate)
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestSLSAProvenanceV1AdmissionIsClosed(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong statement type", func(document map[string]any) { document["_type"] = "https://in-toto.io/Statement/v0.1" }},
		{"wrong predicate type", func(document map[string]any) { document["predicateType"] = "https://slsa.dev/provenance/v0.2" }},
		{"missing subject", func(document map[string]any) { document["subject"] = []any{} }},
		{"duplicate subject", func(document map[string]any) {
			document["subject"] = append(document["subject"].([]any), document["subject"].([]any)[0])
		}},
		{"extra digest algorithm", func(document map[string]any) {
			document["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha512"] = "00"
		}},
		{"invalid subject digest", func(document map[string]any) {
			document["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = "00"
		}},
		{"invalid build type", func(document map[string]any) {
			document["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["buildType"] = "relative-build-type"
		}},
		{"invalid builder ID", func(document map[string]any) {
			document["predicate"].(map[string]any)["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = "relative-builder"
		}},
		{"empty source revision", func(document map[string]any) {
			document["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)["sourceRevision"] = ""
		}},
		{"invalid lock digest", func(document map[string]any) {
			document["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)["dependencyLockDigest"] = "sha256:00"
		}},
		{"networked build", func(document map[string]any) {
			document["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["internalParameters"].(map[string]any)["networkAccess"] = true
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			mutateEvidenceReport(t, &input, "evidence/provenance.json", testCase.mutate)
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != "provenance_evidence_schema_mismatch" {
				t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
			}
		})
	}

	bindingCases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unrelated source revision", func(document map[string]any) {
			document["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)["sourceRevision"] = "ffffffffffffffffffffffffffffffffffffffff"
		}},
		{"unrelated dependency lock", func(document map[string]any) {
			document["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)["dependencyLockDigest"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"unrelated subject digest", func(document map[string]any) {
			document["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"unrelated subject name", func(document map[string]any) {
			document["subject"].([]any)[0].(map[string]any)["name"] = "other-policy-content"
		}},
	}
	for _, testCase := range bindingCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			mutateEvidenceReport(t, &input, "evidence/provenance.json", testCase.mutate)
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != "provenance_evidence_binding_mismatch" {
				t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
			}
		})
	}
}
