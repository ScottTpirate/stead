package ci_test

import (
	"bytes"
	"encoding/json"
	"testing"
)

type vectorInventory struct {
	SchemaVersion string `json:"schema_version"`
	ConsumerOwner string `json:"consumer_owner"`
	Authority     string `json:"authority"`
	Cases         []struct {
		ID         string `json:"id"`
		Obligation string `json:"obligation"`
		Mutation   string `json:"mutation"`
		Expected   string `json:"expected"`
	} `json:"cases"`
}

func TestNegativeVectorInventoriesAreBoundedAndNonAuthorizing(t *testing.T) {
	for _, fixture := range []string{"vectors/negative-cases.json", "vectors/ws06-consumer-negative-cases.json"} {
		t.Run(fixture, func(t *testing.T) {
			raw := fixtureBytes(t, fixture)
			if bytes.Contains(bytes.ToLower(raw), []byte("private_key")) || bytes.Contains(bytes.ToLower(raw), []byte("begin private key")) {
				t.Fatal("vector inventory contains private key material")
			}
			var inventory vectorInventory
			if err := json.Unmarshal(raw, &inventory); err != nil {
				t.Fatal(err)
			}
			if inventory.SchemaVersion != "1.0.0" || len(inventory.Cases) == 0 {
				t.Fatal("invalid or empty vector inventory")
			}
			seen := make(map[string]struct{}, len(inventory.Cases))
			for _, testCase := range inventory.Cases {
				if testCase.ID == "" {
					t.Fatal("vector has empty ID")
				}
				if _, duplicate := seen[testCase.ID]; duplicate {
					t.Fatalf("duplicate vector ID %q", testCase.ID)
				}
				seen[testCase.ID] = struct{}{}
			}
			if fixture == "vectors/ws06-consumer-negative-cases.json" && (inventory.ConsumerOwner != "WS-06" || inventory.Authority != "none") {
				t.Fatal("consumer vectors crossed verifier/authority ownership")
			}
		})
	}
}

func TestBuilderNegativeInventoryCoversEveryOwnedObligation(t *testing.T) {
	var inventory vectorInventory
	if err := json.Unmarshal(fixtureBytes(t, "vectors/negative-cases.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{
		"T-ADR-0006-DSSE":                 false,
		"T-ADR-0006-CONTENT-INTEGRITY":    false,
		"T-ADR-0006-ARCHIVE-SAFETY":       false,
		"T-ADR-0006-TRANSPORT-IDENTITY":   false,
		"T-ADR-0006-ASSURANCE-POLICY":     false,
		"T-ADR-0006-CUSTODIAN-SEPARATION": false,
		"T-ADR-0006-TUF-NONAUTHORITY":     false,
	}
	for _, testCase := range inventory.Cases {
		if _, ok := required[testCase.Obligation]; ok {
			required[testCase.Obligation] = true
		}
	}
	for obligation, covered := range required {
		if !covered {
			t.Fatalf("negative inventory missing %s", obligation)
		}
	}
}
