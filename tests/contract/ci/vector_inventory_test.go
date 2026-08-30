package ci_test

import (
	"bytes"
	"encoding/json"
	"strings"
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

type ws06MutationInstruction struct {
	Operation          string `json:"operation"`
	Target             string `json:"target"`
	ByteOffset         int    `json:"byte_offset,omitempty"`
	BitMask            int    `json:"bit_mask,omitempty"`
	Replacement        string `json:"replacement,omitempty"`
	ReplacementFixture string `json:"replacement_fixture,omitempty"`
}

type ws06ConsumerInventory struct {
	SchemaVersion string `json:"schema_version"`
	FixtureStatus string `json:"fixture_status"`
	BaseVector    string `json:"base_vector"`
	ConsumerOwner string `json:"consumer_owner"`
	Authority     string `json:"authority"`
	Cases         []struct {
		ID                   string                  `json:"id"`
		Obligation           string                  `json:"obligation"`
		Mutation             ws06MutationInstruction `json:"mutation"`
		ExpectedOutcome      string                  `json:"expected_outcome"`
		ExpectedConsumerCode string                  `json:"expected_consumer_code"`
	} `json:"cases"`
}

func TestNegativeVectorInventoriesAreBoundedAndNonAuthorizing(t *testing.T) {
	for _, fixture := range []string{"vectors/negative-cases.json"} {
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
		})
	}
}

func TestWS06ConsumerFixtureIsClosedCompleteAndNonAuthorizing(t *testing.T) {
	raw := fixtureBytes(t, "vectors/ws06-consumer-negative-cases.json")
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var inventory ws06ConsumerInventory
	if err := decoder.Decode(&inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.SchemaVersion != "1.0.0" || inventory.FixtureStatus != "nonauthorizing_consumer_mutation_instructions" || inventory.BaseVector != "golden-vector.json" || inventory.ConsumerOwner != "WS-06" || inventory.Authority != "none" {
		t.Fatal("consumer fixture crossed verifier ownership or mutable base-vector identity")
	}
	required := map[string]bool{
		"activation-signature-bit-flip": false, "release-signature-bit-flip": false,
		"activation-payload-bit-flip": false, "release-payload-bit-flip": false,
		"misleading-keyid": false, "wrong-curve-spki": false, "wrong-purpose": false,
		"duplicate-spki-alias": false, "duplicate-custodian-alias": false,
		"expired-trust-key": false, "revoked-trust-key": false,
		"archive-attestation-swap": false, "tuf-only-substitution": false,
		"offline-egress-denied": false, "syntactic-r1-s1-arbitrary-receipt": false,
	}
	allowedOperations := map[string]bool{
		"flip_bit": true, "replace_string": true, "replace_fixture": true,
		"duplicate_with_alias": true, "set_verification_time": true,
		"remove_dsse_envelopes": true, "deny_network": true,
		"replace_with_r1_s1_and_arbitrary_receipt": true,
	}
	allowedCodes := map[string]bool{
		"crypto_signature_invalid": true, "signed_payload_mismatch": true,
		"spki_identity_mismatch": true, "unsupported_key_profile": true,
		"key_purpose_mismatch": true, "duplicate_key_identity": true,
		"distinct_custodian_threshold_not_met": true, "key_outside_validity": true,
		"key_revoked": true, "immutable_pair_mismatch": true,
		"authoritative_dsse_missing": true, "offline_verification_complete": true,
	}
	if len(inventory.Cases) != len(required) {
		t.Fatalf("consumer fixture has %d cases, want exact complete set %d", len(inventory.Cases), len(required))
	}
	for _, testCase := range inventory.Cases {
		if _, ok := required[testCase.ID]; !ok || required[testCase.ID] {
			t.Fatalf("unknown or duplicate consumer fixture case %q", testCase.ID)
		}
		required[testCase.ID] = true
		if !strings.HasPrefix(testCase.Obligation, "T-ADR-0006-") || !allowedOperations[testCase.Mutation.Operation] || testCase.Mutation.Target == "" || !allowedCodes[testCase.ExpectedConsumerCode] {
			t.Fatalf("consumer fixture case %q is not a closed executable instruction", testCase.ID)
		}
		if testCase.ExpectedOutcome != "reject" && !(testCase.ID == "offline-egress-denied" && testCase.ExpectedOutcome == "accept") {
			t.Fatalf("consumer fixture case %q has invalid outcome %q", testCase.ID, testCase.ExpectedOutcome)
		}
		if testCase.Mutation.Operation == "flip_bit" && (testCase.Mutation.ByteOffset < 0 || testCase.Mutation.BitMask < 1 || testCase.Mutation.BitMask > 255) {
			t.Fatalf("consumer fixture case %q has invalid bit mutation", testCase.ID)
		}
	}
	for id, covered := range required {
		if !covered {
			t.Fatalf("consumer fixture missing %s", id)
		}
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
	reviewerCases := map[string]bool{
		"dsse-r1-s1-arbitrary-receipt-nonauthority":      false,
		"evidence-renamed-or-encoded-protected-material": false,
		"handoff-deep-copy-isolation":                    false,
		"profile-schema-id-or-version-mismatch":          false,
		"deployment-schema-id-or-version-mismatch":       false,
		"deployment-profile-ceiling-mismatch":            false,
	}
	for _, testCase := range inventory.Cases {
		if _, ok := reviewerCases[testCase.ID]; ok {
			reviewerCases[testCase.ID] = true
		}
	}
	for id, covered := range reviewerCases {
		if !covered {
			t.Fatalf("negative inventory missing review regression %s", id)
		}
	}
}
