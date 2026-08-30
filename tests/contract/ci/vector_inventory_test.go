package ci_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
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
	Operation         string          `json:"operation"`
	TargetFile        string          `json:"target_file"`
	Target            string          `json:"target"`
	DecodedTarget     string          `json:"decoded_target,omitempty"`
	ByteOffset        int             `json:"byte_offset,omitempty"`
	BitMask           int             `json:"bit_mask,omitempty"`
	Replacement       json.RawMessage `json:"replacement,omitempty"`
	ReplacementFile   string          `json:"replacement_file,omitempty"`
	ReplacementTarget string          `json:"replacement_target,omitempty"`
}

type ws06ConsumerInventory struct {
	SchemaVersion     string `json:"schema_version"`
	FixtureStatus     string `json:"fixture_status"`
	BaseVector        string `json:"base_vector"`
	VerificationTime  string `json:"verification_time"`
	ExecutionContract string `json:"execution_contract"`
	ConsumerOwner     string `json:"consumer_owner"`
	Authority         string `json:"authority"`
	Cases             []struct {
		ID                   string                  `json:"id"`
		Obligation           string                  `json:"obligation"`
		Mutation             ws06MutationInstruction `json:"mutation"`
		ExpectedOutcome      string                  `json:"expected_outcome"`
		ExpectedConsumerCode string                  `json:"expected_consumer_code"`
	} `json:"cases"`
}

func decodeFixtureJSON(t testing.TB, raw []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document
}

func jsonPointerTokens(pointer string) ([]string, error) {
	if pointer == "/" {
		return nil, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("JSON pointer must start with slash")
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	for index := range parts {
		parts[index] = strings.ReplaceAll(strings.ReplaceAll(parts[index], "~1", "/"), "~0", "~")
	}
	return parts, nil
}

func jsonPointerValue(document any, pointer string) (any, error) {
	tokens, err := jsonPointerTokens(pointer)
	if err != nil {
		return nil, err
	}
	current := document
	for _, token := range tokens {
		switch value := current.(type) {
		case map[string]any:
			var present bool
			current, present = value[token]
			if !present {
				return nil, fmt.Errorf("object target is absent")
			}
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(value) {
				return nil, fmt.Errorf("array target is absent")
			}
			current = value[index]
		default:
			return nil, fmt.Errorf("target parent is scalar")
		}
	}
	return current, nil
}

func setJSONPointer(document *any, pointer string, replacement any) error {
	tokens, err := jsonPointerTokens(pointer)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		*document = replacement
		return nil
	}
	parentPointer := "/" + strings.Join(tokens[:len(tokens)-1], "/")
	if len(tokens) == 1 {
		parentPointer = "/"
	}
	parent, err := jsonPointerValue(*document, parentPointer)
	if err != nil {
		return err
	}
	last := tokens[len(tokens)-1]
	switch value := parent.(type) {
	case map[string]any:
		if _, present := value[last]; !present {
			return fmt.Errorf("object target is absent")
		}
		value[last] = replacement
	case []any:
		index, err := strconv.Atoi(last)
		if err != nil || index < 0 || index >= len(value) {
			return fmt.Errorf("array target is absent")
		}
		value[index] = replacement
	default:
		return fmt.Errorf("target parent is scalar")
	}
	return nil
}

func replacementJSON(t testing.TB, raw json.RawMessage) any {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("mutation replacement is absent")
	}
	return decodeFixtureJSON(t, raw)
}

func replacementFileJSON(t testing.TB, mutation ws06MutationInstruction) any {
	t.Helper()
	if mutation.ReplacementFile == "" {
		t.Fatal("mutation replacement file is absent")
	}
	return decodeFixtureJSON(t, fixtureBytes(t, mutation.ReplacementFile))
}

func mutateEncodedJSON(t testing.TB, document *any, mutation ws06MutationInstruction, mutate func(*any)) {
	t.Helper()
	encodedValue, err := jsonPointerValue(*document, mutation.Target)
	if err != nil {
		t.Fatal(err)
	}
	encoded, ok := encodedValue.(string)
	if !ok {
		t.Fatal("encoded target is not a string")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	nested := decodeFixtureJSON(t, decoded)
	mutate(&nested)
	mutated, err := json.Marshal(nested)
	if err != nil {
		t.Fatal(err)
	}
	if err := setJSONPointer(document, mutation.Target, base64.StdEncoding.EncodeToString(mutated)); err != nil {
		t.Fatal(err)
	}
}

func materializeWS06Mutation(t testing.TB, mutation ws06MutationInstruction) []byte {
	t.Helper()
	document := decodeFixtureJSON(t, fixtureBytes(t, mutation.TargetFile))
	before, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	switch mutation.Operation {
	case "replace_value":
		if err := setJSONPointer(&document, mutation.Target, replacementJSON(t, mutation.Replacement)); err != nil {
			t.Fatal(err)
		}
	case "replace_value_from_file":
		replacement := replacementFileJSON(t, mutation)
		replacement, err = jsonPointerValue(replacement, mutation.ReplacementTarget)
		if err != nil {
			t.Fatal(err)
		}
		if err := setJSONPointer(&document, mutation.Target, replacement); err != nil {
			t.Fatal(err)
		}
	case "merge_object_from_file":
		target, err := jsonPointerValue(document, mutation.Target)
		if err != nil {
			t.Fatal(err)
		}
		targetObject, targetOK := target.(map[string]any)
		replacementObject, replacementOK := replacementFileJSON(t, mutation).(map[string]any)
		if !targetOK || !replacementOK {
			t.Fatal("merge mutation requires JSON objects")
		}
		for key, value := range replacementObject {
			targetObject[key] = value
		}
	case "flip_nested_base64_bit":
		mutateEncodedJSON(t, &document, mutation, func(nested *any) {
			value, err := jsonPointerValue(*nested, mutation.DecodedTarget)
			if err != nil {
				t.Fatal(err)
			}
			encoded, ok := value.(string)
			if !ok {
				t.Fatal("nested Base64 target is not a string")
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || mutation.ByteOffset < 0 || mutation.ByteOffset >= len(decoded) || mutation.BitMask < 1 || mutation.BitMask > 255 {
				t.Fatal("invalid nested Base64 bit mutation")
			}
			decoded[mutation.ByteOffset] ^= byte(mutation.BitMask)
			if err := setJSONPointer(nested, mutation.DecodedTarget, base64.StdEncoding.EncodeToString(decoded)); err != nil {
				t.Fatal(err)
			}
		})
	case "replace_base64_json_value":
		mutateEncodedJSON(t, &document, mutation, func(nested *any) {
			if err := setJSONPointer(nested, mutation.DecodedTarget, replacementJSON(t, mutation.Replacement)); err != nil {
				t.Fatal(err)
			}
		})
	case "reserialize_base64_json_from_recipe":
		recipe := replacementFileJSON(t, mutation).(map[string]any)
		if recipe["transformation"] != "decode_and_indented_reserialize_dsse_envelope" || recipe["preserve_payload_and_signatures"] != true {
			t.Fatal("invalid exact-ceremony recipe")
		}
		encodedValue, err := jsonPointerValue(document, mutation.Target)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(encodedValue.(string))
		if err != nil {
			t.Fatal(err)
		}
		nested := decodeFixtureJSON(t, decoded)
		reserialized, err := json.MarshalIndent(nested, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		reserialized = append(reserialized, '\n')
		if err := setJSONPointer(&document, mutation.Target, base64.StdEncoding.EncodeToString(reserialized)); err != nil {
			t.Fatal(err)
		}
	case "replace_document_from_file":
		if err := setJSONPointer(&document, mutation.Target, replacementFileJSON(t, mutation)); err != nil {
			t.Fatal(err)
		}
	case "replace_signature_and_add_receipt":
		replacement := replacementFileJSON(t, mutation).(map[string]any)
		mutateEncodedJSON(t, &document, mutation, func(nested *any) {
			if err := setJSONPointer(nested, "/signatures/0/keyid", replacement["key_id"]); err != nil {
				t.Fatal(err)
			}
			if err := setJSONPointer(nested, "/signatures/0/sig", replacement["signature_base64"]); err != nil {
				t.Fatal(err)
			}
		})
		activation, err := jsonPointerValue(document, "/activation")
		if err != nil {
			t.Fatal(err)
		}
		activation.(map[string]any)["presented_receipt"] = replacement["presented_receipt"]
	default:
		t.Fatalf("unsupported mutation operation %q", mutation.Operation)
	}
	after, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("mutation resolved but did not change its target")
	}
	return after
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
	verificationTime, timeErr := time.Parse(time.RFC3339, inventory.VerificationTime)
	if inventory.SchemaVersion != "1.0.0" || inventory.FixtureStatus != "nonauthorizing_consumer_mutation_instructions" || inventory.BaseVector != "golden-vector.json" || inventory.ExecutionContract != "mutation_materialization_only" || inventory.ConsumerOwner != "WS-06" || inventory.Authority != "none" || timeErr != nil || verificationTime.Format(time.RFC3339) != inventory.VerificationTime {
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
		"flip_nested_base64_bit": true, "replace_base64_json_value": true,
		"replace_value": true, "replace_value_from_file": true,
		"merge_object_from_file": true, "reserialize_base64_json_from_recipe": true,
		"replace_document_from_file": true, "replace_signature_and_add_receipt": true,
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
		if !strings.HasPrefix(testCase.Obligation, "T-ADR-0006-") || !allowedOperations[testCase.Mutation.Operation] || testCase.Mutation.TargetFile == "" || testCase.Mutation.Target == "" || !allowedCodes[testCase.ExpectedConsumerCode] {
			t.Fatalf("consumer fixture case %q is not a closed executable instruction", testCase.ID)
		}
		if testCase.ExpectedOutcome != "reject" && !(testCase.ID == "offline-egress-denied" && testCase.ExpectedOutcome == "accept") {
			t.Fatalf("consumer fixture case %q has invalid outcome %q", testCase.ID, testCase.ExpectedOutcome)
		}
		if testCase.Mutation.Operation == "flip_nested_base64_bit" && (testCase.Mutation.DecodedTarget == "" || testCase.Mutation.ByteOffset < 0 || testCase.Mutation.BitMask < 1 || testCase.Mutation.BitMask > 255) {
			t.Fatalf("consumer fixture case %q has invalid bit mutation", testCase.ID)
		}
		materialized := materializeWS06Mutation(t, testCase.Mutation)
		if len(materialized) == 0 {
			t.Fatalf("consumer fixture case %q did not materialize", testCase.ID)
		}
		switch testCase.ID {
		case "duplicate-spki-alias":
			mutated := decodeFixtureJSON(t, materialized).(map[string]any)
			keys := mutated["keys"].([]any)
			first, second := keys[0].(map[string]any), keys[1].(map[string]any)
			if mutated["signature_threshold"] != json.Number("2") || first["spki_der_base64"] != second["spki_der_base64"] || first["key_id"] == second["key_id"] {
				t.Fatal("duplicate-SPKI vector does not preserve threshold two with an alias key ID")
			}
		case "duplicate-custodian-alias":
			mutated := decodeFixtureJSON(t, materialized).(map[string]any)
			keys := mutated["keys"].([]any)
			if mutated["signature_threshold"] != json.Number("2") || keys[0].(map[string]any)["custodian_id"] != keys[1].(map[string]any)["custodian_id"] {
				t.Fatal("duplicate-custodian vector does not exercise a threshold-two collision")
			}
		case "expired-trust-key":
			mutated := decodeFixtureJSON(t, materialized).(map[string]any)
			notAfter, err := time.Parse(time.RFC3339, mutated["keys"].([]any)[0].(map[string]any)["not_after"].(string))
			if err != nil || !notAfter.Before(verificationTime) {
				t.Fatal("expired-key vector is not expired at the pinned verification time")
			}
		case "archive-attestation-swap":
			mutated := decodeFixtureJSON(t, materialized).(map[string]any)
			encoded := mutated["attestation"].(map[string]any)["envelope_base64"].(string)
			envelope, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policyrelease.ParseDSSEEnvelope(envelope); err != nil {
				t.Fatalf("alternate exact envelope is not syntax-valid: %v", err)
			}
		case "syntactic-r1-s1-arbitrary-receipt":
			mutated := decodeFixtureJSON(t, materialized).(map[string]any)
			activation := mutated["activation"].(map[string]any)
			envelope, err := base64.StdEncoding.Strict().DecodeString(activation["envelope_base64"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policyrelease.ParseDSSEEnvelope(envelope); err != nil || activation["presented_receipt"] == nil {
				t.Fatalf("r=1,s=1 mutation must remain syntax-only presented material: %v", err)
			}
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
