package ci_test

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func withUnknownPadding(t *testing.T, envelope []byte, size int) []byte {
	t.Helper()
	if len(envelope) == 0 || envelope[len(envelope)-1] != '}' {
		t.Fatal("not a JSON object")
	}
	prefix := append(append([]byte(nil), envelope[:len(envelope)-1]...), []byte(`,"ignored_padding":"`)...)
	suffix := []byte(`"}`)
	padding := size - len(prefix) - len(suffix)
	if padding < 0 {
		t.Fatalf("target %d smaller than envelope", size)
	}
	result := make([]byte, 0, size)
	result = append(result, prefix...)
	result = append(result, bytes.Repeat([]byte{'a'}, padding)...)
	result = append(result, suffix...)
	return result
}

func nestedUnknownEnvelope(t *testing.T, levels int) []byte {
	t.Helper()
	payload := []byte("x")
	base, _ := externallySign(t, policyrelease.ActivationManifestPayloadType, payload, 1, false)
	prefix := append(append([]byte(nil), base[:len(base)-1]...), []byte(`,"ignored":`)...)
	prefix = append(prefix, bytes.Repeat([]byte{'['}, levels)...)
	prefix = append(prefix, '0')
	prefix = append(prefix, bytes.Repeat([]byte{']'}, levels)...)
	prefix = append(prefix, '}')
	return prefix
}

// T-ADR-0006-DSSE parser/resource ceilings and canonical Base64.
func TestDSSEEnvelopeAndPayloadBoundaries(t *testing.T) {
	base, _ := externallySign(t, policyrelease.ActivationManifestPayloadType, []byte("x"), 1, false)
	exactEnvelope := withUnknownPadding(t, base, policyrelease.MaxEnvelopeBytes)
	if _, err := policyrelease.ParseDSSEEnvelope(exactEnvelope); err != nil {
		t.Fatalf("exact envelope ceiling rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	oneOverEnvelope := append(exactEnvelope, ' ')
	if _, err := policyrelease.ParseDSSEEnvelope(oneOverEnvelope); policyrelease.ErrorCode(err) != "envelope_size_limit" {
		t.Fatalf("one-over envelope error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	exactPayload := bytes.Repeat([]byte{'p'}, policyrelease.MaxDecodedPayloadBytes)
	exactPayloadEnvelope, _ := externallySign(t, policyrelease.ActivationManifestPayloadType, exactPayload, 1, false)
	parsed, err := policyrelease.ParseDSSEEnvelope(exactPayloadEnvelope)
	if err != nil || len(parsed.Payload) != policyrelease.MaxDecodedPayloadBytes {
		t.Fatalf("exact payload ceiling: len=%d err=%v (%s)", len(parsed.Payload), err, policyrelease.ErrorCode(err))
	}
	oneOverPayloadEnvelope, _ := externallySign(t, policyrelease.ActivationManifestPayloadType, append(exactPayload, 'p'), 1, false)
	if _, err := policyrelease.ParseDSSEEnvelope(oneOverPayloadEnvelope); policyrelease.ErrorCode(err) != "base64_decoded_limit" {
		t.Fatalf("one-over payload error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestDSSEDepthSignatureAndKeyBoundaries(t *testing.T) {
	if _, err := policyrelease.ParseDSSEEnvelope(nestedUnknownEnvelope(t, policyrelease.MaxJSONDepth-1)); err != nil {
		t.Fatalf("exact JSON depth rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	if _, err := policyrelease.ParseDSSEEnvelope(nestedUnknownEnvelope(t, policyrelease.MaxJSONDepth)); policyrelease.ErrorCode(err) != "json_depth_limit" {
		t.Fatalf("one-over depth error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	sixteen, _ := externallySign(t, policyrelease.ActivationManifestPayloadType, []byte("x"), policyrelease.MaxEnvelopeSignatures, false)
	if _, err := policyrelease.ParseDSSEEnvelope(sixteen); err != nil {
		t.Fatalf("exact signature count rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	signatures := make([]fixtureSignature, 0, policyrelease.MaxEnvelopeSignatures+1)
	for index := 0; index < policyrelease.MaxEnvelopeSignatures+1; index++ {
		signature, keyID := fixtureSign(policyrelease.ActivationManifestPayloadType, []byte("x"), index)
		signatures = append(signatures, fixtureSignature{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)})
	}
	seventeen, err := json.Marshal(fixtureEnvelope{PayloadType: policyrelease.ActivationManifestPayloadType, Payload: base64.StdEncoding.EncodeToString([]byte("x")), Signatures: signatures})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyrelease.ParseDSSEEnvelope(seventeen); policyrelease.ErrorCode(err) != "signature_count_limit" {
		t.Fatalf("one-over signatures error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	validSignature, validKeyID := fixtureSign(policyrelease.ActivationManifestPayloadType, []byte("x"), 0)
	raw := fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString([]byte("x")),
		Signatures:  []fixtureSignature{{KeyID: validKeyID, Sig: base64.StdEncoding.EncodeToString(validSignature)}},
	}
	raw.Signatures[0].KeyID = strings.Repeat("k", policyrelease.MaxKeyIDBytes+1)
	encoded, _ := json.Marshal(raw)
	if _, err := policyrelease.ParseDSSEEnvelope(encoded); policyrelease.ErrorCode(err) != "invalid_key_id" {
		t.Fatalf("one-over keyid error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	raw.Signatures[0].KeyID = validKeyID
	raw.Signatures[0].Sig = strings.Repeat("A", policyrelease.MaxEncodedSignatureBytes)
	encoded, _ = json.Marshal(raw)
	if _, err := policyrelease.ParseDSSEEnvelope(encoded); policyrelease.ErrorCode(err) == "encoded_signature_limit" {
		t.Fatalf("exact encoded signature ceiling rejected by encoded limit: %v", err)
	}
	raw.Signatures[0].Sig = strings.Repeat("A", policyrelease.MaxEncodedSignatureBytes+1)
	encoded, _ = json.Marshal(raw)
	if _, err := policyrelease.ParseDSSEEnvelope(encoded); policyrelease.ErrorCode(err) != "encoded_signature_limit" {
		t.Fatalf("one-over encoded signature error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
	raw.Signatures[0].Sig = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, policyrelease.MaxDecodedSignatureBytes))
	encoded, _ = json.Marshal(raw)
	if _, err := policyrelease.ParseDSSEEnvelope(encoded); policyrelease.ErrorCode(err) == "base64_decoded_limit" {
		t.Fatalf("exact decoded signature ceiling rejected by decoded limit: %v", err)
	}
	raw.Signatures[0].Sig = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, policyrelease.MaxDecodedSignatureBytes+1))
	encoded, _ = json.Marshal(raw)
	if _, err := policyrelease.ParseDSSEEnvelope(encoded); policyrelease.ErrorCode(err) != "base64_decoded_limit" {
		t.Fatalf("one-over decoded signature error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestDSSECanonicalBase64AndUnknownEnvelopeFields(t *testing.T) {
	payload := []byte{0xfb, 0xff, 0xef}
	signature, keyID := fixtureSign(policyrelease.ActivationManifestPayloadType, payload, 0)
	standard, _ := json.Marshal(fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []fixtureSignature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)}},
	})
	if _, err := policyrelease.ParseDSSEEnvelope(standard); err != nil {
		t.Fatalf("standard Base64: %v", err)
	}
	urlSafe, _ := json.Marshal(fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     base64.URLEncoding.EncodeToString(payload),
		Signatures:  []fixtureSignature{{KeyID: keyID, Sig: base64.URLEncoding.EncodeToString(signature)}},
	})
	if _, err := policyrelease.ParseDSSEEnvelope(urlSafe); err != nil {
		t.Fatalf("URL-safe Base64: %v", err)
	}
	unknown := withUnknownPadding(t, standard, len(standard)+32)
	if _, err := policyrelease.ParseDSSEEnvelope(unknown); err != nil {
		t.Fatalf("bounded unknown envelope field: %v", err)
	}
	caseFoldedRoot := bytes.Replace(standard, []byte(`"payloadType"`), []byte(`"PayloadType"`), 1)
	caseFoldedSignature := bytes.Replace(standard, []byte(`"keyid"`), []byte(`"KeyID"`), 1)
	exactAndAlias := append(append([]byte(nil), standard[:len(standard)-1]...), []byte(`,"PayloadType":"ignored"}`)...)
	for name, candidate := range map[string][]byte{
		"case-folded root member":      caseFoldedRoot,
		"case-folded signature member": caseFoldedSignature,
		"exact plus folded alias":      exactAndAlias,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policyrelease.ParseDSSEEnvelope(candidate); policyrelease.ErrorCode(err) != "json_member_name_mismatch" {
				t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
			}
		})
	}

	mixed, _ := json.Marshal(fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     "+_==",
		Signatures:  []fixtureSignature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)}},
	})
	unpadded, _ := json.Marshal(fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     "eA",
		Signatures:  []fixtureSignature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)}},
	})
	excessPadded, _ := json.Marshal(fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     "eA======",
		Signatures:  []fixtureSignature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)}},
	})
	badCases := []struct {
		name string
		raw  []byte
		code string
	}{
		{"mixed alphabet", mixed, "mixed_base64_alphabet"},
		{"unpadded", unpadded, "noncanonical_base64"},
		{"excess padded", excessPadded, "invalid_base64"},
		{"duplicate JSON key", []byte(`{"payloadType":"application/vnd.stead.policy-activation-manifest.v1+json","payloadType":"application/vnd.stead.policy-activation-manifest.v1+json","payload":"eA==","signatures":[{"keyid":"` + keyID + `","sig":"` + base64.StdEncoding.EncodeToString(signature) + `"}]}`), "duplicate_json_key"},
	}
	for _, testCase := range badCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := policyrelease.ParseDSSEEnvelope(testCase.raw)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestDSSERejectsHighSNonminimalDuplicateAndCrossType(t *testing.T) {
	payload := []byte("x")
	signature, keyID := fixtureSign(policyrelease.ActivationManifestPayloadType, payload, 0)
	var decoded fixtureECDSASignature
	if _, err := asn1.Unmarshal(signature, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.S.Sub(elliptic.P256().Params().N, decoded.S)
	highS, _ := asn1.Marshal(decoded)
	highEnvelope, _ := json.Marshal(fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []fixtureSignature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(highS)}},
	})
	if _, err := policyrelease.ParseDSSEEnvelope(highEnvelope); policyrelease.ErrorCode(err) != "high_s_signature" {
		t.Fatalf("high-S error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	duplicateEnvelope, _ := json.Marshal(fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []fixtureSignature{
			{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)},
			{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)},
		},
	})
	if _, err := policyrelease.ParseDSSEEnvelope(duplicateEnvelope); policyrelease.ErrorCode(err) != "duplicate_signature_key" {
		t.Fatalf("duplicate signature error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	crossType, signing := externallySign(t, policyrelease.ReleaseAttestationPayloadType, unsigned.ManifestPayload, 1, false)
	_, err = observedPolicyRelease.FinalizeActivationArchive(unsigned, crossType, signing)
	if policyrelease.ErrorCode(err) != "cross_type_dsse_substitution" {
		t.Fatalf("cross-type error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	// A deliberately non-minimal INTEGER encoding for r=1, s=1.
	nonminimal := []byte{0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01}
	nonminimalEnvelope, _ := json.Marshal(fixtureEnvelope{
		PayloadType: policyrelease.ActivationManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []fixtureSignature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(nonminimal)}},
	})
	if _, err := policyrelease.ParseDSSEEnvelope(nonminimalEnvelope); policyrelease.ErrorCode(err) != "invalid_ecdsa_der" && policyrelease.ErrorCode(err) != "nonminimal_ecdsa_der" {
		t.Fatalf("non-minimal DER error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestPAEFixedEncoding(t *testing.T) {
	got := policyrelease.PAE("text/plain", []byte("hello"))
	want := []byte("DSSEv1 10 text/plain 5 hello")
	if !bytes.Equal(got, want) {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
}
