package ci_test

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

type goldenKey struct {
	KeyID       string `json:"key_id"`
	SPKIBase64  string `json:"spki_base64"`
	CustodianID string `json:"custodian_id"`
	Purpose     string `json:"purpose"`
}

type goldenActivation struct {
	ManifestPayloadBase64  string `json:"manifest_payload_base64"`
	ActivationSetID        string `json:"activation_set_id"`
	PolicyBundleID         string `json:"policy_bundle_id"`
	EvidenceManifestDigest string `json:"evidence_manifest_digest"`
	PAEDigest              string `json:"pae_digest"`
	SignatureBase64        string `json:"signature_base64"`
	EnvelopeBase64         string `json:"envelope_base64"`
	EnvelopeDigest         string `json:"envelope_digest"`
	ArchiveBase64          string `json:"archive_base64"`
	ArchiveDigest          string `json:"archive_digest"`
	ArchiveBytes           int    `json:"archive_bytes"`
	SigningRequestDigest   string `json:"signing_request_digest"`
}

type goldenAttestation struct {
	PayloadBase64        string `json:"payload_base64"`
	AttestationID        string `json:"attestation_id"`
	PAEDigest            string `json:"pae_digest"`
	SignatureBase64      string `json:"signature_base64"`
	EnvelopeBase64       string `json:"envelope_base64"`
	EnvelopeDigest       string `json:"envelope_digest"`
	SigningRequestDigest string `json:"signing_request_digest"`
}

type goldenVector struct {
	SchemaVersion         string            `json:"schema_version"`
	FixtureClassification string            `json:"fixture_classification"`
	Authority             string            `json:"authority"`
	Keys                  []goldenKey       `json:"keys"`
	Activation            goldenActivation  `json:"activation"`
	Attestation           goldenAttestation `json:"attestation"`
}

func makeGoldenVector(t testing.TB) goldenVector {
	t.Helper()
	activation, attestation, handoff := completeFixtureRelease(t, "commercial", 1, false)
	activationEnvelope, err := policyrelease.ParseDSSEEnvelope(activation.EnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	releaseEnvelope, err := policyrelease.ParseDSSEEnvelope(handoff.ReleaseAttestationEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, keyID := testPublicKey(0)
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return goldenVector{
		SchemaVersion:         "1.0.0",
		FixtureClassification: "public-nonproduction-nonauthorizing-test-vector",
		Authority:             "none",
		Keys:                  []goldenKey{{KeyID: keyID, SPKIBase64: base64.StdEncoding.EncodeToString(spki), CustodianID: "fixture-custodian-a", Purpose: policyrelease.ReleaseKeyPurpose}},
		Activation: goldenActivation{
			ManifestPayloadBase64:  base64.StdEncoding.EncodeToString(activation.Unsigned.ManifestPayload),
			ActivationSetID:        activation.Unsigned.ActivationSetID,
			PolicyBundleID:         activation.Unsigned.PolicyBundleID,
			EvidenceManifestDigest: activation.Unsigned.EvidenceManifestDigest,
			PAEDigest:              policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ActivationManifestPayloadType, activation.Unsigned.ManifestPayload)),
			SignatureBase64:        base64.StdEncoding.EncodeToString(activationEnvelope.Signatures[0].Bytes),
			EnvelopeBase64:         base64.StdEncoding.EncodeToString(activation.EnvelopeBytes),
			EnvelopeDigest:         activation.SignedEnvelopeDigest,
			ArchiveBase64:          base64.StdEncoding.EncodeToString(activation.ArchiveBytes),
			ArchiveDigest:          activation.ArchiveDigest,
			ArchiveBytes:           len(activation.ArchiveBytes),
			SigningRequestDigest:   policyrelease.SHA256Digest(activation.Unsigned.SigningRequestBytes),
		},
		Attestation: goldenAttestation{
			PayloadBase64:        base64.StdEncoding.EncodeToString(attestation.PayloadBytes),
			AttestationID:        attestation.AttestationID,
			PAEDigest:            policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes)),
			SignatureBase64:      base64.StdEncoding.EncodeToString(releaseEnvelope.Signatures[0].Bytes),
			EnvelopeBase64:       base64.StdEncoding.EncodeToString(handoff.ReleaseAttestationEnvelopeBytes),
			EnvelopeDigest:       handoff.ReleaseAttestationEnvelopeDigest,
			SigningRequestDigest: policyrelease.SHA256Digest(attestation.SigningRequestBytes),
		},
	}
}

// T-ADR-0006-DETERMINISTIC-BUILD, T-ADR-0006-TRANSPORT-IDENTITY, and the
// independent offline fixed-vector handoff.
func TestGoldenOfflineVector(t *testing.T) {
	actual := makeGoldenVector(t)
	if os.Getenv("STEAD_PRINT_POLICY_GOLDEN") == "1" {
		encoded, err := json.MarshalIndent(actual, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(string(encoded))
		return
	}
	fixture := fixtureBytes(t, "vectors/golden-vector.json")
	var expected goldenVector
	if err := json.Unmarshal(fixture, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("golden policy release vector drifted: activation=%s archive=%s attestation=%s envelope=%s", actual.Activation.ActivationSetID, actual.Activation.ArchiveDigest, actual.Attestation.AttestationID, actual.Attestation.EnvelopeDigest)
	}
	verifyGoldenVector(t, expected)
}

func verifyGoldenVector(t *testing.T, vector goldenVector) {
	t.Helper()
	decode := func(field, value string) []byte {
		t.Helper()
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil {
			t.Fatalf("decode %s: %v", field, err)
		}
		return decoded
	}
	spki := decode("spki", vector.Keys[0].SPKIBase64)
	parsedKey, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("golden key is not ECDSA")
	}
	if policyrelease.SHA256Digest(spki) != vector.Keys[0].KeyID {
		t.Fatal("golden key identity mismatch")
	}
	activationPayload := decode("activation payload", vector.Activation.ManifestPayloadBase64)
	activationSignature := decode("activation signature", vector.Activation.SignatureBase64)
	activationDigest := sha256.Sum256(policyrelease.PAE(policyrelease.ActivationManifestPayloadType, activationPayload))
	if !ecdsa.VerifyASN1(publicKey, activationDigest[:], activationSignature) || policyrelease.SHA256Digest(activationPayload) != vector.Activation.ActivationSetID {
		t.Fatal("golden activation signature or identity failed")
	}
	activationEnvelope := decode("activation envelope", vector.Activation.EnvelopeBase64)
	archive := decode("activation archive", vector.Activation.ArchiveBase64)
	if policyrelease.SHA256Digest(activationEnvelope) != vector.Activation.EnvelopeDigest || policyrelease.SHA256Digest(archive) != vector.Activation.ArchiveDigest || len(archive) != vector.Activation.ArchiveBytes {
		t.Fatal("golden activation envelope/archive identity failed")
	}
	if _, err := policyrelease.InspectArchive(archive); err != nil {
		t.Fatalf("golden archive safety: %v", err)
	}
	archiveFiles := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != 0 {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		archiveFiles[header.Name] = content
	}
	if !bytes.Equal(archiveFiles["manifest.dsse.json"], activationEnvelope) {
		t.Fatal("golden archive does not contain exact activation envelope")
	}
	parsedActivationEnvelope, err := policyrelease.ParseDSSEEnvelope(activationEnvelope)
	if err != nil || !bytes.Equal(parsedActivationEnvelope.Payload, activationPayload) {
		t.Fatal("golden activation envelope payload mismatch")
	}
	trustPayload := archiveFiles["payload/trust-set.json"]
	trustEnvelope, err := policyrelease.ParseDSSEEnvelope(archiveFiles["payload/trust-set-envelope.json"])
	if err != nil || trustEnvelope.PayloadType != policyrelease.TrustSetPayloadType || !bytes.Equal(trustEnvelope.Payload, trustPayload) {
		t.Fatalf("golden trust envelope binding failed: %v", err)
	}
	trustDigest := sha256.Sum256(policyrelease.PAE(policyrelease.TrustSetPayloadType, trustPayload))
	if trustEnvelope.Signatures[0].KeyID != vector.Keys[0].KeyID || !ecdsa.VerifyASN1(publicKey, trustDigest[:], trustEnvelope.Signatures[0].Bytes) {
		t.Fatal("golden trust-set signature failed")
	}
	var trustDocument struct {
		Keys []struct {
			KeyID         string `json:"key_id"`
			SPKIDERBase64 string `json:"spki_der_base64"`
			CustodianID   string `json:"custodian_id"`
			Purpose       string `json:"purpose"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(trustPayload, &trustDocument); err != nil || len(trustDocument.Keys) != 1 {
		t.Fatalf("golden trust-set document: %v", err)
	}
	if trustDocument.Keys[0].KeyID != vector.Keys[0].KeyID || trustDocument.Keys[0].SPKIDERBase64 != vector.Keys[0].SPKIBase64 || trustDocument.Keys[0].CustodianID != vector.Keys[0].CustodianID || trustDocument.Keys[0].Purpose != vector.Keys[0].Purpose {
		t.Fatal("golden trust-set key/custodian/purpose binding failed")
	}
	attestationPayload := decode("attestation payload", vector.Attestation.PayloadBase64)
	attestationSignature := decode("attestation signature", vector.Attestation.SignatureBase64)
	attestationDigest := sha256.Sum256(policyrelease.PAE(policyrelease.ReleaseAttestationPayloadType, attestationPayload))
	if !ecdsa.VerifyASN1(publicKey, attestationDigest[:], attestationSignature) || policyrelease.SHA256Digest(attestationPayload) != vector.Attestation.AttestationID {
		t.Fatal("golden attestation signature or identity failed")
	}
	attestationEnvelope := decode("attestation envelope", vector.Attestation.EnvelopeBase64)
	if policyrelease.SHA256Digest(attestationEnvelope) != vector.Attestation.EnvelopeDigest {
		t.Fatal("golden attestation envelope identity failed")
	}
	parsedAttestationEnvelope, err := policyrelease.ParseDSSEEnvelope(attestationEnvelope)
	if err != nil || !bytes.Equal(parsedAttestationEnvelope.Payload, attestationPayload) {
		t.Fatal("golden attestation envelope payload mismatch")
	}
	var attestation policyrelease.ReleaseAttestationV1
	if err := json.Unmarshal(attestationPayload, &attestation); err != nil {
		t.Fatal(err)
	}
	if attestation.ActivationSetID != vector.Activation.ActivationSetID || attestation.SignedEnvelopeDigest != vector.Activation.EnvelopeDigest || attestation.ArchiveDigest != vector.Activation.ArchiveDigest || attestation.EvidenceManifestDigest != vector.Activation.EvidenceManifestDigest {
		t.Fatal("golden release attestation does not bind exact activation release")
	}
	if bytes.Contains(attestationPayload, []byte("release_attestation_id")) || bytes.Contains(attestationPayload, []byte("release_attestation_envelope_digest")) {
		t.Fatal("golden attestation is self-referential")
	}
}
