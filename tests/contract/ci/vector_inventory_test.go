package ci_test

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sort"
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
	Operation       string          `json:"operation"`
	Target          string          `json:"target"`
	DecodedTarget   string          `json:"decoded_target,omitempty"`
	ByteOffset      int             `json:"byte_offset,omitempty"`
	BitMask         int             `json:"bit_mask,omitempty"`
	Replacement     json.RawMessage `json:"replacement,omitempty"`
	ReplacementFile string          `json:"replacement_file,omitempty"`
}

type ws06CompositionBaseline struct {
	ReleaseVectorFile          string `json:"release_vector_file"`
	ConsumerEnvironmentFile    string `json:"consumer_environment_file"`
	SignatureThreshold         int    `json:"signature_threshold"`
	DistinctCustodiansRequired bool   `json:"distinct_custodians_required"`
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
		Baseline             ws06CompositionBaseline `json:"baseline"`
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

func archiveFileContents(t testing.TB, archive []byte) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
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
		files[header.Name] = content
	}
	return files
}

func ws06CompositionDocument(t testing.TB, baseline ws06CompositionBaseline) any {
	t.Helper()
	releaseBytes := fixtureBytes(t, baseline.ReleaseVectorFile)
	release := decodeFixtureJSON(t, releaseBytes)
	var vector goldenVector
	if err := json.Unmarshal(releaseBytes, &vector); err != nil {
		t.Fatal(err)
	}
	var manifest policyrelease.PolicyActivationManifestV1
	if err := json.Unmarshal(decodeWS06Base64(t, "composition activation payload", vector.Activation.ManifestPayloadBase64), &manifest); err != nil {
		t.Fatal(err)
	}
	archiveEncoded, err := jsonPointerValue(release, "/activation/archive_base64")
	if err != nil {
		t.Fatalf("baseline release archive: %v", err)
	}
	archive, err := base64.StdEncoding.Strict().DecodeString(archiveEncoded.(string))
	if err != nil {
		t.Fatal(err)
	}
	archiveFiles := archiveFileContents(t, archive)
	trustPayload, payloadPresent := archiveFiles[manifest.Trust.TrustSetPath]
	trustEnvelope, envelopePresent := archiveFiles[manifest.Trust.TrustSetEnvelopePath]
	if !payloadPresent || !envelopePresent {
		t.Fatal("baseline archive has no signed trust-set pair")
	}
	return map[string]any{
		"release": release,
		"trusted_release_policy": map[string]any{
			"payload_base64":            base64.StdEncoding.EncodeToString(trustPayload),
			"envelope_base64":           base64.StdEncoding.EncodeToString(trustEnvelope),
			"trust_set_id":              manifest.Trust.TrustSetID,
			"envelope_digest":           manifest.Trust.TrustSetEnvelopeDigest,
			"epoch":                     manifest.Trust.TrustEpoch,
			"deployment_policy_id":      manifest.DeploymentPolicy.PolicyID,
			"deployment_policy_version": manifest.DeploymentPolicy.Version,
			"deployment_policy_digest":  manifest.DeploymentPolicy.Digest,
		},
		"consumer_environment": decodeFixtureJSON(t, fixtureBytes(t, baseline.ConsumerEnvironmentFile)),
	}
}

func assertWS06MutationIsIsolated(t testing.TB, before, after any, target string) {
	t.Helper()
	beforeTarget, err := jsonPointerValue(before, target)
	if err != nil {
		t.Fatal(err)
	}
	encodedAfter, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	normalized := decodeFixtureJSON(t, encodedAfter)
	if err := setJSONPointer(&normalized, target, beforeTarget); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, normalized) {
		t.Fatalf("mutation changed data outside its isolated target %s", target)
	}
}

func ws06PublicFixtureScalar(t testing.TB, publicKey *ecdsa.PublicKey) *big.Int {
	t.Helper()
	for scalar := int64(1); scalar <= 32; scalar++ {
		x, y := publicKey.Curve.ScalarBaseMult(big.NewInt(scalar).Bytes())
		if x.Cmp(publicKey.X) == 0 && y.Cmp(publicKey.Y) == 0 {
			return big.NewInt(scalar)
		}
	}
	x, y := publicKey.Curve.ScalarBaseMult([]byte{1})
	fixtureKey := &ecdsa.PublicKey{Curve: publicKey.Curve, X: x, Y: y}
	spki, err := x509.MarshalPKIXPublicKey(fixtureKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("signed trust mutation references a non-public fixture key; scalar-one fixture is %s (%s)", base64.StdEncoding.EncodeToString(spki), policyrelease.SHA256Digest(spki))
	return nil
}

func ws06FixtureSignature(t testing.TB, payloadType string, payload []byte, publicKey *ecdsa.PublicKey) []byte {
	t.Helper()
	n := publicKey.Curve.Params().N
	d := ws06PublicFixtureScalar(t, publicKey)
	if publicKey.Curve == elliptic.P256() {
		signature, keyID := fixtureSign(payloadType, payload, int(d.Int64()-1))
		spki, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil || keyID != policyrelease.SHA256Digest(spki) {
			t.Fatal("P-256 fixture signer identity drifted")
		}
		return signature
	}
	digest := sha256.Sum256(policyrelease.PAE(payloadType, payload))
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	nonceInput := append([]byte("stead-public-ws06-trust-mutation-nonce-v1:"+policyrelease.SHA256Digest(spki)+":"), digest[:]...)
	nonceSeed := sha256.Sum256(nonceInput)
	k := new(big.Int).SetBytes(nonceSeed[:])
	k.Mod(k, new(big.Int).Sub(n, big.NewInt(1)))
	k.Add(k, big.NewInt(1))
	x, _ := publicKey.Curve.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(x, n)
	z := new(big.Int).SetBytes(digest[:])
	s := new(big.Int).Mul(r, d)
	s.Add(s, z)
	s.Mul(s, new(big.Int).ModInverse(k, n))
	s.Mod(s, n)
	halfN := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(n, s)
	}
	encoded, err := asn1.Marshal(fixtureECDSASignature{R: r, S: s})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func ws06PresentedSigning(t testing.TB, envelopeBytes []byte, distinctCustodians bool, firstReceipt map[string]any) (policyrelease.PresentedSigningResult, policyrelease.PresentedSignatureSummary) {
	t.Helper()
	var envelope fixtureEnvelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		t.Fatal(err)
	}
	receipts := make([]policyrelease.PresentedSignatureReceipt, 0, len(envelope.Signatures))
	keyIDs := make([]string, 0, len(envelope.Signatures))
	custodianSet := make(map[string]struct{}, len(envelope.Signatures))
	for index, signature := range envelope.Signatures {
		signatureBytes := decodeWS06Base64(t, "presented signature", signature.Sig)
		custodian := "fixture-custodian-" + string(rune('a'+index))
		purpose := policyrelease.ReleaseKeyPurpose
		if index == 0 && firstReceipt != nil {
			if value, ok := firstReceipt["claimed_custodian_id"].(string); ok {
				custodian = value
			}
			if value, ok := firstReceipt["claimed_key_purpose"].(string); ok {
				purpose = value
			}
			if want, ok := firstReceipt["signature_digest"].(string); !ok || want != policyrelease.SHA256Digest(signatureBytes) {
				t.Fatal("presented receipt does not bind its exact signature")
			}
		}
		receipts = append(receipts, policyrelease.PresentedSignatureReceipt{
			KeyIDHint:          signature.KeyID,
			ClaimedCustodianID: custodian,
			ClaimedKeyPurpose:  purpose,
			SignatureDigest:    policyrelease.SHA256Digest(signatureBytes),
		})
		keyIDs = append(keyIDs, signature.KeyID)
		custodianSet[custodian] = struct{}{}
	}
	result, err := policyrelease.NewPresentedSigningResult("external-fixture-signing-workflow-v1", receipts)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(keyIDs)
	custodians := make([]string, 0, len(custodianSet))
	for custodian := range custodianSet {
		custodians = append(custodians, custodian)
	}
	sort.Strings(custodians)
	return result, policyrelease.PresentedSignatureSummary{
		Treatment:                        policyrelease.PresentedMaterialTreatment,
		RequestedSignatureThreshold:      len(envelope.Signatures),
		PresentedDistinctKeyIDHints:      len(keyIDs),
		DistinctCustodianClaimsRequested: distinctCustodians,
		PresentedDistinctCustodianClaims: len(custodians),
		KeyIDHints:                       keyIDs,
		ClaimedCustodianIDs:              custodians,
	}
}

func signWS06Envelope(t testing.TB, payloadType string, payload []byte, trust ws06TrustSetDocument) ([]byte, policyrelease.PresentedSigningResult, policyrelease.PresentedSignatureSummary) {
	t.Helper()
	if trust.SignatureThreshold < 1 || len(trust.Keys) < trust.SignatureThreshold {
		t.Fatal("signed WS-06 material cannot satisfy its declared signature count")
	}
	signatures := make([]fixtureSignature, 0, trust.SignatureThreshold)
	for index := 0; index < trust.SignatureThreshold; index++ {
		spki := decodeWS06Base64(t, "mutated trust SPKI", trust.Keys[index].SPKIDERBase64)
		parsed, err := x509.ParsePKIXPublicKey(spki)
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || policyrelease.SHA256Digest(spki) != trust.Keys[index].KeyID {
			t.Fatal("signed trust mutation has an inconsistent SPKI identity")
		}
		signature := ws06FixtureSignature(t, payloadType, payload, publicKey)
		signatures = append(signatures, fixtureSignature{KeyID: trust.Keys[index].KeyID, Sig: base64.StdEncoding.EncodeToString(signature)})
	}
	envelope, err := json.Marshal(fixtureEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  signatures,
	})
	if err != nil {
		t.Fatal(err)
	}
	signing, summary := ws06PresentedSigning(t, envelope, true, nil)
	return envelope, signing, summary
}

func ws06SigningRequestDigest(t testing.TB, purpose, payloadType string, payload []byte, manifest policyrelease.PolicyActivationManifestV1) string {
	t.Helper()
	request := policyrelease.SigningRequestV1{
		SchemaVersion:              "1.0.0",
		Purpose:                    purpose,
		PayloadType:                payloadType,
		PayloadBase64:              base64.StdEncoding.EncodeToString(payload),
		PAEDigest:                  policyrelease.SHA256Digest(policyrelease.PAE(payloadType, payload)),
		KeyPurpose:                 policyrelease.ReleaseKeyPurpose,
		DeploymentPolicyID:         manifest.DeploymentPolicy.PolicyID,
		DeploymentPolicyVersion:    manifest.DeploymentPolicy.Version,
		DeploymentPolicyDigest:     manifest.DeploymentPolicy.Digest,
		RequiredSignatureThreshold: manifest.DeploymentPolicy.PolicySignatureThreshold,
		DistinctCustodiansRequired: manifest.DeploymentPolicy.DistinctSigningCustodians,
		SourceRevision:             manifest.SourceRevision,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return policyrelease.SHA256Digest(encoded)
}

func writeWS06Archive(t testing.TB, envelope []byte, files map[string][]byte) []byte {
	t.Helper()
	type entry struct {
		name      string
		directory bool
		content   []byte
	}
	entries := []entry{{name: "manifest.dsse.json", content: envelope}}
	directories := make(map[string]struct{})
	for path, content := range files {
		if path == "manifest.dsse.json" {
			continue
		}
		parts := strings.Split(path, "/")
		for index := 1; index < len(parts); index++ {
			directories[strings.Join(parts[:index], "/")+"/"] = struct{}{}
		}
		entries = append(entries, entry{name: path, content: content})
	}
	for directory := range directories {
		entries = append(entries, entry{name: directory, directory: true})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, item := range entries {
		header := &tar.Header{
			Name: item.name, Mode: 0o444, Uid: 0, Gid: 0, Size: int64(len(item.content)),
			ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if item.directory {
			header.Mode, header.Size, header.Typeflag = 0o555, 0, tar.TypeDir
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if !item.directory {
			if _, err := writer.Write(item.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buffer.Bytes()
	if _, err := policyrelease.InspectArchive(archive); err != nil {
		t.Fatalf("recomposed WS-06 archive: %v", err)
	}
	return archive
}

func updateWS06ManifestFile(t testing.TB, manifest *policyrelease.PolicyActivationManifestV1, path string, content []byte) {
	t.Helper()
	for index := range manifest.Files {
		if manifest.Files[index].Path == path {
			manifest.Files[index].Size = int64(len(content))
			manifest.Files[index].Digest = policyrelease.SHA256Digest(content)
			return
		}
	}
	t.Fatalf("manifest has no bound file %s", path)
}

func ws06TrustKeys(trust ws06TrustSetDocument) []goldenKey {
	keys := make([]goldenKey, 0, len(trust.Keys))
	for _, key := range trust.Keys {
		keys = append(keys, goldenKey{
			KeyID: key.KeyID, SPKIBase64: key.SPKIDERBase64,
			CustodianID: key.CustodianID, Purpose: key.Purpose,
		})
	}
	return keys
}

func ws06ReleaseVector(t testing.TB, document any) goldenVector {
	t.Helper()
	release, err := jsonPointerValue(document, "/release")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	var vector goldenVector
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func setWS06CompositionRelease(t testing.TB, document *any, vector goldenVector) {
	t.Helper()
	encoded, err := json.Marshal(vector)
	if err != nil {
		t.Fatal(err)
	}
	if err := setJSONPointer(document, "/release", decodeFixtureJSON(t, encoded)); err != nil {
		t.Fatal(err)
	}
	archive := decodeWS06Base64(t, "recomposed activation archive", vector.Activation.ArchiveBase64)
	files := archiveFileContents(t, archive)
	var manifest policyrelease.PolicyActivationManifestV1
	if err := json.Unmarshal(decodeWS06Base64(t, "recomposed activation payload", vector.Activation.ManifestPayloadBase64), &manifest); err != nil {
		t.Fatal(err)
	}
	trustPayload := files[manifest.Trust.TrustSetPath]
	trustEnvelope := files[manifest.Trust.TrustSetEnvelopePath]
	signedTrust := map[string]any{
		"payload_base64": base64.StdEncoding.EncodeToString(trustPayload), "envelope_base64": base64.StdEncoding.EncodeToString(trustEnvelope),
		"trust_set_id": manifest.Trust.TrustSetID, "envelope_digest": manifest.Trust.TrustSetEnvelopeDigest,
		"epoch":                json.Number(strconv.FormatUint(manifest.Trust.TrustEpoch, 10)),
		"deployment_policy_id": manifest.DeploymentPolicy.PolicyID, "deployment_policy_version": manifest.DeploymentPolicy.Version,
		"deployment_policy_digest": manifest.DeploymentPolicy.Digest,
	}
	if err := setJSONPointer(document, "/trusted_release_policy", signedTrust); err != nil {
		t.Fatal(err)
	}
}

func finishWS06ReleaseVector(t testing.TB, base goldenVector, manifest policyrelease.PolicyActivationManifestV1, manifestPayload, activationEnvelope, archive []byte, activationSigning policyrelease.PresentedSigningResult, activationSummary policyrelease.PresentedSignatureSummary, trust ws06TrustSetDocument) goldenVector {
	t.Helper()
	var parsedActivation fixtureEnvelope
	if err := json.Unmarshal(activationEnvelope, &parsedActivation); err != nil || len(parsedActivation.Signatures) == 0 {
		t.Fatalf("recomposed activation envelope: %v", err)
	}
	vector := base
	vector.Keys = ws06TrustKeys(trust)
	vector.Activation = goldenActivation{
		ManifestPayloadBase64:  base64.StdEncoding.EncodeToString(manifestPayload),
		ActivationSetID:        policyrelease.SHA256Digest(manifestPayload),
		PolicyBundleID:         manifest.PolicyBundleID,
		EvidenceManifestDigest: manifest.EvidenceManifestDigest,
		PAEDigest:              policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ActivationManifestPayloadType, manifestPayload)),
		SignatureBase64:        parsedActivation.Signatures[0].Sig,
		EnvelopeBase64:         base64.StdEncoding.EncodeToString(activationEnvelope),
		EnvelopeDigest:         policyrelease.SHA256Digest(activationEnvelope),
		ArchiveBase64:          base64.StdEncoding.EncodeToString(archive),
		ArchiveDigest:          policyrelease.SHA256Digest(archive),
		ArchiveBytes:           len(archive),
		SigningRequestDigest:   ws06SigningRequestDigest(t, "policy_activation_manifest", policyrelease.ActivationManifestPayloadType, manifestPayload, manifest),
	}

	var attestation policyrelease.ReleaseAttestationV1
	if err := json.Unmarshal(decodeWS06Base64(t, "base release attestation", base.Attestation.PayloadBase64), &attestation); err != nil {
		t.Fatal(err)
	}
	oldArchiveDigest := attestation.ArchiveDigest
	attestation.ActivationSetID = vector.Activation.ActivationSetID
	attestation.SignedEnvelopeDigest = vector.Activation.EnvelopeDigest
	attestation.ArchiveDigest = vector.Activation.ArchiveDigest
	attestation.EvidenceManifestDigest = vector.Activation.EvidenceManifestDigest
	attestation.PolicyBundleID = vector.Activation.PolicyBundleID
	attestation.Trust = manifest.Trust
	attestation.DeploymentPolicy = manifest.DeploymentPolicy
	attestation.PresentedActivationWorkflowIdentity = activationSigning.WorkflowIdentity
	attestation.PresentedActivationReceiptSetDigest = activationSigning.ReceiptSetDigest
	attestation.PresentedActivationSignatures = activationSummary
	for index := range attestation.PresentedReviewReceipts {
		if attestation.PresentedReviewReceipts[index].SubjectDigest == oldArchiveDigest {
			attestation.PresentedReviewReceipts[index].SubjectDigest = vector.Activation.ArchiveDigest
		}
	}
	if attestation.PresentedOfflineCheck.SubjectArchiveDigest == oldArchiveDigest {
		attestation.PresentedOfflineCheck.SubjectArchiveDigest = vector.Activation.ArchiveDigest
	}
	attestationPayload, err := json.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}
	attestationEnvelope, _, _ := signWS06Envelope(t, policyrelease.ReleaseAttestationPayloadType, attestationPayload, trust)
	var parsedAttestation fixtureEnvelope
	if err := json.Unmarshal(attestationEnvelope, &parsedAttestation); err != nil || len(parsedAttestation.Signatures) == 0 {
		t.Fatalf("recomposed release-attestation envelope: %v", err)
	}
	vector.Attestation = goldenAttestation{
		PayloadBase64:        base64.StdEncoding.EncodeToString(attestationPayload),
		AttestationID:        policyrelease.SHA256Digest(attestationPayload),
		PAEDigest:            policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ReleaseAttestationPayloadType, attestationPayload)),
		SignatureBase64:      parsedAttestation.Signatures[0].Sig,
		EnvelopeBase64:       base64.StdEncoding.EncodeToString(attestationEnvelope),
		EnvelopeDigest:       policyrelease.SHA256Digest(attestationEnvelope),
		SigningRequestDigest: ws06SigningRequestDigest(t, "policy_release_attestation", policyrelease.ReleaseAttestationPayloadType, attestationPayload, manifest),
	}
	return vector
}

func recomposeWS06ReleaseForTrust(t testing.TB, base goldenVector, trust ws06TrustSetDocument) goldenVector {
	t.Helper()
	manifestPayload := decodeWS06Base64(t, "base activation manifest", base.Activation.ManifestPayloadBase64)
	var manifest policyrelease.PolicyActivationManifestV1
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	archive := decodeWS06Base64(t, "base activation archive", base.Activation.ArchiveBase64)
	files := archiveFileContents(t, archive)
	trustPayload, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	trustEnvelope, _, _ := signWS06Envelope(t, policyrelease.TrustSetPayloadType, trustPayload, trust)
	files[manifest.Trust.TrustSetPath] = trustPayload
	files[manifest.Trust.TrustSetEnvelopePath] = trustEnvelope
	manifest.Trust.TrustSetID = policyrelease.SHA256Digest(trustPayload)
	manifest.Trust.TrustSetEnvelopeDigest = policyrelease.SHA256Digest(trustEnvelope)
	manifest.Trust.TrustEpoch = trust.Epoch

	evidencePath := ""
	for _, file := range manifest.Files {
		if file.Digest == manifest.EvidenceManifestDigest {
			evidencePath = file.Path
			break
		}
	}
	if evidencePath == "" {
		t.Fatal("activation manifest has no bound pre-signing evidence manifest")
	}
	var evidence policyrelease.PreSigningEvidenceManifestV1
	if err := json.Unmarshal(files[evidencePath], &evidence); err != nil {
		t.Fatal(err)
	}
	evidence.Trust = manifest.Trust
	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	files[evidencePath] = evidenceBytes
	manifest.EvidenceManifestDigest = policyrelease.SHA256Digest(evidenceBytes)
	updateWS06ManifestFile(t, &manifest, manifest.Trust.TrustSetPath, trustPayload)
	updateWS06ManifestFile(t, &manifest, manifest.Trust.TrustSetEnvelopePath, trustEnvelope)
	updateWS06ManifestFile(t, &manifest, evidencePath, evidenceBytes)
	manifestPayload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	activationEnvelope, activationSigning, activationSummary := signWS06Envelope(t, policyrelease.ActivationManifestPayloadType, manifestPayload, trust)
	archive = writeWS06Archive(t, activationEnvelope, files)
	return finishWS06ReleaseVector(t, base, manifest, manifestPayload, activationEnvelope, archive, activationSigning, activationSummary, trust)
}

func rebindWS06ActivationTransport(t testing.TB, document *any) {
	t.Helper()
	vector := ws06ReleaseVector(t, *document)
	manifestPayload := decodeWS06Base64(t, "activation manifest", vector.Activation.ManifestPayloadBase64)
	var manifest policyrelease.PolicyActivationManifestV1
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	activationEnvelope := decodeWS06Base64(t, "mutated activation envelope", vector.Activation.EnvelopeBase64)
	archiveFiles := archiveFileContents(t, decodeWS06Base64(t, "activation archive", vector.Activation.ArchiveBase64))
	archive := writeWS06Archive(t, activationEnvelope, archiveFiles)
	var trust ws06TrustSetDocument
	if err := json.Unmarshal(archiveFiles[manifest.Trust.TrustSetPath], &trust); err != nil {
		t.Fatal(err)
	}
	activationMap, err := jsonPointerValue(*document, "/release/activation")
	if err != nil {
		t.Fatal(err)
	}
	var presentedReceipt map[string]any
	if receipt, present := activationMap.(map[string]any)["presented_receipt"]; present {
		presentedReceipt, _ = receipt.(map[string]any)
	}
	activationSigning, activationSummary := ws06PresentedSigning(t, activationEnvelope, manifest.DeploymentPolicy.DistinctSigningCustodians, presentedReceipt)
	vector = finishWS06ReleaseVector(t, vector, manifest, manifestPayload, activationEnvelope, archive, activationSigning, activationSummary, trust)
	setWS06CompositionRelease(t, document, vector)
	if presentedReceipt != nil {
		activation, err := jsonPointerValue(*document, "/release/activation")
		if err != nil {
			t.Fatal(err)
		}
		activation.(map[string]any)["presented_receipt"] = presentedReceipt
	}
}

func rebindWS06AttestationTransport(t testing.TB, document *any) {
	t.Helper()
	vector := ws06ReleaseVector(t, *document)
	envelopeBytes := decodeWS06Base64(t, "mutated release-attestation envelope", vector.Attestation.EnvelopeBase64)
	envelope, err := policyrelease.ParseDSSEEnvelope(envelopeBytes)
	if err != nil || len(envelope.Signatures) == 0 {
		t.Fatalf("mutated release-attestation envelope: %v", err)
	}
	vector.Attestation.SignatureBase64 = base64.StdEncoding.EncodeToString(envelope.Signatures[0].Bytes)
	vector.Attestation.EnvelopeDigest = policyrelease.SHA256Digest(envelopeBytes)
	setWS06CompositionRelease(t, document, vector)
}

func mutateWS06SignedTrust(t testing.TB, document *any, mutation ws06MutationInstruction) {
	t.Helper()
	target, err := jsonPointerValue(*document, mutation.Target)
	if err != nil {
		t.Fatal(err)
	}
	signedTrust, ok := target.(map[string]any)
	if !ok {
		t.Fatal("signed trust mutation target is not an object")
	}
	payload := decodeWS06Base64(t, "signed trust payload", signedTrust["payload_base64"].(string))
	trustDocument := decodeFixtureJSON(t, payload)
	beforeBytes, err := json.Marshal(trustDocument)
	if err != nil {
		t.Fatal(err)
	}
	beforeTrust := decodeFixtureJSON(t, beforeBytes)
	switch mutation.Operation {
	case "replace_signed_trust_value":
		if err := setJSONPointer(&trustDocument, mutation.DecodedTarget, replacementJSON(t, mutation.Replacement)); err != nil {
			t.Fatal(err)
		}
	case "merge_signed_trust_key_from_file":
		key, err := jsonPointerValue(trustDocument, mutation.DecodedTarget)
		if err != nil {
			t.Fatal(err)
		}
		keyObject, keyOK := key.(map[string]any)
		replacement, replacementOK := replacementFileJSON(t, mutation).(map[string]any)
		if !keyOK || !replacementOK {
			t.Fatal("signed trust key merge requires objects")
		}
		for name, value := range replacement {
			keyObject[name] = value
		}
	case "append_signed_trust_key_from_file":
		keys, err := jsonPointerValue(trustDocument, mutation.DecodedTarget)
		if err != nil {
			t.Fatal(err)
		}
		keyList, ok := keys.([]any)
		if !ok {
			t.Fatal("signed trust append target is not an array")
		}
		keyList = append(keyList, replacementFileJSON(t, mutation))
		if err := setJSONPointer(&trustDocument, mutation.DecodedTarget, keyList); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported signed trust mutation %q", mutation.Operation)
	}
	normalizedBytes, err := json.Marshal(trustDocument)
	if err != nil {
		t.Fatal(err)
	}
	normalized := decodeFixtureJSON(t, normalizedBytes)
	switch mutation.Operation {
	case "replace_signed_trust_value", "merge_signed_trust_key_from_file":
		beforeTarget, err := jsonPointerValue(beforeTrust, mutation.DecodedTarget)
		if err != nil {
			t.Fatal(err)
		}
		if err := setJSONPointer(&normalized, mutation.DecodedTarget, beforeTarget); err != nil {
			t.Fatal(err)
		}
	case "append_signed_trust_key_from_file":
		beforeKeys, err := jsonPointerValue(beforeTrust, mutation.DecodedTarget)
		if err != nil {
			t.Fatal(err)
		}
		if err := setJSONPointer(&normalized, mutation.DecodedTarget, beforeKeys); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(normalized, beforeTrust) {
		t.Fatalf("signed trust mutation %s changed more than its declared semantic target", mutation.Operation)
	}
	mutatedPayload, err := json.Marshal(trustDocument)
	if err != nil {
		t.Fatal(err)
	}
	var trust ws06TrustSetDocument
	if err := json.Unmarshal(mutatedPayload, &trust); err != nil {
		t.Fatal(err)
	}
	base := ws06ReleaseVector(t, *document)
	var baselineTrust ws06TrustSetDocument
	if err := json.Unmarshal(payload, &baselineTrust); err != nil {
		t.Fatal(err)
	}
	if roundTrip := recomposeWS06ReleaseForTrust(t, base, baselineTrust); !reflect.DeepEqual(roundTrip, base) {
		t.Fatalf("canonical WS-06 release does not round-trip through the trust recomposition materializer: activation=%s/%s archive=%s/%s attestation=%s/%s envelope=%s/%s", roundTrip.Activation.ActivationSetID, base.Activation.ActivationSetID, roundTrip.Activation.ArchiveDigest, base.Activation.ArchiveDigest, roundTrip.Attestation.AttestationID, base.Attestation.AttestationID, roundTrip.Attestation.EnvelopeDigest, base.Attestation.EnvelopeDigest)
	}
	setWS06CompositionRelease(t, document, recomposeWS06ReleaseForTrust(t, base, trust))
}

func materializeWS06Mutation(t testing.TB, baseline ws06CompositionBaseline, mutation ws06MutationInstruction) []byte {
	t.Helper()
	document := ws06CompositionDocument(t, baseline)
	beforeBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	before := decodeFixtureJSON(t, beforeBytes)
	switch mutation.Operation {
	case "replace_signed_trust_value", "merge_signed_trust_key_from_file", "append_signed_trust_key_from_file":
		mutateWS06SignedTrust(t, &document, mutation)
	case "replace_value":
		if err := setJSONPointer(&document, mutation.Target, replacementJSON(t, mutation.Replacement)); err != nil {
			t.Fatal(err)
		}
	case "flip_base64_bit":
		value, err := jsonPointerValue(document, mutation.Target)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(value.(string))
		if err != nil || mutation.ByteOffset < 0 || mutation.ByteOffset >= len(decoded) || mutation.BitMask < 1 || mutation.BitMask > 255 {
			t.Fatal("invalid Base64 bit mutation")
		}
		decoded[mutation.ByteOffset] ^= byte(mutation.BitMask)
		if err := setJSONPointer(&document, mutation.Target, base64.StdEncoding.EncodeToString(decoded)); err != nil {
			t.Fatal(err)
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
			if err := setJSONPointer(nested, "/signatures/0/sig", replacement["signature_base64"]); err != nil {
				t.Fatal(err)
			}
		})
		activation, err := jsonPointerValue(document, "/release/activation")
		if err != nil {
			t.Fatal(err)
		}
		activation.(map[string]any)["presented_receipt"] = replacement["presented_receipt"]
	default:
		t.Fatalf("unsupported mutation operation %q", mutation.Operation)
	}
	activationEnvelopeMutation := mutation.Target == "/release/activation/envelope_base64" &&
		(mutation.Operation == "flip_nested_base64_bit" || mutation.Operation == "replace_base64_json_value" || mutation.Operation == "replace_signature_and_add_receipt")
	releaseEnvelopeSignatureMutation := mutation.Target == "/release/attestation/envelope_base64" && mutation.Operation == "flip_nested_base64_bit"
	if activationEnvelopeMutation {
		rebindWS06ActivationTransport(t, &document)
	}
	if releaseEnvelopeSignatureMutation {
		rebindWS06AttestationTransport(t, &document)
	}
	after, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(beforeBytes, after) {
		t.Fatal("mutation resolved but did not change its target")
	}
	derivedMutation := activationEnvelopeMutation || releaseEnvelopeSignatureMutation || strings.Contains(mutation.Operation, "signed_trust")
	if derivedMutation {
		beforeEnvironment, beforeErr := jsonPointerValue(before, "/consumer_environment")
		afterEnvironment, afterErr := jsonPointerValue(document, "/consumer_environment")
		if beforeErr != nil || afterErr != nil || !reflect.DeepEqual(beforeEnvironment, afterEnvironment) {
			t.Fatal("derived mutation changed the consumer environment")
		}
	} else {
		assertWS06MutationIsIsolated(t, before, document, mutation.Target)
	}
	return after
}

type ws06TrustSetDocument struct {
	DeploymentPolicyDigest  string `json:"deployment_policy_digest"`
	DeploymentPolicyID      string `json:"deployment_policy_id"`
	DeploymentPolicyVersion string `json:"deployment_policy_version"`
	Epoch                   uint64 `json:"epoch"`
	Keys                    []struct {
		CustodianID   string `json:"custodian_id"`
		KeyID         string `json:"key_id"`
		NotAfter      string `json:"not_after"`
		NotBefore     string `json:"not_before"`
		Purpose       string `json:"purpose"`
		SPKIDERBase64 string `json:"spki_der_base64"`
		Status        string `json:"status"`
	} `json:"keys"`
	PreviousTrustSetID   *string `json:"previous_trust_set_id"`
	RecoveryKeyReference string  `json:"recovery_key_reference"`
	SchemaVersion        string  `json:"schema_version"`
	SignatureThreshold   int     `json:"signature_threshold"`
}

func decodeWS06Base64(t testing.TB, field, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	return decoded
}

func exactWS06Time(t testing.TB, field, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value || parsed.Location() != time.UTC {
		t.Fatalf("%s is not canonical UTC second precision: %q", field, value)
	}
	return parsed
}

func verifyWS06EnvelopeThreshold(t testing.TB, field string, envelopeBytes, payload []byte, payloadType string, keys map[string]*ecdsa.PublicKey, custodians map[string]string, threshold int, requireDistinct bool) {
	t.Helper()
	envelope, err := policyrelease.ParseDSSEEnvelope(envelopeBytes)
	if err != nil {
		t.Fatalf("%s parse: %v", field, err)
	}
	if envelope.PayloadType != payloadType || !bytes.Equal(envelope.Payload, payload) || len(envelope.Signatures) != threshold {
		t.Fatalf("%s payload or threshold binding failed", field)
	}
	digest := sha256.Sum256(policyrelease.PAE(payloadType, payload))
	seenKeys := make(map[string]struct{}, threshold)
	seenCustodians := make(map[string]struct{}, threshold)
	for _, signature := range envelope.Signatures {
		publicKey, present := keys[signature.KeyID]
		if !present || !ecdsa.VerifyASN1(publicKey, digest[:], signature.Bytes) {
			t.Fatalf("%s has an invalid or unknown signature", field)
		}
		if _, duplicate := seenKeys[signature.KeyID]; duplicate {
			t.Fatalf("%s repeats a key identity", field)
		}
		seenKeys[signature.KeyID] = struct{}{}
		seenCustodians[custodians[signature.KeyID]] = struct{}{}
	}
	if len(seenKeys) < threshold || (requireDistinct && len(seenCustodians) < threshold) {
		t.Fatalf("%s did not independently satisfy key and custodian threshold", field)
	}
}

func validateWS06CompositionBaseline(t testing.TB, baseline ws06CompositionBaseline, verificationTime time.Time) {
	t.Helper()
	if baseline.ReleaseVectorFile == "" || baseline.ConsumerEnvironmentFile == "" || baseline.SignatureThreshold < 1 {
		t.Fatal("consumer case does not name a closed composition baseline")
	}
	var environment struct {
		NetworkEnabled   bool   `json:"network_enabled"`
		VerificationMode string `json:"verification_mode"`
	}
	if err := json.Unmarshal(fixtureBytes(t, baseline.ConsumerEnvironmentFile), &environment); err != nil || !environment.NetworkEnabled || environment.VerificationMode != "offline" {
		t.Fatal("composition baseline environment is not the canonical offline input")
	}
	var vector goldenVector
	if err := json.Unmarshal(fixtureBytes(t, baseline.ReleaseVectorFile), &vector); err != nil {
		t.Fatal(err)
	}
	if vector.SchemaVersion != "1.0.0" || vector.FixtureClassification != "public-nonproduction-nonauthorizing-test-vector" || vector.Authority != "none" || len(vector.Keys) != baseline.SignatureThreshold {
		t.Fatal("release baseline is not canonical, nonauthorizing, or threshold-complete")
	}
	publicKeys := make(map[string]*ecdsa.PublicKey, len(vector.Keys))
	custodians := make(map[string]string, len(vector.Keys))
	spkiIDs := make(map[string]struct{}, len(vector.Keys))
	custodianIDs := make(map[string]struct{}, len(vector.Keys))
	for _, key := range vector.Keys {
		spki := decodeWS06Base64(t, "release key SPKI", key.SPKIBase64)
		parsed, err := x509.ParsePKIXPublicKey(spki)
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || publicKey.Curve != elliptic.P256() || policyrelease.SHA256Digest(spki) != key.KeyID || key.Purpose != policyrelease.ReleaseKeyPurpose {
			t.Fatal("release baseline key is not a P-256 SPKI-derived release-policy identity")
		}
		if _, duplicate := spkiIDs[key.KeyID]; duplicate {
			t.Fatal("release baseline repeats an SPKI-derived key identity")
		}
		spkiIDs[key.KeyID] = struct{}{}
		if _, duplicate := custodianIDs[key.CustodianID]; duplicate && baseline.DistinctCustodiansRequired {
			t.Fatal("release baseline repeats a required distinct custodian")
		}
		custodianIDs[key.CustodianID] = struct{}{}
		publicKeys[key.KeyID] = publicKey
		custodians[key.KeyID] = key.CustodianID
	}

	activationPayload := decodeWS06Base64(t, "activation payload", vector.Activation.ManifestPayloadBase64)
	activationEnvelope := decodeWS06Base64(t, "activation envelope", vector.Activation.EnvelopeBase64)
	archive := decodeWS06Base64(t, "activation archive", vector.Activation.ArchiveBase64)
	if policyrelease.SHA256Digest(activationPayload) != vector.Activation.ActivationSetID ||
		policyrelease.SHA256Digest(activationEnvelope) != vector.Activation.EnvelopeDigest ||
		policyrelease.SHA256Digest(archive) != vector.Activation.ArchiveDigest || len(archive) != vector.Activation.ArchiveBytes ||
		policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ActivationManifestPayloadType, activationPayload)) != vector.Activation.PAEDigest {
		t.Fatal("activation payload, envelope, or archive identity mismatch")
	}
	verifyWS06EnvelopeThreshold(t, "activation envelope", activationEnvelope, activationPayload, policyrelease.ActivationManifestPayloadType, publicKeys, custodians, baseline.SignatureThreshold, baseline.DistinctCustodiansRequired)
	parsedActivationEnvelope, err := policyrelease.ParseDSSEEnvelope(activationEnvelope)
	if err != nil || base64.StdEncoding.EncodeToString(parsedActivationEnvelope.Signatures[0].Bytes) != vector.Activation.SignatureBase64 {
		t.Fatal("activation signature field does not name the exact envelope signature")
	}
	var manifest policyrelease.PolicyActivationManifestV1
	if err := json.Unmarshal(activationPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	issuedAt := exactWS06Time(t, "activation issued_at", manifest.IssuedAt)
	expiresAt := exactWS06Time(t, "activation expires_at", manifest.ExpiresAt)
	if verificationTime.Before(issuedAt) || !verificationTime.Before(expiresAt) ||
		manifest.PolicyBundleID != vector.Activation.PolicyBundleID || manifest.EvidenceManifestDigest != vector.Activation.EvidenceManifestDigest ||
		manifest.DeploymentPolicy.PolicySignatureThreshold != baseline.SignatureThreshold || manifest.DeploymentPolicy.DistinctSigningCustodians != baseline.DistinctCustodiansRequired {
		t.Fatal("activation policy or pinned-time binding failed")
	}
	if _, err := policyrelease.InspectArchive(archive); err != nil {
		t.Fatalf("baseline archive safety: %v", err)
	}
	archiveFiles := archiveFileContents(t, archive)
	if !bytes.Equal(archiveFiles["manifest.dsse.json"], activationEnvelope) || len(manifest.Files) != len(archiveFiles)-1 {
		t.Fatal("archive does not contain the exact activation envelope and manifest file set")
	}
	for _, file := range manifest.Files {
		content, present := archiveFiles[file.Path]
		if !present || int64(len(content)) != file.Size || policyrelease.SHA256Digest(content) != file.Digest {
			t.Fatalf("archive file binding failed for %s", file.Path)
		}
	}
	policyBytes := archiveFiles[manifest.DeploymentPolicy.Path]
	if policyrelease.SHA256Digest(policyBytes) != manifest.DeploymentPolicy.Digest {
		t.Fatal("deployment policy content binding failed")
	}
	var deploymentPolicy struct {
		DomainID  string `json:"domain_id"`
		Version   string `json:"version"`
		Assurance struct {
			PolicySignatureThreshold  int  `json:"policy_signature_threshold"`
			DistinctSigningCustodians bool `json:"distinct_signing_custodians"`
		} `json:"assurance"`
	}
	if err := json.Unmarshal(policyBytes, &deploymentPolicy); err != nil || deploymentPolicy.DomainID != manifest.DeploymentPolicy.PolicyID || deploymentPolicy.Version != manifest.DeploymentPolicy.Version || deploymentPolicy.Assurance.PolicySignatureThreshold != baseline.SignatureThreshold || deploymentPolicy.Assurance.DistinctSigningCustodians != baseline.DistinctCustodiansRequired {
		t.Fatal("deployment policy content does not declare its exact threshold/custody binding")
	}

	trustPayload := archiveFiles[manifest.Trust.TrustSetPath]
	trustEnvelope := archiveFiles[manifest.Trust.TrustSetEnvelopePath]
	if policyrelease.SHA256Digest(trustPayload) != manifest.Trust.TrustSetID || policyrelease.SHA256Digest(trustEnvelope) != manifest.Trust.TrustSetEnvelopeDigest {
		t.Fatal("signed trust payload or envelope identity failed")
	}
	var trust ws06TrustSetDocument
	if err := json.Unmarshal(trustPayload, &trust); err != nil {
		t.Fatal(err)
	}
	if trust.SchemaVersion != "1.0.0" || trust.Epoch != manifest.Trust.TrustEpoch || trust.SignatureThreshold != baseline.SignatureThreshold ||
		trust.DeploymentPolicyID != manifest.DeploymentPolicy.PolicyID || trust.DeploymentPolicyVersion != manifest.DeploymentPolicy.Version || trust.DeploymentPolicyDigest != manifest.DeploymentPolicy.Digest || len(trust.Keys) != len(vector.Keys) {
		t.Fatal("trust epoch, threshold, or deployment-policy binding failed")
	}
	for index, key := range trust.Keys {
		notBefore := exactWS06Time(t, "trust key not_before", key.NotBefore)
		notAfter := exactWS06Time(t, "trust key not_after", key.NotAfter)
		if verificationTime.Before(notBefore) || !verificationTime.Before(notAfter) || key.Status != "active" || key.Purpose != policyrelease.ReleaseKeyPurpose ||
			key.KeyID != vector.Keys[index].KeyID || key.SPKIDERBase64 != vector.Keys[index].SPKIBase64 || key.CustodianID != vector.Keys[index].CustodianID {
			t.Fatal("trust key is not active, in interval, purpose-bound, or identical to its release key")
		}
	}
	verifyWS06EnvelopeThreshold(t, "trust envelope", trustEnvelope, trustPayload, policyrelease.TrustSetPayloadType, publicKeys, custodians, baseline.SignatureThreshold, baseline.DistinctCustodiansRequired)

	attestationPayload := decodeWS06Base64(t, "release attestation payload", vector.Attestation.PayloadBase64)
	attestationEnvelope := decodeWS06Base64(t, "release attestation envelope", vector.Attestation.EnvelopeBase64)
	if policyrelease.SHA256Digest(attestationPayload) != vector.Attestation.AttestationID || policyrelease.SHA256Digest(attestationEnvelope) != vector.Attestation.EnvelopeDigest ||
		policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ReleaseAttestationPayloadType, attestationPayload)) != vector.Attestation.PAEDigest {
		t.Fatal("release attestation payload or envelope identity mismatch")
	}
	verifyWS06EnvelopeThreshold(t, "release attestation envelope", attestationEnvelope, attestationPayload, policyrelease.ReleaseAttestationPayloadType, publicKeys, custodians, baseline.SignatureThreshold, baseline.DistinctCustodiansRequired)
	parsedAttestationEnvelope, err := policyrelease.ParseDSSEEnvelope(attestationEnvelope)
	if err != nil || base64.StdEncoding.EncodeToString(parsedAttestationEnvelope.Signatures[0].Bytes) != vector.Attestation.SignatureBase64 {
		t.Fatal("release attestation signature field does not name the exact envelope signature")
	}
	var attestation policyrelease.ReleaseAttestationV1
	if err := json.Unmarshal(attestationPayload, &attestation); err != nil {
		t.Fatal(err)
	}
	if attestation.Authority != "none" || attestation.ActivationSetID != vector.Activation.ActivationSetID ||
		attestation.SignedEnvelopeDigest != vector.Activation.EnvelopeDigest || attestation.ArchiveDigest != vector.Activation.ArchiveDigest ||
		attestation.EvidenceManifestDigest != vector.Activation.EvidenceManifestDigest || attestation.PolicyBundleID != vector.Activation.PolicyBundleID ||
		!reflect.DeepEqual(attestation.Trust, manifest.Trust) || !reflect.DeepEqual(attestation.DeploymentPolicy, manifest.DeploymentPolicy) {
		t.Fatal("archive and release-attestation immutable pair binding failed")
	}
}

func materializedWS06TrustDocument(t testing.TB, materialized []byte) (map[string]any, ws06TrustSetDocument) {
	t.Helper()
	composition := decodeFixtureJSON(t, materialized).(map[string]any)
	signedTrust := composition["trusted_release_policy"].(map[string]any)
	payload := decodeWS06Base64(t, "materialized trust payload", signedTrust["payload_base64"].(string))
	envelopeBytes := decodeWS06Base64(t, "materialized trust envelope", signedTrust["envelope_base64"].(string))
	if signedTrust["trust_set_id"] != policyrelease.SHA256Digest(payload) || signedTrust["envelope_digest"] != policyrelease.SHA256Digest(envelopeBytes) {
		t.Fatal("materialized signed trust identity is stale")
	}
	var trust ws06TrustSetDocument
	if err := json.Unmarshal(payload, &trust); err != nil {
		t.Fatal(err)
	}
	if signedTrust["epoch"] != json.Number(strconv.FormatUint(trust.Epoch, 10)) || signedTrust["deployment_policy_id"] != trust.DeploymentPolicyID ||
		signedTrust["deployment_policy_version"] != trust.DeploymentPolicyVersion || signedTrust["deployment_policy_digest"] != trust.DeploymentPolicyDigest {
		t.Fatal("materialized signed trust epoch or deployment-policy binding is stale")
	}
	keys := make(map[string]*ecdsa.PublicKey, trust.SignatureThreshold)
	for index := 0; index < trust.SignatureThreshold; index++ {
		key := trust.Keys[index]
		spki := decodeWS06Base64(t, "materialized trust key", key.SPKIDERBase64)
		parsed, err := x509.ParsePKIXPublicKey(spki)
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || policyrelease.SHA256Digest(spki) != key.KeyID {
			t.Fatal("materialized signed trust has an inconsistent key identity")
		}
		keys[key.KeyID] = publicKey
	}
	var envelope fixtureEnvelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil || envelope.PayloadType != policyrelease.TrustSetPayloadType || envelope.Payload != base64.StdEncoding.EncodeToString(payload) || len(envelope.Signatures) != trust.SignatureThreshold {
		t.Fatal("materialized signed trust envelope shape or payload binding failed")
	}
	digest := sha256.Sum256(policyrelease.PAE(policyrelease.TrustSetPayloadType, payload))
	seen := make(map[string]struct{}, trust.SignatureThreshold)
	for _, signature := range envelope.Signatures {
		publicKey, present := keys[signature.KeyID]
		signatureBytes := decodeWS06Base64(t, "materialized trust signature", signature.Sig)
		if !present || !ecdsa.VerifyASN1(publicKey, digest[:], signatureBytes) {
			t.Fatal("materialized signed trust signature failed")
		}
		if _, duplicate := seen[signature.KeyID]; duplicate {
			t.Fatal("materialized signed trust repeats a signing key")
		}
		seen[signature.KeyID] = struct{}{}
	}
	return signedTrust, trust
}

type ws06SignatureInvariant struct {
	Valid                int
	UnknownKey           int
	MismatchedHintCrypto int
	DistinctCustodians   int
}

// checkWS06MaterializedSignatures proves only that the mutation materializer
// preserved non-target cryptographic relationships. It is not the WS-06
// consumer verifier and never maps a condition to an authorization outcome.
func checkWS06MaterializedSignatures(t testing.TB, field string, envelopeBytes, payload []byte, payloadType string, trust ws06TrustSetDocument) ws06SignatureInvariant {
	t.Helper()
	var envelope fixtureEnvelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil || envelope.PayloadType != payloadType || envelope.Payload != base64.StdEncoding.EncodeToString(payload) || len(envelope.Signatures) != trust.SignatureThreshold {
		t.Fatalf("%s lost its payload/type/threshold shape: %v", field, err)
	}
	digest := sha256.Sum256(policyrelease.PAE(payloadType, payload))
	result := ws06SignatureInvariant{}
	custodians := make(map[string]struct{})
	for _, signature := range envelope.Signatures {
		signatureBytes := decodeWS06Base64(t, field+" signature", signature.Sig)
		matched := false
		valid := false
		for _, key := range trust.Keys {
			spki := decodeWS06Base64(t, field+" trust key", key.SPKIDERBase64)
			parsed, err := x509.ParsePKIXPublicKey(spki)
			publicKey, ok := parsed.(*ecdsa.PublicKey)
			if err != nil || !ok || policyrelease.SHA256Digest(spki) != key.KeyID {
				t.Fatalf("%s trust key identity is not self-consistent", field)
			}
			verified := ecdsa.VerifyASN1(publicKey, digest[:], signatureBytes)
			if key.KeyID == signature.KeyID {
				matched = true
				if verified {
					valid = true
					custodians[key.CustodianID] = struct{}{}
				}
			} else if verified {
				result.MismatchedHintCrypto++
			}
		}
		if valid {
			result.Valid++
		} else if !matched {
			result.UnknownKey++
		}
	}
	result.DistinctCustodians = len(custodians)
	return result
}

func assertWS06MaterializedNonTargetInvariants(t testing.TB, caseID string, materialized []byte) {
	t.Helper()
	if caseID == "tuf-only-substitution" {
		return
	}
	composition := decodeFixtureJSON(t, materialized).(map[string]any)
	vector := ws06ReleaseVector(t, composition)
	activationEnvelopeBytes := decodeWS06Base64(t, "materialized activation envelope", vector.Activation.EnvelopeBase64)
	var activationEnvelope fixtureEnvelope
	if err := json.Unmarshal(activationEnvelopeBytes, &activationEnvelope); err != nil {
		t.Fatal(err)
	}
	if caseID != "wrong-curve-spki" {
		if _, err := policyrelease.ParseDSSEEnvelope(activationEnvelopeBytes); err != nil {
			t.Fatalf("activation mutation introduced an unrelated DSSE syntax fault: %v", err)
		}
	}
	activationPayload := decodeWS06Base64(t, "materialized activation envelope payload", activationEnvelope.Payload)
	presentedActivationPayload := decodeWS06Base64(t, "materialized presented activation payload", vector.Activation.ManifestPayloadBase64)
	activationPayloadMismatch := !bytes.Equal(activationPayload, presentedActivationPayload)
	if activationPayloadMismatch != (caseID == "activation-payload-bit-flip") {
		t.Fatal("activation payload mismatch is not isolated to its named case")
	}
	if activationPayloadMismatch && !json.Valid(presentedActivationPayload) {
		t.Fatal("activation payload mismatch introduced an unrelated JSON syntax fault")
	}
	if policyrelease.SHA256Digest(activationPayload) != vector.Activation.ActivationSetID ||
		policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ActivationManifestPayloadType, activationPayload)) != vector.Activation.PAEDigest ||
		policyrelease.SHA256Digest(activationEnvelopeBytes) != vector.Activation.EnvelopeDigest {
		t.Fatal("materialized activation identities are stale")
	}
	if len(activationEnvelope.Signatures) == 0 || activationEnvelope.Signatures[0].Sig != vector.Activation.SignatureBase64 {
		t.Fatal("materialized activation signature summary is stale")
	}
	var manifest policyrelease.PolicyActivationManifestV1
	if err := json.Unmarshal(activationPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	if vector.Activation.SigningRequestDigest != ws06SigningRequestDigest(t, "policy_activation_manifest", policyrelease.ActivationManifestPayloadType, activationPayload, manifest) {
		t.Fatal("materialized activation signing-request binding is stale")
	}
	archive := decodeWS06Base64(t, "materialized archive", vector.Activation.ArchiveBase64)
	if policyrelease.SHA256Digest(archive) != vector.Activation.ArchiveDigest || len(archive) != vector.Activation.ArchiveBytes {
		t.Fatal("materialized archive identity is stale")
	}
	if _, err := policyrelease.InspectArchive(archive); err != nil {
		t.Fatalf("materialized archive safety: %v", err)
	}
	archiveFiles := archiveFileContents(t, archive)
	if !bytes.Equal(archiveFiles["manifest.dsse.json"], activationEnvelopeBytes) || len(archiveFiles)-1 != len(manifest.Files) {
		t.Fatal("materialized archive does not bind the exact activation envelope/file set")
	}
	for _, file := range manifest.Files {
		content, present := archiveFiles[file.Path]
		if !present || int64(len(content)) != file.Size || policyrelease.SHA256Digest(content) != file.Digest {
			t.Fatalf("materialized archive file binding failed for %s", file.Path)
		}
	}
	trustPayload := archiveFiles[manifest.Trust.TrustSetPath]
	trustEnvelopeBytes := archiveFiles[manifest.Trust.TrustSetEnvelopePath]
	if policyrelease.SHA256Digest(trustPayload) != manifest.Trust.TrustSetID || policyrelease.SHA256Digest(trustEnvelopeBytes) != manifest.Trust.TrustSetEnvelopeDigest {
		t.Fatal("materialized trust binding is stale")
	}
	var trust ws06TrustSetDocument
	if err := json.Unmarshal(trustPayload, &trust); err != nil {
		t.Fatal(err)
	}
	if trust.Epoch != manifest.Trust.TrustEpoch || trust.DeploymentPolicyID != manifest.DeploymentPolicy.PolicyID || trust.DeploymentPolicyVersion != manifest.DeploymentPolicy.Version || trust.DeploymentPolicyDigest != manifest.DeploymentPolicy.Digest || trust.SignatureThreshold != manifest.DeploymentPolicy.PolicySignatureThreshold {
		t.Fatal("materialized trust epoch, policy, or threshold binding is stale")
	}
	if len(vector.Keys) != len(trust.Keys) {
		t.Fatal("materialized release key inventory diverges from signed trust")
	}
	for index, key := range trust.Keys {
		if vector.Keys[index].KeyID != key.KeyID || vector.Keys[index].SPKIBase64 != key.SPKIDERBase64 || vector.Keys[index].CustodianID != key.CustodianID || vector.Keys[index].Purpose != key.Purpose {
			t.Fatal("materialized release key inventory has a stale signed-trust binding")
		}
	}
	signedTrust := composition["trusted_release_policy"].(map[string]any)
	if signedTrust["payload_base64"] != base64.StdEncoding.EncodeToString(trustPayload) || signedTrust["envelope_base64"] != base64.StdEncoding.EncodeToString(trustEnvelopeBytes) || signedTrust["trust_set_id"] != manifest.Trust.TrustSetID || signedTrust["envelope_digest"] != manifest.Trust.TrustSetEnvelopeDigest {
		t.Fatal("materialized consumer trust input diverges from the release-bound trust pair")
	}
	evidencePath := ""
	for _, file := range manifest.Files {
		if file.Digest == manifest.EvidenceManifestDigest {
			evidencePath = file.Path
			break
		}
	}
	var evidence policyrelease.PreSigningEvidenceManifestV1
	if evidencePath == "" || json.Unmarshal(archiveFiles[evidencePath], &evidence) != nil || !reflect.DeepEqual(evidence.Trust, manifest.Trust) || evidence.DeploymentPolicyID != manifest.DeploymentPolicy.PolicyID || evidence.DeploymentPolicyVersion != manifest.DeploymentPolicy.Version || evidence.DeploymentPolicyDigest != manifest.DeploymentPolicy.Digest {
		t.Fatal("materialized pre-signing evidence lost its trust/policy binding")
	}

	trustCheck := checkWS06MaterializedSignatures(t, "trust envelope", trustEnvelopeBytes, trustPayload, policyrelease.TrustSetPayloadType, trust)
	if trustCheck.Valid != trust.SignatureThreshold || trustCheck.UnknownKey != 0 {
		t.Fatal("materialized trust signatures are not independently valid")
	}
	if caseID != "duplicate-custodian-alias" && trustCheck.DistinctCustodians < trust.SignatureThreshold {
		t.Fatal("materialized trust envelope lost its non-target distinct-custodian threshold")
	}
	activationCheck := checkWS06MaterializedSignatures(t, "activation envelope", activationEnvelopeBytes, activationPayload, policyrelease.ActivationManifestPayloadType, trust)
	wantActivationValid := trust.SignatureThreshold
	if caseID == "activation-signature-bit-flip" || caseID == "misleading-keyid" || caseID == "syntactic-r1-s1-arbitrary-receipt" {
		wantActivationValid--
	}
	if activationCheck.Valid != wantActivationValid {
		t.Fatalf("activation mutation has %d valid signatures, want %d", activationCheck.Valid, wantActivationValid)
	}
	if caseID == "misleading-keyid" && (activationCheck.UnknownKey != 1 || activationCheck.MismatchedHintCrypto < 1) {
		t.Fatal("misleading keyid did not preserve a cryptographically valid signature under a different trusted SPKI")
	}
	if (caseID == "activation-signature-bit-flip" || caseID == "syntactic-r1-s1-arbitrary-receipt") && (activationCheck.UnknownKey != 0 || activationCheck.MismatchedHintCrypto != 0) {
		t.Fatal("activation signature mutation introduced an unrelated key-selection fault")
	}

	attestationEnvelopeBytes := decodeWS06Base64(t, "materialized release-attestation envelope", vector.Attestation.EnvelopeBase64)
	var attestationEnvelope fixtureEnvelope
	if err := json.Unmarshal(attestationEnvelopeBytes, &attestationEnvelope); err != nil {
		t.Fatal(err)
	}
	if caseID != "wrong-curve-spki" {
		if _, err := policyrelease.ParseDSSEEnvelope(attestationEnvelopeBytes); err != nil {
			t.Fatalf("release-attestation mutation introduced an unrelated DSSE syntax fault: %v", err)
		}
	}
	attestationPayload := decodeWS06Base64(t, "materialized release-attestation envelope payload", attestationEnvelope.Payload)
	presentedAttestationPayload := decodeWS06Base64(t, "materialized presented release-attestation payload", vector.Attestation.PayloadBase64)
	attestationPayloadMismatch := !bytes.Equal(attestationPayload, presentedAttestationPayload)
	if attestationPayloadMismatch != (caseID == "release-payload-bit-flip") {
		t.Fatal("release-attestation payload mismatch is not isolated to its named case")
	}
	if attestationPayloadMismatch && !json.Valid(presentedAttestationPayload) {
		t.Fatal("release-attestation payload mismatch introduced an unrelated JSON syntax fault")
	}
	if policyrelease.SHA256Digest(attestationPayload) != vector.Attestation.AttestationID || policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ReleaseAttestationPayloadType, attestationPayload)) != vector.Attestation.PAEDigest {
		t.Fatal("materialized release-attestation payload identity is stale")
	}
	envelopeDigestMismatch := policyrelease.SHA256Digest(attestationEnvelopeBytes) != vector.Attestation.EnvelopeDigest
	if envelopeDigestMismatch != (caseID == "archive-attestation-swap") {
		t.Fatal("release-attestation envelope identity mismatch is not isolated to its named case")
	}
	if len(attestationEnvelope.Signatures) == 0 || attestationEnvelope.Signatures[0].Sig != vector.Attestation.SignatureBase64 {
		t.Fatal("materialized release-attestation signature summary is stale")
	}
	attestationCheck := checkWS06MaterializedSignatures(t, "release-attestation envelope", attestationEnvelopeBytes, attestationPayload, policyrelease.ReleaseAttestationPayloadType, trust)
	wantAttestationValid := trust.SignatureThreshold
	if caseID == "release-signature-bit-flip" {
		wantAttestationValid--
	}
	if attestationCheck.Valid != wantAttestationValid {
		t.Fatalf("release-attestation mutation has %d valid signatures, want %d", attestationCheck.Valid, wantAttestationValid)
	}
	if caseID == "release-signature-bit-flip" && (attestationCheck.UnknownKey != 0 || attestationCheck.MismatchedHintCrypto != 0) {
		t.Fatal("release-attestation signature mutation introduced an unrelated key-selection fault")
	}
	var attestation policyrelease.ReleaseAttestationV1
	if err := json.Unmarshal(attestationPayload, &attestation); err != nil {
		t.Fatal(err)
	}
	if vector.Attestation.SigningRequestDigest != ws06SigningRequestDigest(t, "policy_release_attestation", policyrelease.ReleaseAttestationPayloadType, attestationPayload, manifest) {
		t.Fatal("materialized release-attestation signing-request binding is stale")
	}
	if attestation.ActivationSetID != vector.Activation.ActivationSetID || attestation.SignedEnvelopeDigest != vector.Activation.EnvelopeDigest || attestation.ArchiveDigest != vector.Activation.ArchiveDigest || attestation.EvidenceManifestDigest != vector.Activation.EvidenceManifestDigest || attestation.PolicyBundleID != vector.Activation.PolicyBundleID || !reflect.DeepEqual(attestation.Trust, manifest.Trust) || !reflect.DeepEqual(attestation.DeploymentPolicy, manifest.DeploymentPolicy) {
		t.Fatal("materialized release attestation lost a non-target immutable binding")
	}
	if caseID != "duplicate-custodian-alias" && caseID != "activation-signature-bit-flip" && caseID != "misleading-keyid" && caseID != "syntactic-r1-s1-arbitrary-receipt" && activationCheck.DistinctCustodians < trust.SignatureThreshold {
		t.Fatal("materialized activation lost its non-target distinct-custodian threshold")
	}
	if caseID != "duplicate-custodian-alias" && caseID != "release-signature-bit-flip" && attestationCheck.DistinctCustodians < trust.SignatureThreshold {
		t.Fatal("materialized release attestation lost its non-target distinct-custodian threshold")
	}
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
	if inventory.SchemaVersion != "1.0.0" || inventory.FixtureStatus != "nonauthorizing_consumer_mutation_instructions" || inventory.BaseVector != "ws06/canonical-threshold-two-vector.json" || inventory.ExecutionContract != "mutation_materialization_only" || inventory.ConsumerOwner != "WS-06" || inventory.Authority != "none" || timeErr != nil || verificationTime.Format(time.RFC3339) != inventory.VerificationTime || verificationTime.Location() != time.UTC {
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
		"flip_base64_bit": true, "flip_nested_base64_bit": true, "replace_base64_json_value": true,
		"replace_value": true, "reserialize_base64_json_from_recipe": true,
		"replace_document_from_file": true, "replace_signature_and_add_receipt": true,
		"replace_signed_trust_value": true, "merge_signed_trust_key_from_file": true,
		"append_signed_trust_key_from_file": true,
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
		if testCase.Mutation.Operation == "flip_nested_base64_bit" && testCase.Mutation.DecodedTarget == "" {
			t.Fatalf("consumer fixture case %q has no nested Base64 target", testCase.ID)
		}
		if (testCase.Mutation.Operation == "flip_base64_bit" || testCase.Mutation.Operation == "flip_nested_base64_bit") && (testCase.Mutation.ByteOffset < 0 || testCase.Mutation.BitMask < 1 || testCase.Mutation.BitMask > 255) {
			t.Fatalf("consumer fixture case %q has invalid bit mutation", testCase.ID)
		}
		validateWS06CompositionBaseline(t, testCase.Baseline, verificationTime)
		materialized := materializeWS06Mutation(t, testCase.Baseline, testCase.Mutation)
		if len(materialized) == 0 {
			t.Fatalf("consumer fixture case %q did not materialize", testCase.ID)
		}
		assertWS06MaterializedNonTargetInvariants(t, testCase.ID, materialized)
		if strings.Contains(testCase.Mutation.Operation, "signed_trust") {
			materializedWS06TrustDocument(t, materialized)
		}
		switch testCase.ID {
		case "wrong-curve-spki":
			_, trust := materializedWS06TrustDocument(t, materialized)
			key := trust.Keys[0]
			spki := decodeWS06Base64(t, "wrong-curve SPKI", key.SPKIDERBase64)
			parsed, err := x509.ParsePKIXPublicKey(spki)
			publicKey, ok := parsed.(*ecdsa.PublicKey)
			if err != nil || !ok || publicKey.Curve != elliptic.P384() || key.KeyID != policyrelease.SHA256Digest(spki) {
				t.Fatal("wrong-curve mutation did not update its SPKI-derived key identity consistently")
			}
		case "wrong-purpose":
			_, trust := materializedWS06TrustDocument(t, materialized)
			if trust.Keys[0].Purpose != "non-release-purpose" || trust.Keys[1].Purpose != policyrelease.ReleaseKeyPurpose {
				t.Fatal("wrong-purpose mutation is not isolated to one threshold signer")
			}
		case "duplicate-spki-alias":
			_, trust := materializedWS06TrustDocument(t, materialized)
			first, duplicate := trust.Keys[0], trust.Keys[2]
			if trust.SignatureThreshold != 2 || len(trust.Keys) != 3 || first.SPKIDERBase64 != duplicate.SPKIDERBase64 || first.KeyID != duplicate.KeyID || first.CustodianID == duplicate.CustodianID {
				t.Fatal("duplicate-SPKI vector does not preserve threshold two with one consistent duplicated identity")
			}
		case "duplicate-custodian-alias":
			_, trust := materializedWS06TrustDocument(t, materialized)
			if trust.SignatureThreshold != 2 || trust.Keys[0].CustodianID != trust.Keys[1].CustodianID {
				t.Fatal("duplicate-custodian vector does not exercise a threshold-two collision")
			}
		case "expired-trust-key":
			_, trust := materializedWS06TrustDocument(t, materialized)
			notAfter, err := time.Parse(time.RFC3339, trust.Keys[0].NotAfter)
			if err != nil || !notAfter.Before(verificationTime) {
				t.Fatal("expired-key vector is not expired at the pinned verification time")
			}
		case "revoked-trust-key":
			_, trust := materializedWS06TrustDocument(t, materialized)
			if trust.Keys[0].Status != "revoked" || trust.Keys[1].Status != "active" {
				t.Fatal("revoked-key mutation is not isolated to one threshold signer")
			}
		case "archive-attestation-swap":
			mutated := decodeFixtureJSON(t, materialized).(map[string]any)
			release := mutated["release"].(map[string]any)
			encoded := release["attestation"].(map[string]any)["envelope_base64"].(string)
			envelope, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policyrelease.ParseDSSEEnvelope(envelope); err != nil {
				t.Fatalf("alternate exact envelope is not syntax-valid: %v", err)
			}
		case "offline-egress-denied":
			mutated := decodeFixtureJSON(t, materialized).(map[string]any)
			environment := mutated["consumer_environment"].(map[string]any)
			if environment["network_enabled"] != false || !reflect.DeepEqual(mutated["release"], decodeFixtureJSON(t, fixtureBytes(t, "vectors/golden-vector.json"))) {
				t.Fatal("offline case does not compose the unchanged valid golden pair with denied egress")
			}
		case "syntactic-r1-s1-arbitrary-receipt":
			mutated := decodeFixtureJSON(t, materialized).(map[string]any)
			activation := mutated["release"].(map[string]any)["activation"].(map[string]any)
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
		"signing-receipt-count-one-over":                 false,
		"archive-entry-name-log-injection":               false,
		"evidence-renamed-or-encoded-protected-material": false,
		"policy-content-index-stale-digest":              false,
		"provenance-source-revision-mismatch":            false,
		"provenance-dependency-lock-mismatch":            false,
		"provenance-subject-digest-mismatch":             false,
		"build-review-count-one-over":                    false,
		"manifest-metadata-count-one-over":               false,
		"handoff-deep-copy-isolation":                    false,
		"release-review-count-one-over":                  false,
		"release-waiver-count-one-over":                  false,
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
