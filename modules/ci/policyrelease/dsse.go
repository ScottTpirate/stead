package policyrelease

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"
)

type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type ParsedSignature struct {
	KeyID  string
	Bytes  []byte
	Digest string
}

type ParsedEnvelope struct {
	PayloadType string
	Payload     []byte
	Signatures  []ParsedSignature
}

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

type signingResultRecordV1 struct {
	SchemaVersion    string             `json:"schema_version"`
	WorkflowIdentity string             `json:"workflow_identity"`
	Receipts         []SignatureReceipt `json:"receipts"`
}

// PAE implements DSSE v1.0.0 pre-authentication encoding over exact bytes.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func decodeCanonicalBase64(field, value string, decodedLimit int) ([]byte, error) {
	if len(value)%4 != 0 {
		return nil, contractError("noncanonical_base64", field, nil)
	}
	padding := 0
	if strings.HasSuffix(value, "=") {
		padding = 1
		if strings.HasSuffix(value, "==") {
			padding = 2
		}
	}
	decodedLength := len(value)/4*3 - padding
	if decodedLength < 0 || decodedLength > decodedLimit {
		return nil, contractError("base64_decoded_limit", field, nil)
	}
	standardAlphabet := strings.ContainsAny(value, "+/")
	urlAlphabet := strings.ContainsAny(value, "-_")
	if standardAlphabet && urlAlphabet {
		return nil, contractError("mixed_base64_alphabet", field, nil)
	}
	encoding := base64.StdEncoding.Strict()
	if urlAlphabet {
		encoding = base64.URLEncoding.Strict()
	}
	decoded, err := encoding.DecodeString(value)
	if err != nil {
		return nil, contractError("invalid_base64", field, err)
	}
	if len(decoded) > decodedLimit || encoding.EncodeToString(decoded) != value {
		return nil, contractError("noncanonical_base64", field, nil)
	}
	return decoded, nil
}

func validateP256DERSignature(signature []byte) error {
	var decoded ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &decoded)
	if err != nil || len(rest) != 0 || decoded.R == nil || decoded.S == nil {
		return contractError("invalid_ecdsa_der", "signature", err)
	}
	canonical, err := asn1.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, signature) {
		return contractError("nonminimal_ecdsa_der", "signature", err)
	}
	n := elliptic.P256().Params().N
	if decoded.R.Sign() <= 0 || decoded.S.Sign() <= 0 || decoded.R.Cmp(n) >= 0 || decoded.S.Cmp(n) >= 0 {
		return contractError("invalid_ecdsa_scalar", "signature", nil)
	}
	halfN := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if decoded.S.Cmp(halfN) > 0 {
		return contractError("high_s_signature", "signature", nil)
	}
	return nil
}

// ParseDSSEEnvelope performs the bounded, allocation-aware envelope checks
// needed by the builder handoff. It intentionally does not establish signer
// trust or activation authority.
func ParseDSSEEnvelope(envelope []byte) (ParsedEnvelope, error) {
	if len(envelope) == 0 || len(envelope) > MaxEnvelopeBytes {
		return ParsedEnvelope{}, contractError("envelope_size_limit", "envelope", nil)
	}
	if !utf8.Valid(envelope) {
		return ParsedEnvelope{}, contractError("invalid_envelope_utf8", "envelope", nil)
	}
	if err := validateJSON(envelope, MaxJSONDepth, false); err != nil {
		return ParsedEnvelope{}, err
	}
	var raw dsseEnvelope
	if err := json.Unmarshal(envelope, &raw); err != nil {
		return ParsedEnvelope{}, contractError("malformed_dsse_envelope", "envelope", err)
	}
	if raw.PayloadType != ActivationManifestPayloadType && raw.PayloadType != TrustSetPayloadType && raw.PayloadType != ReleaseAttestationPayloadType {
		return ParsedEnvelope{}, contractError("unknown_dsse_payload_type", "payloadType", nil)
	}
	payload, err := decodeCanonicalBase64("payload", raw.Payload, MaxDecodedPayloadBytes)
	if err != nil {
		return ParsedEnvelope{}, err
	}
	if len(raw.Signatures) == 0 || len(raw.Signatures) > MaxEnvelopeSignatures {
		return ParsedEnvelope{}, contractError("signature_count_limit", "signatures", nil)
	}
	parsed := ParsedEnvelope{PayloadType: raw.PayloadType, Payload: payload, Signatures: make([]ParsedSignature, 0, len(raw.Signatures))}
	seen := make(map[string]struct{}, len(raw.Signatures))
	for i, signature := range raw.Signatures {
		field := fmt.Sprintf("signatures[%d]", i)
		if !utf8.ValidString(signature.KeyID) || len(signature.KeyID) > MaxKeyIDBytes || !digestPattern.MatchString(signature.KeyID) {
			return ParsedEnvelope{}, contractError("invalid_key_id", field+".keyid", nil)
		}
		if _, duplicate := seen[signature.KeyID]; duplicate {
			return ParsedEnvelope{}, contractError("duplicate_signature_key", field+".keyid", nil)
		}
		seen[signature.KeyID] = struct{}{}
		if len(signature.Sig) > MaxEncodedSignatureBytes {
			return ParsedEnvelope{}, contractError("encoded_signature_limit", field+".sig", nil)
		}
		decoded, err := decodeCanonicalBase64(field+".sig", signature.Sig, MaxDecodedSignatureBytes)
		if err != nil {
			return ParsedEnvelope{}, err
		}
		if err := validateP256DERSignature(decoded); err != nil {
			return ParsedEnvelope{}, err
		}
		parsed.Signatures = append(parsed.Signatures, ParsedSignature{KeyID: signature.KeyID, Bytes: decoded, Digest: SHA256Digest(decoded)})
	}
	return parsed, nil
}

func validateExpectedEnvelope(envelope, expectedPayload []byte, expectedType string) (ParsedEnvelope, error) {
	parsed, err := ParseDSSEEnvelope(envelope)
	if err != nil {
		return ParsedEnvelope{}, err
	}
	if parsed.PayloadType != expectedType {
		return ParsedEnvelope{}, contractError("cross_type_dsse_substitution", "payloadType", nil)
	}
	if !bytes.Equal(parsed.Payload, expectedPayload) {
		return ParsedEnvelope{}, contractError("signed_payload_mismatch", "payload", nil)
	}
	return parsed, nil
}

func validateSigningResult(parsed ParsedEnvelope, result SigningResult, policy DeploymentPolicyBinding) (ThresholdResult, error) {
	expectedResult, err := NewSigningResult(result.WorkflowIdentity, result.Receipts)
	if err != nil {
		return ThresholdResult{}, err
	}
	if result.ResultDigest != expectedResult.ResultDigest {
		return ThresholdResult{}, contractError("signing_result_digest_mismatch", "signing_result.result_digest", nil)
	}
	if len(result.Receipts) != len(parsed.Signatures) {
		return ThresholdResult{}, contractError("signing_receipt_count_mismatch", "signing_result.receipts", nil)
	}
	receipts := make(map[string]SignatureReceipt, len(result.Receipts))
	for _, receipt := range result.Receipts {
		if !digestPattern.MatchString(receipt.KeyID) {
			return ThresholdResult{}, contractError("invalid_key_id", "signing_result.receipts.key_id", nil)
		}
		if _, duplicate := receipts[receipt.KeyID]; duplicate {
			return ThresholdResult{}, contractError("duplicate_signing_receipt", "signing_result.receipts.key_id", nil)
		}
		if err := validateIdentifier("signing_result.receipts.custodian_id", receipt.CustodianID); err != nil {
			return ThresholdResult{}, err
		}
		if receipt.KeyPurpose != ReleaseKeyPurpose {
			return ThresholdResult{}, contractError("wrong_key_purpose", "signing_result.receipts.key_purpose", nil)
		}
		if err := validateDigest("signing_result.receipts.signature_digest", receipt.SignatureDigest); err != nil {
			return ThresholdResult{}, err
		}
		receipts[receipt.KeyID] = receipt
	}
	keyIDs := make([]string, 0, len(parsed.Signatures))
	custodians := make(map[string]struct{}, len(parsed.Signatures))
	for _, signature := range parsed.Signatures {
		receipt, ok := receipts[signature.KeyID]
		if !ok || receipt.SignatureDigest != signature.Digest {
			return ThresholdResult{}, contractError("signing_receipt_mismatch", "signing_result.receipts", nil)
		}
		keyIDs = append(keyIDs, signature.KeyID)
		custodians[receipt.CustodianID] = struct{}{}
	}
	sort.Strings(keyIDs)
	custodianIDs := make([]string, 0, len(custodians))
	for custodian := range custodians {
		custodianIDs = append(custodianIDs, custodian)
	}
	sort.Strings(custodianIDs)
	threshold := ThresholdResult{
		RequiredSignatures:         policy.PolicySignatureThreshold,
		VerifiedDistinctKeys:       len(keyIDs),
		DistinctCustodiansRequired: policy.DistinctSigningCustodians,
		VerifiedDistinctCustodians: len(custodianIDs),
		KeyIDs:                     keyIDs,
		CustodianIDs:               custodianIDs,
	}
	threshold.Satisfied = threshold.VerifiedDistinctKeys >= threshold.RequiredSignatures && (!threshold.DistinctCustodiansRequired || threshold.VerifiedDistinctCustodians >= threshold.RequiredSignatures)
	if !threshold.Satisfied {
		return ThresholdResult{}, contractError("deployment_signature_threshold_unsatisfied", "signing_result", nil)
	}
	return threshold, nil
}

// NewSigningResult canonicalizes the safe external-signing receipt record and
// computes the digest later bound by release evidence. It signs nothing.
func NewSigningResult(workflowIdentity string, receipts []SignatureReceipt) (SigningResult, error) {
	if err := validateIdentifier("signing_result.workflow_identity", workflowIdentity); err != nil {
		return SigningResult{}, err
	}
	resultReceipts := append([]SignatureReceipt(nil), receipts...)
	sort.Slice(resultReceipts, func(i, j int) bool { return resultReceipts[i].KeyID < resultReceipts[j].KeyID })
	for index, receipt := range resultReceipts {
		if !digestPattern.MatchString(receipt.KeyID) {
			return SigningResult{}, contractError("invalid_key_id", "signing_result.receipts.key_id", nil)
		}
		if index > 0 && receipt.KeyID == resultReceipts[index-1].KeyID {
			return SigningResult{}, contractError("duplicate_signing_receipt", "signing_result.receipts.key_id", nil)
		}
		if err := validateIdentifier("signing_result.receipts.custodian_id", receipt.CustodianID); err != nil {
			return SigningResult{}, err
		}
		if receipt.KeyPurpose != ReleaseKeyPurpose {
			return SigningResult{}, contractError("wrong_key_purpose", "signing_result.receipts.key_purpose", nil)
		}
		if err := validateDigest("signing_result.receipts.signature_digest", receipt.SignatureDigest); err != nil {
			return SigningResult{}, err
		}
	}
	recordBytes, err := marshalCanonical(signingResultRecordV1{SchemaVersion: "1.0.0", WorkflowIdentity: workflowIdentity, Receipts: resultReceipts})
	if err != nil {
		return SigningResult{}, err
	}
	return SigningResult{WorkflowIdentity: workflowIdentity, ResultDigest: SHA256Digest(recordBytes), Receipts: resultReceipts}, nil
}

func makeSigningRequest(purpose, payloadType string, payload []byte, manifest ManifestInput) (SigningRequestV1, []byte, error) {
	request := SigningRequestV1{
		SchemaVersion:              "1.0.0",
		Purpose:                    purpose,
		PayloadType:                payloadType,
		PayloadBase64:              base64.StdEncoding.EncodeToString(payload),
		PAEDigest:                  SHA256Digest(PAE(payloadType, payload)),
		KeyPurpose:                 ReleaseKeyPurpose,
		DeploymentPolicyID:         manifest.DeploymentPolicy.PolicyID,
		DeploymentPolicyVersion:    manifest.DeploymentPolicy.Version,
		DeploymentPolicyDigest:     manifest.DeploymentPolicy.Digest,
		RequiredSignatureThreshold: manifest.DeploymentPolicy.PolicySignatureThreshold,
		DistinctCustodiansRequired: manifest.DeploymentPolicy.DistinctSigningCustodians,
		SourceRevision:             manifest.SourceRevision,
	}
	encoded, err := marshalCanonical(request)
	if err != nil {
		return SigningRequestV1{}, nil, err
	}
	return request, encoded, nil
}
