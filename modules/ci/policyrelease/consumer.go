package policyrelease

import (
	"archive/tar"
	"bytes"
	"io"
	"time"
)

// ValidateActivationArchive is the P1-006 consumer of the existing archive and
// complete content-schema validators. It returns untrusted presented material,
// never signature, approval, activation, or runtime authorization authority.
// Its observer must durably acknowledge the validation just as for a release
// producer. WS-06 still verifies signatures, trust, time, and activation fences.
func (workflow *ObservedWorkflow) ValidateActivationArchive(archive []byte) (UnsignedActivation, []byte, error) {
	if err := workflow.beginOperation(); err != nil {
		return UnsignedActivation{}, nil, err
	}
	defer workflow.active.Store(false)
	unsigned, envelope, operationErr := decodeActivationArchive(archive)
	facts := LifecycleFacts{}
	if operationErr == nil {
		facts = lifecycleUnsignedFacts(unsigned)
		facts.ArchiveDigest = SHA256Digest(archive)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowActivation, LifecycleStageValidateArchive, facts, operationErr)
	if err := workflow.observe(event); err != nil {
		return UnsignedActivation{}, nil, err
	}
	if operationErr != nil {
		return UnsignedActivation{}, nil, operationErr
	}
	return unsigned, envelope, nil
}

func decodeActivationArchive(archive []byte) (UnsignedActivation, []byte, error) {
	// Preflight raw blocks before archive/tar can normalize extended headers.
	if _, err := inspectArchive(archive); err != nil {
		return UnsignedActivation{}, nil, err
	}
	contents := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return UnsignedActivation{}, nil, contractError("invalid_archive", "archive", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(reader, MaxArchiveFileBytes+1))
		if err != nil || len(data) > MaxArchiveFileBytes {
			return UnsignedActivation{}, nil, contractError("invalid_archive_file", "archive", err)
		}
		contents[header.Name] = data
	}
	envelope := contents["manifest.dsse.json"]
	parsed, err := ParseDSSEEnvelope(envelope)
	if err != nil || parsed.PayloadType != ActivationManifestPayloadType {
		return UnsignedActivation{}, nil, contractError("invalid_activation_envelope", "manifest", err)
	}
	var manifest PolicyActivationManifestV1
	if err := decodeStrict(parsed.Payload, &manifest); err != nil {
		return UnsignedActivation{}, nil, err
	}
	if _, err := validateArchive(archive, envelope, manifest.Files); err != nil {
		return UnsignedActivation{}, nil, err
	}
	unsigned := UnsignedActivation{Manifest: manifest, ManifestPayload: parsed.Payload,
		ActivationSetID: SHA256Digest(parsed.Payload), PolicyBundleID: manifest.PolicyBundleID,
		EvidenceManifestBytes: contents[evidenceManifestPath], EvidenceManifestDigest: manifest.EvidenceManifestDigest}
	if err := decodeStrict(unsigned.EvidenceManifestBytes, &unsigned.EvidenceManifest); err != nil {
		return UnsignedActivation{}, nil, err
	}
	for _, file := range manifest.Files {
		unsigned.Files = append(unsigned.Files, File{Path: file.Path, MediaType: file.MediaType, Content: contents[file.Path]})
	}
	issued, err := time.Parse(time.RFC3339, manifest.IssuedAt)
	if err != nil {
		return UnsignedActivation{}, nil, contractError("invalid_activation_validity", "issued_at", err)
	}
	expires, err := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if err != nil {
		return UnsignedActivation{}, nil, contractError("invalid_activation_validity", "expires_at", err)
	}
	input := ManifestInput{DeploymentPolicy: manifest.DeploymentPolicy, SourceRevision: manifest.SourceRevision, IssuedAt: issued, ExpiresAt: expires}
	unsigned.SigningRequest, unsigned.SigningRequestBytes, err = makeSigningRequest("policy_activation_manifest", ActivationManifestPayloadType, parsed.Payload, input)
	if err != nil {
		return UnsignedActivation{}, nil, err
	}
	if err := validateUnsignedActivation(unsigned); err != nil {
		return UnsignedActivation{}, nil, err
	}
	return unsigned, envelope, nil
}
