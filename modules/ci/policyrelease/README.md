# Stead policy activation release builder v1

This package implements the WS-09 construction side of ADR-0006. It creates
deterministic unsigned activation content, external DSSE signing requests,
strict ustar archives for exact returned activation envelopes, post-signing
release-attestation requests, and an immutable archive-plus-attestation handoff.

It deliberately does not contain a signing function, private-key input, trust
store, OpenFGA or policy evaluator, database port, activation pointer, or
runtime authorization decision. WS-06 independently verifies cryptography,
trust, compatibility, conformance, and activation prerequisites before these
bytes can gain authority.

## Construction order

The public API makes the non-circular order explicit:

1. `PrepareUnsigned(BuildInput)` validates bounded inputs, creates
   `evidence/pre-signing-evidence-manifest.json`, emits canonical manifest bytes,
   computes the policy/evidence/activation identities, and emits an activation
   `SigningRequestV1`.
2. A separately authorized release signing service or offline ceremony signs
   the exact request payload. It returns exact DSSE envelope bytes and a
   separately digest-bound `SigningResult` constructed with
   `NewSigningResult`; the builder never receives its key. Signing-workflow
   identities may not be the builder or release-workflow identity.
3. `FinalizeActivationArchive` checks the returned envelope's bounded DSSE
   shape, exact payload, DER/low-S shape, result receipts, deployment-policy
   threshold, and distinct custodians. It then writes and re-inspects one
   deterministic ustar archive for those exact envelope bytes.
4. A network-disabled verifier records a safe result digest for that exact
   archive. This result is evidence, not activation authority.
5. `PrepareReleaseAttestation` binds the final activation-set, envelope,
   archive, embedded evidence, policy/model/trust/deployment-policy, exact
   disclosure mode, evaluated assurance, signer/custodian threshold, source,
   reviews, waivers, builder/workflow, and offline-result identities. Its
   payload contains neither its own ID nor its future envelope digest.
6. The separate release ceremony signs that exact attestation request.
   `FinalizeReleaseHandoff` independently enforces the attestation threshold and
   returns exact archive and attestation-envelope bytes plus every immutable
   identity needed by WS-06.

ECDSA ceremonies are not assumed deterministic. Unsigned bytes are
reproducible; an archive is reproducible once one exact returned activation
envelope is fixed; every new signing ceremony gets new envelope/archive and
attestation identities.

## Deterministic content and embedded evidence

Typed structs and Go `encoding/json` emit UTF-8 JSON in fixed field order with
no insignificant whitespace. Arrays without semantic order are sorted. Times
must be second-precision UTC RFC 3339. Unknown v1 versions, media types,
deployment modes, malformed/duplicate-key JSON, floating-point numbers in
signed payloads, unbound payload files, and digest mismatches fail closed.

The four v1 contract roles are closed and mandatory: `decision_table`,
`input_schema`, `output_schema`, and `registries`. The policy-content index has
its fixed v1 media type. At least one digest-bound profile and both immutable
OpenFGA compatibility/migration identifiers are required.

Every `payload/` and `evidence/` regular file is listed once by path, media type,
integer length, and SHA-256 digest. `manifest.dsse.json` is the only outer-file
exception. Pre-signing evidence can bind source, lock, policy/model/trust,
SBOM, provenance, test/property/mutation, vulnerability, license, review, and
waiver results. Admission rejects evidence that names a not-yet-existing
activation, envelope, archive, or attestation identity, and rejects PEM private
key markers. Callers remain responsible for supplying only safe evidence
summaries with no protected content.

Policy conformance admission requires 100% decision-row coverage, at least 90%
critical mutation score, and passing deterministic replay, label-lattice,
explicit-deny, Agent-intersection, and provider-bypass results. Runtime staging
must verify this immutable evidence and rerun deployable fixtures; it must not
claim to rerun source mutation analysis.

## DSSE profile and parser limits

The package implements DSSE v1.0.0 PAE and accepts the three non-interchangeable
ADR-0006 payload types. Writers use canonically padded standard RFC 4648 Base64;
bounded readers also accept canonically padded URL-safe Base64, but reject mixed
alphabets, absent/excess padding, duplicate JSON keys, duplicate key IDs,
non-minimal DER, high-S, and cross-type substitution.

| Limit | V1 maximum |
|---|---:|
| Envelope bytes | 4 MiB |
| Decoded payload | 2 MiB |
| JSON nesting | 32 |
| Signatures | 16 |
| Encoded signature | 256 bytes |
| Decoded signature | 128 bytes |
| UTF-8 key ID | 80 bytes |

`keyid` remains an unauthenticated selection hint. The builder checks exact
receipt binding and counts distinct keys/custodians from the externally supplied
workflow result, but only WS-06 may recompute SPKI identity, establish trust,
verify P-256/SHA-256 signatures, key purpose/status/validity/revocation, and
grant activation authority.

## Strict ustar profile

Archive entries are lexical, owner/group zero and unnamed, timestamp zero, and
mode `0444` for files or `0555` for directories. The raw inspector accepts only
POSIX ustar regular files/directories. It rejects PAX/global-PAX, GNU long-name
or long-link, sparse and other extensions; absolute, traversal, backslash,
duplicate or unsorted paths; links, devices, FIFO/socket entries; setuid/setgid;
base-256 or overflowed sizes; malformed UTF-8; noncanonical metadata; bad
checksums; missing end blocks; and non-zero bytes after the end marker. It never
extracts to disk.

| Limit | V1 maximum |
|---|---:|
| Exact tar bytes | 64 MiB |
| Entries | 512 |
| Regular files, including the envelope | 256 |
| One regular file | 8 MiB |
| Total regular-file content | 48 MiB |
| UTF-8 path | 240 bytes |
| Path components | 16 |
| One component | 100 UTF-8 bytes |

All count/size arithmetic is checked before content slicing or allocation.
Zero-block record padding is allowed within the exact 64 MiB raw limit and is
therefore part of the archive digest; the deterministic writer emits its one
canonical representation.

## Assurance, custody, transport, and recovery

Signature/recovery/lowering thresholds, custodian separation, approved
cryptographic boundary, validated-module requirement, evidence profile, and
`request_boundary` or `commit_boundary` mode arrive only through the exact
typed deployment-policy binding. Profile IDs cannot select these values. The
starter threshold-one, threshold-two, and synthetic non-government
threshold-three fixtures prove the data-driven path.

The builder does not parse deployment-policy YAML or invent its semantics. It
requires a canonical, exact-digest `EvaluatedAssuranceResultV1` produced by the
separately owned WS-06/WS-12 validator and rejects unknown fields, stale bytes,
failed results, or any mismatch between that result and the typed binding.

`BuildTransportDescriptor` names only exact archive and attestation-envelope
digests and always states `non_authorizing_transport_only`. TUF metadata, OCI
descriptors/tags, filenames, HTTPS, repository membership, and filesystem
ownership cannot replace either DSSE envelope or the deployment assurance
result. The golden vector verifies wholly from checked-in bytes with no network,
TUF, public PKI, transparency service, registry, KMS, or proprietary dependency.

Build/sign/archive/attestation interruption leaves no runtime state because this
module owns none. Retry from pinned source/lock/recipe and declared metadata;
reuse returned bytes only when their exact digests still match. Rollback is a
new forward release under current or stronger trust, never reuse of revoked or
stale signing evidence. Runtime stage/activate, monotonic anchors, failure
recovery, backup/restore, and audit/outbox transactions remain WS-06/WS-02/WS-07
owned.

## Fixtures and tests

`packages/test-fixtures/ci/policy-release/v1` contains synthetic source/evidence,
a full exact golden archive/attestation vector, WS-09 negative cases, and
explicit WS-06 consumer-verifier mutations. The vector uses a public,
non-secret, nonproduction P-256 scalar solely to make independent verification
repeatable. No private material exists in the fixture and its key has no Stead
trust authority.

Run:

```sh
scripts/run_pinned_go.sh go test ./tests/contract/ci -count=1
scripts/run_pinned_go.sh go test ./tests/contract/ci -run '^TestGoldenOfflineVector$' -count=1
scripts/run_pinned_go.sh go test ./tests/contract/ci -bench . -benchmem -count=5
```

`STEAD_PRINT_POLICY_GOLDEN=1` prints a candidate vector for reviewed fixture
refresh. A changed hash is a contract/release review event; never overwrite the
checked-in vector merely to make a test pass.

The implementation uses only the Go standard library and the local module. It
adds no runtime, signing, archive, canonicalization, TUF, OCI, or cryptographic
dependency.
