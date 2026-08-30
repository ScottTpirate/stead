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
2. A signing service or offline ceremony operating under separately owned
   custody signs the exact request payload. It returns exact DSSE envelope
   bytes and digest-bound, caller-presented receipts canonicalized with
   `NewPresentedSigningResult`; the builder never receives a key. These
   receipts remain `unverified_presented_material` and do not establish signer
   identity, custody, trust, threshold satisfaction, or authority.
3. `FinalizeActivationArchive` checks only bounded DSSE syntax, exact payload,
   canonical DER/low-S shape, exact signature-byte receipt binding, and that
   enough distinct key-ID/custodian claims were presented for the deployment
   policy's requested counts. It does not verify ECDSA or trust. It writes and
   re-inspects one deterministic ustar archive for those exact envelope bytes.
4. A network-disabled workflow may present a digest-addressed check receipt for
   that exact archive. Its claimed outcome is labeled unverified and is not
   activation authority.
5. `PrepareReleaseAttestation` binds the final activation-set, envelope,
   archive, embedded evidence, policy/model/trust/deployment-policy, exact
   disclosure mode, presented assurance, signature/custodian claims, source,
   digest-addressed review and waiver receipts, builder/workflow, and offline
   check identities. Every caller assertion remains explicitly presented and
   unverified. Its payload contains neither its own ID nor its future envelope
   digest and declares `authority: none`.
6. The separate release ceremony signs that exact attestation request.
   `FinalizeReleaseHandoff` repeats the syntax, binding, and presented-count
   checks and returns exact archive and attestation-envelope bytes plus every
   immutable identity needed by WS-06. The handoff declares `authority: none`
   and a typed `required_not_performed_by_ws09` WS-06 verification checklist.

ECDSA ceremonies are not assumed deterministic. Unsigned bytes are
reproducible; an archive is reproducible once one exact returned activation
envelope is fixed; every new signing ceremony gets new envelope/archive and
attestation identities.

## Deterministic content and embedded evidence

Typed structs and Go `encoding/json` emit UTF-8 JSON in fixed field order with
no insignificant whitespace. Arrays without semantic order are sorted. Times
must be second-precision UTC RFC 3339. JSON member admission is exact-case:
case-folded aliases, including an exact member plus an alias, reject. Unknown
v1 versions, media types, deployment modes, malformed/duplicate-key JSON,
floating-point numbers in signed payloads, unbound payload files, and digest
mismatches fail closed. Package-produced failures expose only a stable code;
their compatibility `Field` and `Err` members remain empty, so
attacker-controlled member/path/parser text is neither rendered nor retained.

The four v1 contract roles are closed and mandatory: `decision_table`,
`input_schema`, `output_schema`, and `registries`. The canonical v1
policy-content index has its fixed media type and contains one sorted
role/path/media-type/SHA-256 entry for every semantic `payload/` file other
than itself. That includes contract files, every profile and authoritative
snapshot, the OpenFGA source, deployment policy, presented assurance result,
trust set, and trust-set envelope. Missing, extra, stale, reordered, duplicate,
or noncanonical index material rejects. Because `policy_bundle_id` hashes these
exact index bytes, any semantic payload update creates a new bundle identity
and invalidates review/provenance subjects bound to the predecessor. At least
one digest-bound profile and both immutable OpenFGA compatibility/migration
identifiers are required.

Every `payload/` and `evidence/` regular file is listed once by path, media type,
integer length, and SHA-256 digest. `manifest.dsse.json` is the only outer-file
exception. Evidence admission is a closed typed contract rather than a text
denylist: v1 accepts the SBOM, provenance, conformance, license, and
vulnerability paths, their exact media types, and their strict JSON field
schemas. SLSA provenance additionally binds the exact manifest source
revision, dependency-lock digest, and sole `stead-policy-content-index`
subject digest equal to `policy_bundle_id`; well-formed but unrelated evidence
rejects. The only additional evidence paths are mapping-coverage artifacts
named and SHA-256 bound by an admitted security profile. Authoritative
snapshots are likewise required at `payload/<declared payload_path>`. An
`external_regime_mapping` profile admits only authoritative-snapshot source
objects, requires at least one mapping, and binds every snapshot and mapping
evidence file into the signed manifest. Missing, conflicting, unbound, or
digest-mismatched artifacts reject. Free-form or protected evidence belongs in
a separate authorized evidence system and cannot enter this archive writer.

The digest-listed conformance report must claim 100% decision-row coverage, at
least 90% critical mutation score, and pass outcomes for deterministic replay,
label-lattice, explicit-deny, Agent-intersection, and provider bypass. The
embedded summary is labeled `unverified_presented_material`; WS-09 does not
authenticate the report producer or self-certify those claims. Runtime staging
must verify the immutable evidence and rerun deployable fixtures; it must not
claim to rerun source mutation analysis.

## DSSE profile and parser limits

The package implements DSSE v1.0.0 PAE and accepts the three non-interchangeable
ADR-0006 payload types. Writers use canonically padded standard RFC 4648 Base64;
bounded readers also accept canonically padded URL-safe Base64, but reject mixed
alphabets, absent/excess padding, duplicate JSON keys, case-folded known-member
aliases, duplicate key IDs, non-minimal DER, high-S, and cross-type
substitution. Genuine bounded unknown DSSE envelope extensions remain
ignorable. Activation-manifest, trust-set, and release-attestation payloads all
use exact-case, exact-member admission.

| Limit | V1 maximum |
|---|---:|
| Envelope bytes | 4 MiB |
| Decoded payload | 2 MiB |
| JSON nesting | 32 |
| Signatures | 16 |
| Encoded signature | 256 bytes |
| Decoded signature | 128 bytes |
| UTF-8 key ID | 80 bytes |
| Presented signing receipts | 16 |
| One metadata collection | 256 entries |
| Review receipts | 256 |
| Waiver receipts | 256 |

Caller-controlled file, manifest-metadata, review, waiver, and signing-receipt
cardinalities are checked before package allocation, copying, sorting, or map
construction. Both activation-manifest and release-attestation payloads must
fit the same 2 MiB decoded ceiling before any signing request is emitted.

`keyid` remains an unauthenticated selection hint. The builder checks exact
signature-byte receipt binding and counts distinct presented key-ID and
custodian claims. A canonical DER `r=1,s=1` plus arbitrary matching receipts is
therefore deliberately represented only as unverified syntax; the contract
regression proves it can never produce a verified/satisfied/authorizing WS-09
result. Only WS-06 may recompute SPKI identity, establish trust, verify
P-256/SHA-256 signatures, key purpose/status/validity/revocation, evaluate the
real threshold/custody rule, and grant activation authority.

## Strict ustar profile

Archive entries are lexical, owner/group zero and unnamed, timestamp zero, and
mode `0444` for files or `0555` for directories. The raw inspector accepts only
POSIX ustar `0` regular-file and `5` directory typeflags; the historical NUL
regular-file alias rejects. Every numeric field must use the writer's fixed
zero-padded octal plus canonical terminator, including the checksum's distinct
terminator. It rejects alternate space-padded or blank octal forms,
PAX/global-PAX, GNU long-name or long-link, sparse and other extensions;
absolute, traversal, backslash,
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

The signed fixture/materialization inputs are strict JSON instances of the
repository's exact v0.1 contracts. Security profiles name
`https://stead.example/policies/security-label-profiles/profile-v0.1.schema.json`;
deployment policies name
`https://stead.example/policies/deployment-domains/domain-profile-v0.1.schema.json`.
Closed typed validators enforce required and unknown fields, nested shapes,
IDs, supported versions, semantic constants, profile-version ceilings, empty
v0.1 bridges, and exact assurance binding. The digest-bound
`PresentedAssuranceEvaluationV1` is also labeled unverified; its claimed result
does not replace downstream WS-06/WS-12 authentication or activation checks.

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
a full exact golden archive/attestation vector, WS-09 negative cases, and a
closed machine-readable WS-06 consumer-verifier mutation inventory whose exact
case set, operations, outcomes, and expected codes are contract-tested. Every
target/replacement is checked in, verification time is pinned, and the suite
mechanically resolves and applies every mutation. This execution contract is
mutation materialization only: it does not implement or simulate WS-06's
runtime verifier and does not assert the consumer codes. The inventory is
nonauthorizing handoff material, not evidence that WS-09 executed WS-06
verification. The vector uses a public,
non-secret, nonproduction P-256 scalar solely to make independent verification
repeatable. No private material exists in the fixture and its key has no Stead
trust authority.

Run:

```sh
scripts/run_pinned_go.sh go test ./tests/contract/ci -count=1
scripts/run_pinned_go.sh go test ./tests/contract/ci -run '^TestGoldenOfflineVector$' -count=1
scripts/run_pinned_go.sh go test ./tests/contract/ci -bench . -benchmem -count=5
```

`STEAD_PRINT_POLICY_GOLDEN=1` prints a candidate vector for review.
`STEAD_UPDATE_POLICY_GOLDEN=1` rewrites both checked-in golden vectors through
the deterministic fixture generator. A changed hash is a contract/release
review event; never regenerate merely to make a test pass.

The implementation uses only the Go standard library and the local module. It
adds no runtime, signing, archive, canonicalization, TUF, OCI, or cryptographic
dependency.
