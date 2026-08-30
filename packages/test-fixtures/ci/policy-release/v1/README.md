# Policy release v1 fixtures

These are synthetic, non-authorizing inputs for the `STEAD-P1-016` contract
suite. They contain no production policy, trust root, credential, tenant data,
or private signing key. The Go contract test uses a publicly documented,
non-secret scalar only to emulate an external signer and to produce stable
P-256 verification vectors; that key is never accepted by a Stead trust store.

`source/` exercises deterministic unsigned construction, exact v0.1
security-profile/deployment-policy JSON materializations, and closed typed
embedded evidence. The test fixture generator replaces the empty source
policy-index template with the canonical sorted digest index for the selected
profile/assurance/trust inputs, then binds its identity into the build review
and exact SLSA source/lock/subject fields. All caller-provided evidence, review, waiver, assurance,
offline-check, signature, key-ID, and custodian material is digest-bound and
explicitly labeled unverified; the fixture claims no authority.
`observation/lifecycle-contract.json` inventories the exact WS-09 terminal
observation codes and value-only safe fields consumable by a separately owned
WS-07 durable audit/outbox adapter. It is out-of-artifact test metadata: it is
not included in source inputs, signed bytes, archives, handoffs, or transport
descriptors and grants no persistence or delivery authority.
`vectors/negative-cases.json` is the stable inventory of fail-closed parser,
archive, assurance, identity, custody, offline, and TUF non-authority cases.
The test records every vector by its catalog/ADR obligation.

`vectors/golden-vector.json` contains exact activation payload, signing-request,
DSSE envelope, strict ustar archive, release-attestation payload/envelope, SPKI,
signature, and SHA-256 identities. Verification is entirely offline. A digest
change requires deliberate vector regeneration plus independent review; the
transport descriptor and the WS-06 consumer inventory both declare no
authority.

`vectors/ws06-consumer-negative-cases.json` is a closed machine-readable set of
checked-in targets/replacements, a pinned verification time, mutation
operations, expected outcomes, and stable consumer codes for cryptographic
trust, key status/purpose, exact-pair, offline, and canonical `r=1,s=1`
false-receipt cases. Contract tests resolve and apply every mutation and verify
that the threshold-two alias/custodian cases exercise the intended state. This
is a mutation-materialization contract only. It deliberately does not execute,
simulate, or claim the independent WS-06 runtime verifier or its expected
codes, and build-time syntax checking grants no activation authority.
