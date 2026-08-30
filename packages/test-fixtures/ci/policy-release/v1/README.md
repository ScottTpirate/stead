# Policy release v1 fixtures

These are synthetic, non-authorizing inputs for the `STEAD-P1-016` contract
suite. They contain no production policy, trust root, credential, tenant data,
or private signing key. The Go contract test uses a publicly documented,
non-secret scalar only to emulate an external signer and to produce stable
P-256 verification vectors; that key is never accepted by a Stead trust store.

`source/` exercises deterministic unsigned construction and embedded evidence.
`vectors/negative-cases.json` is the stable inventory of fail-closed parser,
archive, assurance, identity, custody, offline, and TUF non-authority cases.
The test records every vector by its catalog/ADR obligation.

`vectors/golden-vector.json` contains exact activation payload, signing-request,
DSSE envelope, strict ustar archive, release-attestation payload/envelope, SPKI,
signature, and SHA-256 identities. Verification is entirely offline. A digest
change requires deliberate vector regeneration plus independent review; the
transport descriptor and the WS-06 consumer inventory both declare no
authority.

`vectors/ws06-consumer-negative-cases.json` names cryptographic trust, key
status/purpose, exact-pair, and offline mutations that this WS-09 builder must
not absorb. Those vectors are the handoff to the independent runtime verifier,
not claims that build-time shape checking grants activation authority.
