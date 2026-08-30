// Package policyrelease constructs the immutable, signed-policy release
// artifacts owned by WS-09.
//
// The package deliberately has no signing-key, trust-store, policy-evaluation,
// or activation API. It prepares deterministic bytes for an external signing
// ceremony, validates the bounded shape of returned DSSE envelopes, writes a
// strict ustar archive, and prepares the post-signing release attestation.
// Runtime signature verification and activation authority belong to WS-06.
package policyrelease
