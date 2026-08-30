// Package policyrelease constructs the immutable, signed-policy release
// artifacts owned by WS-09.
//
// The package deliberately has no signing-key, trust-store, policy-evaluation,
// or activation API. It prepares deterministic bytes for an external signing
// ceremony, validates the bounded shape of returned DSSE envelopes, writes a
// strict ustar archive, and prepares the post-signing release attestation.
// Runtime signature verification and activation authority belong to WS-06.
// ObservedWorkflow adds a nonauthorizing, out-of-artifact WS-09 lifecycle seam
// whose typed terminal events may be handed to the WS-07-owned durable audit
// and outbox boundary; this package performs no persistence or delivery I/O.
package policyrelease
