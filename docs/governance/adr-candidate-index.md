# ADR candidate implementation-gate index

Status: **Phase 0 approval candidate; every listed decision remains deferred**

This index converts the narrative ADR queue into enforceable issue-activation deadlines. It does not approve an ADR, reopen a locked decision, or authorize implementation. `GATE-P0-APPROVED` and the applicable ADR gate must both pass before a dependent issue becomes active. The machine-readable mirror for the first-slice and Team-relation gates is `adr_decision_gates` in [`implementation-issue-catalog.yaml`](../planning/implementation-issue-catalog.yaml).

Candidates `ADR-CAND-001`–`ADR-CAND-021` are described in [the unresolved implementation-choice queue](../adr/unresolved-implementation-choices.md). The detail below makes the new Team-relation deadline explicit for reviewers.

## Issue activation deadlines

| Candidate | Decision must be accepted before | Known dependent issues | Enforcement note |
|---|---|---|---|
| `ADR-CAND-001` | `STEAD-P1-001` becomes active | `STEAD-P1-001`, `STEAD-P1-002`, `STEAD-P2-009`, `STEAD-P3-006` | Canonical URI/version/redirect grammar must precede executable schema, storage, import, and redirect work. |
| `ADR-CAND-002` | `STEAD-P1-002` becomes active | `STEAD-P1-002`, `STEAD-P1-007`, `STEAD-P1-011`, `STEAD-P2-010` | Physical namespace isolation and transaction coordination precede database/outbox and recovery implementation. |
| `ADR-CAND-003` | `STEAD-P1-006` becomes active | `STEAD-P1-006`, `STEAD-P1-003`, `STEAD-P1-007`, `STEAD-P1-008`, `STEAD-P1-012`, `STEAD-P2-006` | Authorization topology, timeout/cache, revocation, and provider-enforcement behavior precede the first executable decision path. |
| `ADR-CAND-004` | `STEAD-P1-006` becomes active | `STEAD-P1-006`, `STEAD-P1-002`, `STEAD-P2-004` | The formal label algebra/profile identifier representation precedes policy and persisted labeled-resource implementation. |
| `ADR-CAND-005` | `STEAD-P1-006` becomes active | `STEAD-P1-006`, `STEAD-P2-004`, `STEAD-P2-006` | Trusted human/agent/runtime attribute normalization precedes the first identity and policy implementation. |
| `ADR-CAND-006` | `STEAD-P1-007` becomes active | `STEAD-P1-007`, `STEAD-P1-008`, `STEAD-P1-012`, `STEAD-P2-005` | NATS tenant/domain partition, replay, retention, ordering, and DLQ rules precede event transport. |
| `ADR-CAND-007` | `STEAD-P1-006` becomes active | `STEAD-P1-006`, `STEAD-P1-011`, `STEAD-P2-004`, `STEAD-P2-010` | Bundle distribution, trust roots, offline verification, activation, and rollback precede executable OPA policy. |
| `ADR-CAND-008` | `STEAD-P1-003` becomes active | `STEAD-P1-003`, `STEAD-P1-012`, `STEAD-P2-001` | Provider reconciliation source precedence and degraded/conflict behavior precede the Gitea adapter. |
| `ADR-CAND-009` | `STEAD-P3-001` becomes active | `STEAD-P3-001` | Yjs persistence/compaction and deterministic Git projection precede collaboration implementation. |
| `ADR-CAND-010` | `STEAD-P2-002` selects the native fallback | `STEAD-P2-002` | The ADR is conditional: the upstream/headless path may proceed, but fallback code may not begin without acceptance. |
| `ADR-CAND-011` | `STEAD-P2-006` becomes active | `STEAD-P2-006`, `STEAD-P3-004` | Scale/search partition and semantic profile decisions precede the Beta search expansion. |
| `ADR-CAND-012` | `STEAD-P2-008` becomes active | `STEAD-P2-008` | Non-filesystem delivery and partition topology precede provider implementation. |
| `ADR-CAND-013` | `STEAD-P2-007` becomes active | `STEAD-P2-007` | Runner isolation/trust tiers precede runner-pool implementation. |
| `ADR-CAND-014` | `STEAD-P3-003` becomes active | `STEAD-P3-003` | Tamper-evidence/checkpoint/export representation precedes production audit checkpoints. |
| `ADR-CAND-015` | `STEAD-P3-002` becomes active | `STEAD-P3-002`, `STEAD-P3-007` | The validated cryptographic boundary and evidence model precede government/FIPS-capable profiles. |
| `ADR-CAND-016` | `STEAD-P2-009` becomes active | `STEAD-P2-009`, `STEAD-P3-006` | Identity/collision/redirect precedence precedes any importer write to canonical state. |
| `ADR-CAND-017` | `STEAD-P2-006` becomes active | `STEAD-P2-006`, `STEAD-P3-004` | Agent Registry, MCP/A2A execution surface, credential, cancellation, and compatibility choices precede executable agent integration. |
| `ADR-CAND-018` | any typed-property implementation issue is admitted | No current issue | The proposed issue must add this ADR as a dependency before admission; Phase 1 has no user-defined fields. |
| `ADR-CAND-019` | any scheduler/automation implementation issue is admitted | No current issue | The proposed issue must add this ADR as a dependency before admission. |
| `ADR-CAND-020` | any external/guest collaboration issue is admitted | No current issue | The proposed issue must add this ADR as a dependency before admission. |
| `ADR-CAND-021` | `STEAD-P1-006` becomes active | `STEAD-P1-006`, `STEAD-P1-002`, `STEAD-P1-005`, `STEAD-P2-003` | Initial Team lead/member/contributor relation semantics must precede authorization tuples, Team operations, and Team UI. |

## ADR-CAND-021 — Initial Team relation model

The directive locks hierarchical Team identity, owning/contributing Project accountability, and the rule that neither hierarchy nor accountability grants access. It does not select the first executable Team relation vocabulary or its exact mapping to authorization and UI responsibilities.

The ADR must decide whether `lead`, `member`, and `contributor` are distinct OpenFGA relations or stable Platform role labels mapped to a smaller explicit authorization relation set; their cardinality and grant semantics; Directory Group participation; revocation and reparenting effects; provisioning behavior; and backward-compatible tuple/data migration.

- Requirements: `PRIN-015`, `DOM-009`, `AUTH-002`, `AUTH-003`, `AUTH-006`, `UX-006`, `UX-007`.
- Owner: `WS-06`.
- Required reviewers: `WS-01`, `WS-02`, `WS-05`, and independent `WS-13`; project-owner approval applies to the public authorization contract.
- Locked constraints: no access from Team parent/child hierarchy; no access from Project ownership or contribution; no implicit organization-wide visibility; Directory Groups never act; security/classification policy may only restrict an explicit relationship allow; no configurable ontology or arbitrary role engine.
- Compatibility obligations: document initial tuple materialization, SCIM/directory mapping, rename/reparent behavior, revocation, API/UX labels, migration, rollback, and negative hierarchy/accountability tests.

## Gate behavior

An issue with an unresolved deadline candidate remains `BLOCKED`, even if its ordinary issue dependencies and `GATE-P0-APPROVED` have passed. Acceptance must record the ADR revision and project-owner disposition where required. Superseding an ADR updates this index and every affected issue dependency in one reviewed change.
