# ADR index

Status: **Phase 1 active index**

| State | Records |
|---|---|
| Accepted | [ADR-0001: Canonical URI and compatibility profile](./0001-canonical-uri-and-compatibility-profile.md), resolving `ADR-CAND-001`. Locked decisions remain in the canonical directive and constitution, not retroactive ADRs. |
| Proposed | [ADR-0002: Security-label algebra and profile identifiers](./0002-security-label-algebra-and-profile-identifiers.md) (`ADR-CAND-004`), [ADR-0003: Trusted principal and runtime attributes](./0003-trusted-principal-and-runtime-attributes.md) (`ADR-CAND-005`), [ADR-0004: Initial Team role and authorization semantics](./0004-initial-team-role-and-authorization-semantics.md) (`ADR-CAND-021`), [ADR-0005: Authorization and policy-decision topology](./0005-authorization-and-policy-decision-topology.md) (`ADR-CAND-003`), and [ADR-0006: Signed policy-bundle distribution and activation](./0006-signed-policy-bundle-distribution-and-activation.md) (`ADR-CAND-007`). These records are decision-complete but do not unblock dependent implementation until their required approvals are recorded against an immutable revision. |
| Rejected | None. |
| Deferred | `ADR-CAND-002`, `ADR-CAND-006`, and `ADR-CAND-008`–`ADR-CAND-020` in [unresolved-implementation-choices.md](./unresolved-implementation-choices.md), each with a decision owner, reviewers, fixed constraints, and a deadline before dependent implementation. |
| Reconciliation conflicts | None. v0.2 semantic replacements and the `service_account` compatibility mapping are directive reconciliation, documented in `PHASE0_RECONCILIATION_REPORT.md`, and do not require an ADR. |

An accepted ADR authorizes only its bounded decision and dependent, otherwise-authorized issue; it does not pre-approve implementation or another candidate. Decision-record acceptance adopts the decision and its named future evidence obligations; it does not claim that implementation evidence already exists. A dependent implementation issue remains blocked until every named ADR is accepted and all ordinary issue dependencies are satisfied.
