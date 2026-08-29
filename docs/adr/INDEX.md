# ADR index

Status: **Phase 1 active index**

| State | Records |
|---|---|
| Accepted | [ADR-0001: Canonical URI and compatibility profile](./0001-canonical-uri-and-compatibility-profile.md), resolving `ADR-CAND-001`. Locked decisions remain in the canonical directive and constitution, not retroactive ADRs. |
| Rejected | None. |
| Deferred | `ADR-CAND-002`–`ADR-CAND-021` in [unresolved-implementation-choices.md](./unresolved-implementation-choices.md), each with a decision owner, reviewers, fixed constraints, and a deadline before dependent implementation. |
| Reconciliation conflicts | None. v0.2 semantic replacements and the `service_account` compatibility mapping are directive reconciliation, documented in `PHASE0_RECONCILIATION_REPORT.md`, and do not require an ADR. |

An accepted ADR authorizes only its bounded decision and dependent, otherwise-authorized issue; it does not pre-approve implementation or another candidate. A dependent implementation issue remains blocked until its named ADR deadline and all issue dependencies are satisfied.
