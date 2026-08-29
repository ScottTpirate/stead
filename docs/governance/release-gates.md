# Phase 0 Release Gates and Independent Approval Rules

| Field | Value |
|---|---|
| Status | Draft Phase 0 governance contract; no release authority is granted |
| Gate owner | Workstream 13 — QA/security/release |
| Architecture gate owner | Workstream 1 — Architecture/standards |
| Release decision | Independent QA approval **and** independent security approval; project-owner approval where this policy or an ADR requires it |
| Normative requirements | §0; PRIN-010; ARCH-005; SCM-005; DEP-004–005; OPS-003–005; SEC-001–006; TEST-001–009; Phase 0; §21 locked decisions; §22 definition of done; AGENT-001–007 |
| Related artifacts | [`architecture/constitution.md`](../architecture/constitution.md), [`testing/golden-vertical-slice.md`](../testing/golden-vertical-slice.md), [`security/threat-model.md`](../security/threat-model.md), [`security/classification-bypass-inventory.md`](../security/classification-bypass-inventory.md), [`governance/license-and-dependency-approval.md`](license-and-dependency-approval.md) |

This policy governs Phase 0 exit, later milestone promotion, and every release candidate. It does not authorize Phase 1 implementation. A gate passes only for the exact source commit, build and artifact digests, dependency lock, contract/schema/model/policy versions, provider matrix, installation profiles, and evidence manifest reviewed. A later change invalidates affected evidence and approvals.

## Non-negotiable rules

1. A release decision is fail-closed. Missing, inaccessible, unverifiable, stale, contradictory, or unsigned required evidence is a failure, not “unknown but acceptable.”
2. The author or implementation owner of a change cannot be its final QA approver, security approver, or sole release approver. No person or agent self-approves work they authored.
3. Final release requires two explicit dispositions: independent QA `APPROVE` and independent security `APPROVE`. Both reviewers must be outside the candidate’s implementation ownership and must inspect primary evidence. If staffing combines QA/security expertise in one workstream, two independently accountable reviewer identities still sign.
4. A module owner may attest completion and an architecture owner may approve a contract, but neither substitutes for independent final approval.
5. Any required test failure fails the candidate. A retry creates a new run and preserves the original failure; it does not rewrite a failed run as passed.
6. A known unauthorized-disclosure path, authorization/classification bypass, cross-domain/write-down route, acknowledged-write loss, missing required audit event, or failed backup/restore has no ordinary waiver.
7. A locked architecture decision changes only through an ADR plus explicit project-owner approval. A release waiver is not an ADR.
8. Unknown or disallowed distributed licenses, missing SBOM/signature/provenance/checksum/notices, or unapproved dependencies fail the candidate. License exceptions follow the separate ADR + legal + project-owner workflow.
9. “Security-ready,” “FIPS-capable,” and control-mapping evidence do not authorize claims of certification, accreditation, FedRAMP authorization, FIPS validation, CMMC compliance, classified-system approval, cross-domain certification, or a SLSA level the exact process has not achieved.
10. Release pressure, schedule, customer identity, administrative role, or previous approval does not override a deny gate.
11. Agent-ready Phase 0 contracts do not authorize agent execution. No Phase 0 gate may be satisfied by implementing orchestration, prompting, model hosting, agent memory, `AgentRun`, A2A dispatch, a future Agent Registry, or the full MCP tool catalog.
12. A future agent release cannot inherit a human’s broad permissions. Its evidence must prove explicit delegation/task/resource scope, independent revocation, runtime/context intersection, canonical Platform API/MCP use, scoped direct Git credentials, external-runtime trust controls, and distinct requester/actor attribution.

## Roles, independence, and vetoes

| Role | Required action | Independence / veto rule |
|---|---|---|
| Implementation owner(s) | Produce the change, tests, migration/rollback docs, safe telemetry/audit, and signed evidence attestation | Cannot give final QA/security approval; cannot approve own waiver |
| Contract/module owner | Confirm directory, schema, API/provider/policy and compatibility boundaries | Cannot waive a contract violation; cross-owner edits require designated integration ownership |
| Architecture approver (WS-01) | Approve architecture contracts, compatibility and ADR disposition | May veto boundary/locked-decision violations; not a substitute for QA/security |
| QA approver (independent WS-13 identity) | Reproduce required suites, verify traceability/coverage/evidence and functional/recovery behavior | Must not have authored or implemented candidate changes; unresolved required-test failure is a veto |
| Security approver (independent WS-13 identity) | Review threat/bypass results, authz/classification, supply chain, secrets, audit and residual risk | Must not have authored or implemented candidate changes; known disclosure/bypass is a veto |
| License/legal reviewers | Validate distribution rights, obligations and approved exceptions | Unknown/disallowed-unapproved component is a veto; legal cannot waive technical security gates |
| Release manager | Freeze exact candidate, assemble manifest, verify signatures/approvals, publish only after all gates | Cannot change evidence or infer approval; cannot overrule a veto |
| Project owner | Approve Phase 0 constitution and required ADR/license exceptions; accept only explicitly waivable residual risk | Cannot convert an absolute TEST-008 failure into a pass without a conforming change and new evidence |

A reviewer is not independent when they authored the relevant production code/policy/schema/test oracle, controlled the only evidence generation without reproducibility, report to the candidate as an implementation subagent for that change, or have an unresolved conflict of interest. Writing generic harness infrastructure does not automatically disqualify a reviewer, but they cannot be the sole verifier of that harness or its result.

QA and security approvals are separately revocable. Discovery that inputs, evidence, signer identity, or a test result were invalid immediately returns the candidate/release to `HOLD` and invokes quarantine or incident handling.

## Phase 0 architecture-constitution gate

No broad parallel feature implementation starts until `GATE-P0-APPROVED` passes. Drafting schemas, contracts, test specifications and governance artifacts is Phase 0 work; implementing domain/provider/UI features is not.

### Required Phase 0 artifacts

The project owner must approve immutable versions of all items below after WS-01 architecture approval, WS-06 security-contract approval, and separate independent QA and security approvals from two distinct WS-13 reviewer identities:

- product principles and the architecture constitution;
- repository/module layout, database ownership and prohibited-boundary rules;
- OWGP v0.1, canonical entity/resource/relationship schemas and ontology governance;
- security-label schema/profile/lattice and inheritance/join/downgrade rules;
- OpenFGA model v0.1 with model and migration test vectors;
- OPA input/output, trusted-context, deny/error, bundle/version/signature contract and decision table;
- capability-specific provider interfaces;
- OpenAPI 3.1.1 skeleton, JSON Schema 2020-12 linkage and RFC 9457 error profile;
- AsyncAPI 3.1.x skeleton, CloudEvents extensions, naming/subject, replay and idempotency contract;
- threat-model baseline and complete classification/provider-bypass inventory;
- Apache-2.0, notice, dependency, exception, SBOM and quarantine workflow;
- requirements traceability register, dependency-ordered issue hierarchy, workstream ownership map and contract ownership matrix;
- Phase 0 artifact backlog and ADR disposition;
- golden vertical-slice scenario/test plan and this release-gate policy.
- agent-ready principal, assignment, OpenFGA, OPA, audit/event, Platform API/MCP and scoped-direct-Git compatibility seams for AGENT-001–006, together with the AGENT-007 non-goal.

### `GATE-P0-APPROVED` pass criteria

1. The directive version/checksum and complete requirement-ID inventory are recorded.
2. Every requirement ID maps to an owned issue, documentation and stable planned test ID or an explicit non-automation rationale allowed by TEST-001.
3. Every implementation issue contains the directive-mandated owner, dependencies, module/directories, prohibited boundaries, acceptance, tests, authorization/classification, observability/audit, migration/compatibility, upgrade/rollback and documentation fields.
4. Every contract has exactly one edit owner at a time and named consumers/reviewers; overlaps name an integration owner.
5. All required Phase 0 artifacts are internally consistent, versioned, dependency-complete, and have no unresolved Critical/High **Phase 0 artifact defect**. Open implementation risks in the threat register are acceptable at Phase 0 only when they have an owned control/test/release gate; they remain blockers for the applicable executable milestone.
6. Genuine unresolved implementation choices are either resolved by approved ADR or explicitly deferred with a decision deadline before the dependent issue. Locked decisions are not relabeled as open choices.
7. The golden plan covers all 16 TEST-009 steps, the Phase 1 architecture proof, the complete TEST-004 matrix, direct paths, events, audit, backup/restore and upgrade without implementing features.
8. Principal contracts accept `user`, `agent`, and `service_account`; assignment does not expose Gitea’s user-only limitation as canonical; OpenFGA reserves agent and explicit delegation/task/resource/revocation seams; OPA inputs reserve principal type and runtime domain/ceiling/compartment/model-provider/tool-scope/execution-environment context; events/audit preserve `requested_by` and `actor`; API/MCP/direct-Git boundaries are specified.
9. The Phase 0 scope audit proves no agent execution/orchestration/prompting/model-hosting/memory/A2A-dispatch/full-MCP implementation or mandatory model/SDK/provider dependency was introduced.
10. Distinct independent QA and security reviewer identities verify completeness and contradiction checks from source, not only author summaries.
11. The project owner records `APPROVED` against the exact commit/tag and artifact versions. Merge, publication, silence, or partial sign-off is not approval.

On pass, only dependency-ready Phase 1 issues are unblocked. Phase 0 approval does not pre-approve their implementation, dependencies, contracts, security behavior, or release.

## Candidate state machine

```text
DRAFT
→ FROZEN (exact commit, inputs, versions and digests)
→ EVIDENCE_RUNNING
→ QA_REVIEW
→ SECURITY_REVIEW
→ APPROVED
→ PUBLISHED

Any failure or invalidated evidence → HOLD
Integrity/licensing/supply-chain concern → QUARANTINED
Material change after FROZEN → new candidate identity and fresh affected gates
```

Only the release manager moves a candidate after verifying the required signed disposition. `HOLD` is not a release. `QUARANTINED` artifacts cannot be promoted, signed as approved, installed by supported automation, or included in an air-gap bundle.

## Release evidence manifest

One machine-readable, signed manifest is the index to all evidence. It contains at least:

- candidate/release ID, source commit, build identity, timestamps and target release channel;
- exact image, chart, CLI/archive, web, air-gap and other artifact digests;
- dependency manifests/lockfiles, approved-dependency snapshot, SPDX 3.0 SBOMs, third-party notices and license scan;
- checksums, signatures, verification material and SLSA-compatible provenance bound to the same digests;
- platform, database/schema, OpenFGA model, OPA bundle, label profile, OpenAPI/AsyncAPI/schema, Gitea/provider, browser, Kubernetes/Helm/Compose and fixture versions;
- requirement-to-implementation-to-test-to-document status snapshot;
- every required test ID, applicability, result, first-failure/retry history and evidence reference;
- unit/branch, policy decision-table/mutation, provider contract, accessibility, performance, vulnerability, secret, SAST, image, IaC, fuzz and chaos reports;
- install, `platformctl doctor`, backup, restore, upgrade, forward-recovery/rollback and compatibility reports;
- audit-event completeness and telemetry/protected-content canary results;
- when agent-compatible or agent functionality is in scope, principal/delegation/task/revocation and trusted runtime-context versions plus requester/actor attribution and API/MCP/scoped-Git boundary results;
- open defects, accepted residual risks, time-bounded waivers and their approvals/expiry/remediation issues;
- implementation-owner attestation and separate architecture, QA, security, legal (when applicable), and project-owner identities/dispositions.

Evidence must be immutable or tamper-evident, access-controlled to its effective security domain/label, reproducible from documented commands and inputs, and retained by policy. It contains no credentials or unnecessary protected bodies. Sanitization cannot remove the values needed to prove which candidate, policy, test and denial were evaluated.

## Required gates

All gates are cumulative. `PASS` means the exact candidate has complete, successful evidence; `N/A` requires a directive-consistent applicability reason approved by QA and the relevant owner. A required test cannot be made `N/A` merely because it is unimplemented, flaky, costly, or failing.

| Gate | Directive basis | Pass evidence | Absolute failure examples | Approval |
|---|---|---|---|---|
| `RG-00-CANDIDATE` Candidate freeze | §0, §22 | Exact commit/input/artifact/contract/provider versions and signed evidence-manifest skeleton; change freeze | Mutable tag, unpinned input, missing artifact, evidence from a different digest | Release manager + QA |
| `RG-01-TRACE` Requirements traceability | TEST-001 | Machine-readable `requirement_id → implementation_modules → test_ids → documentation → status → release`; every completed requirement has acceptance evidence or allowed automation rationale | Missing requirement ID, orphan implementation/test, false complete status, issue missing mandatory fields | Independent QA |
| `RG-02-LAYERS` Complete test layers | TEST-002 | Applicable unit, property, OpenFGA, OPA, schema, provider contract, module integration, event, browser E2E, accessibility, security, classification, performance, migration, upgrade, install, backup/restore, chaos and parser fuzz suites all pass | Any applicable suite absent or required test failed/flaky on final run | Independent QA; security co-approval for security layers |
| `RG-03-COVERAGE` Coverage and regression floors | TEST-003 | Core Go ≥80% line and branch; authorization/classification 100% decision-table/policy-rule coverage and ≥90% critical-policy mutation score; provider ≥80% plus full contracts; critical UI flows E2E; every prior security/data-loss defect has regression | Below floor, excluded critical rule, missing regression, coverage computed on wrong candidate | QA + security for policy/regression evidence |
| `RG-04-CLASS` Authorization/classification matrix | TEST-004, CLS-006–008, AGENT-001–006 | Every mandated allow/deny, propagation, direct-provider, non-disclosure, backup/log, runner and cross-domain case passes; all applicable `CBI-*` rows `VERIFIED`; agent-capable releases also prove no broad human inheritance, the six-way authority intersection, independent revoke and external-runtime context | Admin/agent bypass, stale label/permission/delegation allow, metadata leak, lower runner/runtime access, direct provider exceeds policy, cross-domain export | Independent security; QA witnesses reproducibility |
| `RG-05-EVENT` Event reliability/security | TEST-005, EVT-001–004 | Atomic outbox, retry idempotency, restart, DLQ/replay, out-of-order safety, schema compatibility, subject authorization and projection rebuild pass | Acknowledged mutation without recoverable outbox; duplicate side effect; unauthorized subscription; corrupt replay | QA + security for subject/content controls |
| `RG-06-PROVIDER` Provider compatibility | TEST-006, SCM-001–005, DOC-002–003 | Full Gitea capability suite on pinned current and previous two supported minors; RC/nightly signal when available; Commonplace/OKF compatibility where applicable; no internal DB/file use | Failed declared-version contract, webhook signature failure, permission-sync bypass, hidden direct DB dependency | QA + architecture; security for permission paths |
| `RG-07-INSTALL-UPGRADE` Installation, air gap and upgrade | TEST-007, DEP-001–005 | Fresh local Compose and lightweight Kubernetes; external DB/object profile; optional OpenSearch when claimed; network-disabled air gap when applicable; all supported prior platform/Gitea upgrades; failure recovery; doctor; Helm schema/tests | Undocumented egress, unsupported claimed profile/version, failed migration/rollback recovery, missing backup/preflight | QA + security for profile/domain controls |
| `RG-08-SECURITY` Security and supply-chain blockers | TEST-008, SEC-001–006, CICD-002–005 | No unwaived Critical/High vulnerability; no known disclosure; authz/classification, audit, backup/restore and install/upgrade green; approved licenses; scans; SBOM/signatures/provenance/checksums/notices present | Any TEST-008 failure condition; secret in artifact/evidence; signature not bound to candidate | Independent security + independent QA; legal where applicable |
| `RG-09-GOLDEN` Golden end-to-end | TEST-009 | One uninterrupted traceable run of `GVS-001`–`GVS-016` from supported install through auth, work/docs/code/PR/build/release/search/non-disclosure, backup/restore, upgrade and repeated checks | Any functional, direct-path, non-disclosure, event, audit, restore, upgrade or post-upgrade assertion fails | Independent QA + independent security |
| `RG-10-OPERABILITY` Reliability, observability and recovery | OPS-001–005, §22 | OTel traces/metrics/logs with safe context; health/doctor; published load fixtures/targets; graceful-degradation/chaos; complete backup/restore; runbooks and alerts | Protected body/secret in telemetry, acknowledged write loss, unavailable recovery, unpublished benchmark basis | QA + security + WS-12 review |
| `RG-11-COMPAT-DOCS` Compatibility, migration, rollback and documentation | ARCH-005, MIG-001–005, DEP-005, §22 | API/event/schema compatibility and deprecation; migration behavior/provenance; upgrade/rollback constraints; operator/user/contributor/security docs; canonical export/import/redirect tests | Silent data loss, unreported unsupported construct, breaking change without version/migration period, undocumented irreversible migration | QA + architecture + security where data flow changes |
| `RG-12-FINAL` Final disposition | §0, TEST-008, §22 | All earlier gates pass; waivers valid; no blocking defect; golden green; exact manifest signed; independent QA and security both explicitly approve | Self-approval, missing approver, veto, expired waiver, candidate changed after evidence | Independent QA **and** independent security; release manager verifies |

### TEST-001 through TEST-009 coverage

| TEST requirement | Enforcing gate(s) | Required outcome |
|---|---|---|
| TEST-001 Requirements traceability | RG-01 | Complete machine-readable matrix; no falsely complete requirement |
| TEST-002 Test layers | RG-02 | All 19 applicable suite classes execute and pass |
| TEST-003 Coverage floors | RG-03 | Numeric floors, full provider contracts, critical E2E and regressions pass |
| TEST-004 Classification security matrix | RG-04 and RG-08 | Every listed deny/allow/propagation/bypass case passes with no existence leak |
| TEST-005 Event tests | RG-05 | Atomicity, retry, restart, DLQ/replay, order, compatibility, subject ACL and rebuild pass |
| TEST-006 Provider tests | RG-06 | Complete Gitea and applicable Commonplace compatibility contracts pass |
| TEST-007 Installation/upgrade tests | RG-07 | Every required topology/profile/version/recovery test passes |
| TEST-008 Security release gates | RG-08 and RG-12 | No enumerated blocker remains; only explicitly permitted vulnerability waiver may apply |
| TEST-009 Golden scenario | RG-09 | All 16 ordered scenario steps and cross-cutting assertions pass |

## Golden scenario rules

The approved [`golden-vertical-slice.md`](../testing/golden-vertical-slice.md) is a release-blocking executable specification. Phase 0 approves its contract only. The Phase 1 architecture proof runs the directive’s thin slice through identity, shared authorization, Project, Gitea-backed Work Item, Git/OKF Document, code repository/PR, NATS/outbox, inbox, PostgreSQL search, audit and local installation. It is an engineering milestone and may not be represented as a production release if the full release obligations are not met.

Every actual release candidate runs the complete TEST-009 sequence, including Action/build/SBOM/artifact/release visibility, non-disclosure, backup/restore, supported upgrade and repeated post-upgrade checks. A split run assembled from different candidates, fixtures, policy versions or restored states does not satisfy the golden gate.

## Defects, failures and retests

| Classification | Result |
|---|---|
| Known unauthorized disclosure, cross-domain/write-down, authz/classification bypass, acknowledged-write loss, corrupt/unrestorable backup, missing mandatory audit | `HOLD`; no ordinary waiver; fix and rerun affected plus full security/golden regression |
| Required test failure | `HOLD`; preserve first failure; fix and produce a fresh candidate/run |
| Flaky required test | Treat as failure until root cause is fixed or the test is deterministically replaced with equal/stronger coverage and reviewed |
| Critical/High vulnerability | `HOLD` unless the narrow TEST-008 time-bounded waiver below is approved |
| Unknown/disallowed distributed license or missing obligation | `QUARANTINED`; remove/replace or complete ADR + legal + project-owner approval, rebuild, and rerun |
| Missing/tampered/unbound SBOM, signature, provenance, checksum or evidence | `QUARANTINED`; regenerate from trusted inputs and rerun |
| Medium/Low defect | Release manager records disposition; QA/security decide gate relevance based on confidentiality, integrity, availability and requirement impact; it cannot mask a required-test failure |
| Documentation-only error in required safety/migration/rollback instructions | `HOLD` until corrected and independently verified |

A failed test cannot be deleted, weakened, reclassified as non-required, or have its oracle changed solely to make the candidate pass. Such changes require requirement/contract review and evidence that coverage remains at least equivalent.

## Waiver policy

The only ordinary TEST-008 waiver is for a specific Critical/High vulnerability that has a documented, time-bounded waiver. It requires:

- exact vulnerability/component/artifact/version/digest and affected deployment profiles;
- exploitability and reachability evidence for the candidate’s actual configuration;
- impact analysis including authorization/classification and air-gap contexts;
- compensating controls that are implemented and tested, not merely planned;
- named remediation owner, issue, fixed deadline and maximum affected release scope;
- upgrade and rollback/removal plan;
- explicit security recommendation and independent QA verification;
- project-owner risk acceptance;
- machine-readable evidence-manifest entry and release notes/known-issue disclosure appropriate to the audience.

The implementation owner cannot request and approve the same waiver. Expiry automatically blocks subsequent promotion/install/update through supported channels until remediation or a newly reviewed decision. Renewal is a new waiver with new evidence; a waiver does not silently become policy.

The following are not waivable under this release process:

- any failed required test or unmet coverage floor;
- a known unauthorized disclosure or direct-provider/classification bypass;
- a cross-domain/write-down route in core;
- failed OpenFGA/OPA model/policy tests or a fail-open decision path;
- failed backup/restore, install, upgrade or mandatory audit coverage;
- unknown or unapproved-disallowed distributed license;
- missing SBOM, required third-party notices, signature, checksum or provenance;
- an unapproved dependency, locked-decision change, ontology change or direct upstream database access;
- missing independent QA/security approval or self-approval.
- broad human permission inheritance by an agent, missing independent agent/task revocation, provider-business-API bypass, or conflated requester/actor attribution when agent functionality is in scope.

TEST-001 permits an explicit reason when an automated acceptance test is impossible. That is not a release waiver: the reason must be approved during contract review, a stable manual or analytic verification procedure and evidence must be defined, and independent QA/security must execute/review it for every applicable candidate. “Not implemented,” expense, flakiness and schedule are not valid impossibility reasons.

## Approval record

Each gate records one of `PASS`, `FAIL`, or `N/A` with reviewer identity, independence attestation, timestamp, candidate digest, evidence references, comments and signature. Final approval is valid only when all required gates are `PASS`, all `N/A` entries have approved applicability rationales, every waiver is valid, and QA and security sign the exact same manifest digest.

The release manager then records `PUBLISHED` with repository/registry locations and immutable digests. If later evidence shows a gate was false, inputs were compromised, or a waiver expired, the release is marked affected, artifacts are quarantined/revoked as appropriate, supported-channel promotion stops, and the project publishes recovery guidance. Approval history remains append-only.

## Phase-specific application

- **Phase 0:** `GATE-P0-APPROVED` only; contracts and test specifications are approved. AGENT-001–006 compatibility seams are reviewed, while AGENT-007 prohibits agent execution/orchestration/prompting/model hosting/memory/`AgentRun`/A2A dispatch/full MCP catalog. No feature implementation or product release is implied.
- **Phase 1 architecture proof:** Phase 0 must already pass. Run the complete thin vertical-slice subset defined by the golden plan plus all gates applicable to changed executable components. It validates architecture but cannot claim production completeness.
- **Phase 2 Pilot/Beta:** All candidate gates apply to delivered scope and every public release runs full TEST-009. Beta status does not relax authorization, disclosure, licensing, recovery or independent approval.
- **Phase 3 Production 1.0:** All gates and claimed profiles apply, including air-gap, OSCAL artifact accuracy, real-time collaboration, OpenSearch/HA when shipped, tamper-evident audit, supply-chain outputs and production SLO evidence.
- **Patch/security release:** All safety, traceability, supply-chain, upgrade/rollback and golden gates still apply. The relevant regression suite expands; urgency does not create self-approval or fail-open authority.
