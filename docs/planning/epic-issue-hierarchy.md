# Stead epic and issue hierarchy

Status: Phase 0 baselined; Phase 1 foundation active<br>
Normative source: `docs/architecture/MASTER_BUILD_DIRECTIVE.md`

This hierarchy decomposes the directive without changing its locked architecture or fixed ontology. The exhaustive requirement-to-issue mapping is in [the traceability register](../../specs/traceability/requirements.yaml). The complete machine-readable issue contracts are in [the implementation issue catalog](implementation-issue-catalog.yaml).

Deferred implementation choices are enforced by the [ADR candidate implementation-gate index](../governance/adr-candidate-index.md). Passing `GATE-P0-APPROVED` does not waive a candidate's issue-specific decision deadline.

## Controlling rule

Phase 0 contract, architecture, planning, threat-model, test-design, and governance work is baselined at tag `phase0`. ADR-0002 through ADR-0006 are accepted at immutable decision revision `24c74d52ef0a78840ab147da48c3d66589e49e3e`; this does not resolve another ADR candidate or supply implementation evidence. `STEAD-P1-001` is `COMPLETED_PHASE_1`; later Phase 1 issues remain `DEPENDENCY_BLOCKED` until their exact remaining dependencies and ADR gates pass, and every Phase 2–3 issue is `PHASE_GATED`.

`GATE-P0-APPROVED` is `APPROVED` against tag `phase0`, immutable commit `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31`, with the five dispositions recorded in the closeout packet. The gate opens dependency-ready work only. Any proposed change to a locked decision still requires its own ADR and project-owner approval.

## Epic hierarchy

```text
Stead
├── EPIC-P0-A  Constitution and canonical contracts
│   ├── STEAD-P0-001  Architecture constitution and guardrails
│   ├── STEAD-P0-002  OWGP and canonical schemas
│   └── STEAD-P0-003  Runtime, database, and transaction boundaries
├── EPIC-P0-B  Integration and cross-cutting contracts
│   ├── STEAD-P0-004  Gitea provider contract
│   ├── STEAD-P0-005  Knowledge/Commonplace contract
│   ├── STEAD-P0-006  Unified UX contract
│   ├── STEAD-P0-007  Identity/authorization/classification contract
│   ├── STEAD-P0-008  Events/activity/inbox/audit contract
│   ├── STEAD-P0-009  Search/work-graph/MCP contract
│   ├── STEAD-P0-011  Storage contract
│   ├── STEAD-P0-010  CI/runner/artifact/secret contract
│   ├── STEAD-P0-012  Migration contract
│   └── STEAD-P0-015  Agent-ready compatibility seams and Phase 0 non-goal
├── EPIC-P0-C  Operational assurance and approval
│   ├── STEAD-P0-013  Deployment/operations/upgrade/restore contract
│   └── STEAD-P0-014  Traceability/threat/golden/release-gate package
├── GATE-P0-APPROVED  Approved at phase0 / e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31
├── EPIC-P1  Executable vertical slice [FOUNDATION ACTIVE]
├── EPIC-P2  Pilot/Beta [PHASE GATED]
└── EPIC-P3  Production 1.0 [PHASE GATED]
```

## Phase 0 dependency order

The rows are topologically ordered. Issues in the same wave may proceed concurrently only when their owned contracts and directories do not overlap.

| Wave | Issue | Owner | Depends on | Contract result and requirement coverage |
|---:|---|---|---|---|
| 0 | STEAD-P0-001 | WS-01 | none | Canonical directive/reconciliation, constitution, 30 locked decisions, repository layout, standards/license guardrails; PRIN-001…015, ARCH-001…005 |
| 1 | STEAD-P0-002 | WS-01 | P0-001 | OWGP v0.1, open-work entities/relationships, Team/Project/container/capability/lifecycle schemas/examples and compatibility; STD-001…002, DOM-001…011 |
| 2 | STEAD-P0-003 | WS-02 | P0-001, P0-002 | Runtime responsibilities, module/table ownership, provider ports, work-item ownership, transactions and the transactional outbox; ARCH-003…004, DOM-004, EVT-002 |
| 3 | STEAD-P0-004 | WS-03 | P0-001…003 | Capability-scoped Gitea interfaces, tracker mapping, reconciliation, provider enforcement and compatibility; SCM-001…006 |
| 4 | STEAD-P0-005 | WS-04 | P0-001, P0-002, P0-004 | Git/OKF knowledge and document model, Commonplace upstream/patch/fallback, review and repository security boundary; DOM-005, DOC-001…005 |
| 4 | STEAD-P0-007 | WS-06 | P0-001…004 | OIDC/SCIM, groups/principals, hierarchy non-inheritance, OpenFGA v0.1, policy-decision layer I/O/agent intersection, label lattice, domains, downgrade and bypass; PRIN-007,011–012,015, DOM-007,009–010, AUTH-001…006, CLS-001…008 |
| 5 | STEAD-P0-006 | WS-05 | P0-001, P0-002, P0-005 | Universal/capability IA, presets, object surface, six persona flows, design constitution, Devlane boundary, markings/accessibility/performance; PRIN-001,013–014, DOM-008,011, UX-001…009 |
| 5 | STEAD-P0-008 | WS-07 | P0-002, P0-003, P0-007 | CloudEvents/AsyncAPI, NATS and the WS-02 outbox publisher/consumer binding, delivery, activity, inbox, notification and audit contracts; EVT-001,003…004, ACT-001, NOTIF-001…002, AUD-001…002 |
| 5 | STEAD-P0-011 | WS-10 | P0-002, P0-007 | BlobStore, portable object metadata, authorized URL, retention, scan and partition contracts; STOR-001…003; supports WS-09's ART-001 integration through the BlobStore port |
| 6 | STEAD-P0-009 | WS-08 | P0-002, P0-007, P0-008 | Multi-resource SearchProvider, Work Graph, non-disclosing query/rebuild, contract-only MCP/A2A seams; DOM-010, AUTH-006, SRCH-001…003, GRAPH-001…002 |
| 6 | STEAD-P0-010 | WS-09 | P0-004, P0-007, P0-008, P0-011 | OCI/package integration, Actions, internal catalog, runners, artifact/provenance and SecretProvider contracts; ART-001, CICD-001…005 |
| 6 | STEAD-P0-012 | WS-11 | P0-002, P0-004, P0-005, P0-007, P0-011 | Resumable migration stages, mappings, preservation, reconciliation, cutover and redirects; MIG-001…005 |
| 7 | STEAD-P0-013 | WS-12 | P0-003, P0-004, P0-007, P0-008, P0-010, P0-011 | Infrastructure-agnostic/simple operation, install profiles, steadctl, Helm/air-gap, OTel/health, backup/restore and safe upgrades; PRIN-008…009, DEP-001…005, OPS-001…005 |
| 7 | STEAD-P0-015 | WS-01 | P0-002, P0-003, P0-004, P0-007, P0-008, P0-009 | Principal/assignment seams, agent-ready auth/classification, dual actor/requester event and audit fields, API/MCP/scoped-Git boundary, future A2A direction, and the Phase 0 runtime non-goal; AGENT-001…007 |
| 8 | STEAD-P0-014 | WS-13 | P0-001…013, P0-015 | 128-ID traceability, 33-threat/47-bypass baseline, license/scope gates, TEST-009/010 plans, closeout packet and independent approval rules; PRIN-010, SEC-001…006, TEST-001…010, AGENT-001…007 |
| 9 | GATE-P0-APPROVED | Project owner + WS-01 + WS-06 + distinct independent WS-13 QA/security identities | P0-001…015 | Recorded approval of every Phase 0 artifact; opens, but does not complete, Phase 1 |

## Phase 1 executable vertical slice

`STEAD-P1-001` is complete. All later Phase 1 issues remain dependency/ADR-gated; the ordering deliberately establishes central authorization before any provider-backed protected workflow.

The Phase 1 records preserve the approved principal, assignment, authorization, audit/event, API/MCP, scoped-Git, and classification seams. They implement the standard `request_boundary` vertical path, reserve typed `commit_boundary` seams, and establish performance instrumentation before feature expansion. They do not implicitly authorize agent orchestration, prompting, model hosting, agent memory, AgentRun execution, or A2A dispatch.

| Order | Issue | Owner | Direct predecessors | Deliverable |
|---:|---|---|---|---|
| 1 | STEAD-P1-001 | WS-01 | GATE-P0-APPROVED | Root manifests, CI and contract-test foundation, schema/API lint, dependency approvals/notices, and Devlane provenance |
| 2 | STEAD-P1-015 | WS-02, with WS-06/07 handoff | GATE-P0-APPROVED, P1-001, accepted ADR-CAND-003/007, and unresolved ADR-CAND-002 | Owner-scoped one-operation request-boundary authorization/audit composition, `core_outbox` and durable-effect ports, plus typed strict-mode coordination seams; no domain feature implementation or strict persistence prerequisite |
| 2 | STEAD-P1-016 | WS-09 | GATE-P0-APPROVED, P1-001, accepted ADR-CAND-007 | Deterministic policy activation archive, pre-signing evidence, post-signing release attestation, and immutable writer/fixture handoff; no runtime activation authority |
| 3 | STEAD-P1-006 | WS-06 | P1-001, P1-015, P1-016, accepted security ADRs | Bootstrap/OIDC identity; central set-oriented OpenFGA + policy path; signed profile-neutral mode selection; complete `request_boundary`; typed `commit_boundary` seam |
| 4 | STEAD-P1-002 | WS-02 | P1-001, P1-006, P1-015, approved core/auth contracts | Canonical modular core, PrincipalRef-based User/Agent Work assignment, PostgreSQL ownership, bounded composed-read queries, optimistic concurrency and atomic outbox |
| 5 | STEAD-P1-003 | WS-03 | P1-002, P1-006 | Stock Gitea adapter, hidden tracker/board, provider-neutral Work backing, docs Git, and local rebuildable provider projection; no general code repo or ordinary-read provider waterfall |
| 5 | STEAD-P1-010 | WS-10 | P1-002, P1-006 | Filesystem BlobStore and authorized attachment path |
| 5 | STEAD-P1-007 | WS-07 | ADR-CAND-006, P1-002, P1-006 | Transactional outbox commit with post-response JetStream relay; set-oriented activity/inbox; one aggregate composed-read audit |
| 6 | STEAD-P1-004 | WS-04 | P1-002, P1-003, P1-006, P1-010 | One deterministic Git/OKF document flow |
| 6 | STEAD-P1-008 | WS-08 | ADR-CAND-006, P1-002, P1-006, P1-007 | PostgreSQL search/work-graph baseline with non-disclosure, set-oriented call-count tests, and 300 ms first-results target |
| 7 | STEAD-P1-005 | WS-05 | P1-002, P1-003, P1-004, P1-006, P1-007, P1-008 | Responsive universal shell, one composed primary request, ≤250 KiB eager JavaScript, and complete TEST-009 general Work+Docs path |
| 8 | STEAD-P1-013 | WS-03 | P1-003, P1-005, P1-006 | Additive software code repository, branch, commit and Pull Request path |
| 9 | STEAD-P1-009 | WS-09 | P1-006, P1-007, P1-010, P1-013 | One pinned Action with build/SBOM/artifact/release trace |
| 10 | STEAD-P1-014 | WS-05 | P1-004, P1-007…009, P1-013 | Present Code and Delivery in the same shell; complete TEST-010 UI path |
| 11 | STEAD-P1-011 | WS-12 | P1-001…010, P1-013…016 | One-command local install, OTel/health/doctor, policy activation operations, and backup/restore baseline |
| 12 | STEAD-P1-012 | WS-13 | P1-001…011, P1-013…016 | Independently gate TEST-009 before TEST-010; standard performance/call-count evidence; request-boundary security; strict seam; policy activation, bypass, restore and upgrade |

No Phase 2 issue opens merely because its implementation dependency is merged. The Phase 1 candidate must pass STEAD-P1-012 and receive its recorded release decision.

## Phase 2 Pilot/Beta

These issues are `PHASE_GATED` and depend on successful Phase 1 independent validation and its recorded release decision.

| Order | Issue | Owner | Direct predecessors | Deliverable |
|---:|---|---|---|---|
| 1 | STEAD-P2-001 | WS-03 | P1-012 | Gitea governance, direct-path enforcement and support matrix |
| 1 | STEAD-P2-002 | WS-04 | P1-012 | Commonplace integration or ADR-approved native fallback; controlled review |
| 1 | STEAD-P2-003 | WS-05 | P1-012 | Mature unified UX, markings and critical-flow WCAG 2.2 AA |
| 1 | STEAD-P2-004 | WS-06 | P1-012 | Trusted attributes, signed label profiles, propagation/downgrade and bypass suite |
| 1 | STEAD-P2-005 | WS-07 | P1-012 | Full inbox/channels and platform-wide audit coverage |
| 1 | STEAD-P2-006 | WS-08 | P1-012 | Complete search/Work Graph, Agent Registry, and permission-aware MCP/A2A beta |
| 1 | STEAD-P2-007 | WS-09 | P1-012 | Secure runner pools, approved actions, artifact and secret integration |
| 1 | STEAD-P2-008 | WS-10 | P1-012 | Filesystem/S3/Azure/GCS BlobStore contract conformance |
| 1 | STEAD-P2-009 | WS-11 | P1-012 | GitHub/Jira/Confluence discovery, dry run and initial import |
| 1 | STEAD-P2-010 | WS-12 | P1-012 | Kubernetes/Helm/external-services, backup/restore, upgrade and performance baseline |
| 2 | STEAD-P2-011 | WS-13 | P2-001…010 | Independent Pilot/Beta quality and security gate |

## Phase 3 Production 1.0

These issues are `PHASE_GATED` and depend on the successful Pilot/Beta gate.

| Order | Issue | Owner | Direct predecessors | Deliverable |
|---:|---|---|---|---|
| 1 | STEAD-P3-001 | WS-04 | P2-011 | Lossless Yjs real-time document collaboration |
| 1 | STEAD-P3-002 | WS-06 | P2-011 | External-regime/high-assurance profiles, WS-06 strict `commit_boundary` runtime, policy-selected assurance evidence, and cross-domain denial |
| 1 | STEAD-P3-003 | WS-07 | P2-011 | Tamper-evident audit checkpoints and production exports |
| 1 | STEAD-P3-004 | WS-08 | P2-011 | OpenSearch scale profile and production permission-aware MCP |
| 1 | STEAD-P3-005 | WS-09 | P2-011 | Signed SBOM/provenance/checksum/notices/scanning release set |
| 1 | STEAD-P3-006 | WS-11 | P2-011 | Delta sync, cutover, source transition and permanent redirects |
| 1 | STEAD-P3-007 | WS-12 | P2-011 | High-assurance air-gap, HA, strict egress/quiescence operations, separate commit-boundary benchmark, upgrade matrix and production SLO validation |
| 2 | STEAD-P3-008 | WS-13 | P3-001…007 | Independent Production 1.0 security and release decision |

## Mandatory issue contract

Every issue in the machine-readable catalog explicitly states:

- requirement IDs and one accountable owner;
- dependencies, module, and owned directories;
- prohibited boundaries;
- measurable acceptance criteria and named automated tests;
- expected request count, SQL behavior, provider calls, authorization strategy, synchronous writes, frontend bundle impact, and benchmark or concrete not-sensitive reason;
- authorization and classification behavior;
- observability and audit requirements;
- migration and backward-compatibility implications;
- upgrade and rollback behavior;
- documentation obligations.

Any future child implementation issue must restate these fields with a narrower scope. It may not rely on a parent link as a substitute. An implementation issue remains incomplete until its tests, documentation, observability, migration, authorization, classification, audit, upgrade, rollback, and independent review obligations are satisfied.

## Agent-ready compatibility boundary

Phase 0 models identity as a principal union containing at least `user`, `agent`, and `service_account`; permits an agent principal in canonical work-item assignment; reserves agent relationships and future delegation/task/runtime inputs in OpenFGA and the policy-decision layer; and lets CloudEvents and audit records distinguish an acting principal from the initiating/requesting principal.

Future agent business access is through canonical Platform APIs and the platform-wide MCP boundary. Scoped direct Git credentials are the only permitted direct provider path. Phase 0 delivers only the canonical Agent/AgentRun schemas and MCP/A2A compatibility contracts; MCP tools, A2A dispatch, Agent Registry behavior, and agent execution remain out of scope.

The future authorization result must be capable of intersecting delegator authority, agent-specific authority, task scope, runtime security domain, session/environment constraints, and resource classification/handling rules. The compatibility schema grants no authority by itself.

Phase 0 explicitly excludes implementation of agent orchestration, prompting, model hosting, memory, AgentRun execution, A2A dispatch, and a full MCP tool catalog. Introducing any of them requires a separately approved post-Phase-0 issue and any applicable ADR; it cannot be smuggled into a schema or integration task.

## Gate semantics

- Phase 0 review can reject, amend, or approve a contract. Amendments that alter a locked decision require an ADR and project-owner approval.
- WS-13 is independent of the implementation owner and may not approve its own implementation.
- A missing test, release artifact, required audit event, backup/restore result, install/upgrade result, clean license decision, or unresolved unauthorized-disclosure path fails the applicable candidate.
- A waiver for a critical/high vulnerability must be documented, authorized, and time bounded. There is no waiver for a known unauthorized disclosure path.
- Passing one phase does not waive unmet requirements assigned to a later release; the traceability register remains authoritative for release targeting.
