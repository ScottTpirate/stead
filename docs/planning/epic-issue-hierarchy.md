# Stead epic and issue hierarchy

Status: Phase 0 planning draft<br>
Normative source: `unified_open_work_platform_master_build_directive.md`

This hierarchy decomposes the directive without changing its locked architecture or fixed ontology. The exhaustive requirement-to-issue mapping is in [the traceability register](../../specs/traceability/requirements.yaml). The complete machine-readable issue contracts are in [the implementation issue catalog](implementation-issue-catalog.yaml).

## Controlling rule

Only Phase 0 contract, architecture, planning, threat-model, test-design, and governance work is authorized. Every Phase 1, Phase 2, and Phase 3 issue has status `BLOCKED_PENDING_PHASE_0_APPROVAL`.

`GATE-P0-APPROVED` remains `PENDING` until WS-01 records architecture approval, WS-06 records security-contract approval, two distinct independent WS-13 reviewer identities record separate QA and security approvals, and the project owner approves all required Phase 0 artifacts. Approval must be recorded against the same immutable revision; a merged draft, passing formatter, or implementation-owner review is not approval. Any proposed change to a locked decision requires its own ADR and project-owner approval.

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
├── GATE-P0-APPROVED  Project owner + WS-01 + WS-06 + distinct independent WS-13 QA/security approvals
├── EPIC-P1  Executable vertical slice [BLOCKED]
├── EPIC-P2  Pilot/Beta [BLOCKED]
└── EPIC-P3  Production 1.0 [BLOCKED]
```

## Phase 0 dependency order

The rows are topologically ordered. Issues in the same wave may proceed concurrently only when their owned contracts and directories do not overlap.

| Wave | Issue | Owner | Depends on | Contract result and requirement coverage |
|---:|---|---|---|---|
| 0 | STEAD-P0-001 | WS-01 | none | Constitution, precedence, locked decisions, repository layout, standards/license guardrails; PRIN-001…012, ARCH-001…005 |
| 1 | STEAD-P0-002 | WS-01 | P0-001 | OWGP v0.1, resource/entity/relationship schemas, cardinality, conformance and compatibility; STD-001…002, DOM-001…007 |
| 2 | STEAD-P0-003 | WS-02 | P0-001, P0-002 | Runtime responsibilities, module/table ownership, provider ports, work-item ownership, transactions and the transactional outbox; ARCH-003…004, DOM-004, EVT-002 |
| 3 | STEAD-P0-004 | WS-03 | P0-001…003 | Capability-scoped Gitea interfaces, tracker mapping, reconciliation, provider enforcement and compatibility; SCM-001…006 |
| 4 | STEAD-P0-005 | WS-04 | P0-001, P0-002, P0-004 | Git/OKF knowledge and document model, Commonplace upstream/patch/fallback, review and repository security boundary; DOM-005, DOC-001…005 |
| 4 | STEAD-P0-007 | WS-06 | P0-001…004 | Secure-default/open-security/no-cross-domain principles, OIDC/SCIM, OpenFGA v0.1, OPA I/O, trusted attributes, label lattice, security domains, downgrade and bypass rules; PRIN-007,011–012, AUTH-001…005, CLS-001…008, DOM-007 |
| 5 | STEAD-P0-006 | WS-05 | P0-001, P0-002, P0-005 | One product experience, sole shell, project views, interaction vocabulary, markings, accessibility and performance; PRIN-001, UX-001…005 |
| 5 | STEAD-P0-008 | WS-07 | P0-002, P0-003, P0-007 | CloudEvents/AsyncAPI, NATS and the WS-02 outbox publisher/consumer binding, delivery, activity, inbox, notification and audit contracts; EVT-001,003…004, ACT-001, NOTIF-001…002, AUD-001…002 |
| 5 | STEAD-P0-011 | WS-10 | P0-002, P0-007 | BlobStore, portable object metadata, authorized URL, retention, scan and partition contracts; STOR-001…003; supports WS-09's ART-001 integration through the BlobStore port |
| 6 | STEAD-P0-009 | WS-08 | P0-002, P0-007, P0-008 | SearchProvider, work-graph projection, non-disclosing query plan, rebuild and MCP contract; SRCH-001…003, GRAPH-001…002 |
| 6 | STEAD-P0-010 | WS-09 | P0-004, P0-007, P0-008, P0-011 | OCI/package integration, Actions, internal catalog, runners, artifact/provenance and SecretProvider contracts; ART-001, CICD-001…005 |
| 6 | STEAD-P0-012 | WS-11 | P0-002, P0-004, P0-005, P0-007, P0-011 | Resumable migration stages, mappings, preservation, reconciliation, cutover and redirects; MIG-001…005 |
| 7 | STEAD-P0-013 | WS-12 | P0-003, P0-004, P0-007, P0-008, P0-010, P0-011 | Infrastructure-agnostic/simple operation, install profiles, platformctl, Helm/air-gap, OTel/health, backup/restore and safe upgrades; PRIN-008…009, DEP-001…005, OPS-001…005 |
| 7 | STEAD-P0-015 | WS-01 | P0-002, P0-003, P0-004, P0-007, P0-008, P0-009 | Principal/assignment seams, agent-ready auth/classification, dual actor/requester event and audit fields, API/MCP/scoped-Git boundary, future A2A direction, and the Phase 0 runtime non-goal; AGENT-001…007 |
| 8 | STEAD-P0-014 | WS-13 | P0-001…013, P0-015 | Testing-as-architecture, 115-ID traceability, threat and bypass baselines, license gates, scope guard, golden plan, test strategy, release gates and independent approvals; PRIN-010, SEC-001…006, TEST-001…009, AGENT-001…007 |
| 9 | GATE-P0-APPROVED | Project owner + WS-01 + WS-06 + distinct independent WS-13 QA/security identities | P0-001…015 | Recorded approval of every Phase 0 artifact; opens, but does not complete, Phase 1 |

## Phase 1 executable vertical slice

All issues below are planning records only and are blocked on `GATE-P0-APPROVED`. The ordering deliberately establishes central authorization before any provider-backed protected workflow.

The Phase 1 records preserve the approved principal, assignment, authorization, audit/event, API/MCP, scoped-Git, and classification seams. They do not implicitly authorize agent orchestration, prompting, model hosting, agent memory, AgentRun execution, or A2A dispatch.

| Order | Issue | Owner | Direct predecessors | Deliverable |
|---:|---|---|---|---|
| 1 | STEAD-P1-001 | WS-01 | GATE-P0-APPROVED | Locked monorepo/toolchains, schema/API lint, license/dependency guardrails |
| 1 | STEAD-P1-006 | WS-06 | GATE-P0-APPROVED | Bootstrap/OIDC identity and central OpenFGA + OPA decision path |
| 2 | STEAD-P1-002 | WS-02 | P1-001, approved core/auth contracts | Canonical modular core, PostgreSQL ownership, optimistic concurrency and atomic outbox |
| 3 | STEAD-P1-003 | WS-03 | P1-002, P1-006 | Stock Gitea adapter, tracker/board/work mapping, linked code and PR |
| 3 | STEAD-P1-010 | WS-10 | P1-002, P1-006 | Filesystem BlobStore and authorized attachment path |
| 3 | STEAD-P1-007 | WS-07 | P1-002, P1-006 | JetStream/outbox delivery and basic activity, inbox and audit |
| 4 | STEAD-P1-004 | WS-04 | P1-002, P1-003, P1-006, P1-010 | One deterministic Git/OKF document flow |
| 4 | STEAD-P1-008 | WS-08 | P1-002, P1-006, P1-007 | PostgreSQL search and work-graph baseline with non-disclosure |
| 4 | STEAD-P1-009 | WS-09 | P1-003, P1-006, P1-007, P1-010 | One pinned Action with build/SBOM/artifact/release trace |
| 5 | STEAD-P1-005 | WS-05 | P1-002, P1-003, P1-004, P1-006, P1-007, P1-008 | Sole unified shell and golden interactions |
| 6 | STEAD-P1-011 | WS-12 | P1-001…010 | One-command local install, OTel/health/doctor and backup/restore baseline |
| 7 | STEAD-P1-012 | WS-13 | P1-001…011 | Independent golden-slice, bypass, restore and upgrade gate |

No Phase 2 issue opens merely because its implementation dependency is merged. The Phase 1 candidate must pass STEAD-P1-012 and receive its recorded release decision.

## Phase 2 Pilot/Beta

These issues are `BLOCKED_PENDING_PHASE_0_APPROVAL` and also depend on successful Phase 1 independent validation.

| Order | Issue | Owner | Direct predecessors | Deliverable |
|---:|---|---|---|---|
| 1 | STEAD-P2-001 | WS-03 | P1-012 | Gitea governance, direct-path enforcement and support matrix |
| 1 | STEAD-P2-002 | WS-04 | P1-012 | Commonplace integration or ADR-approved native fallback; controlled review |
| 1 | STEAD-P2-003 | WS-05 | P1-012 | Mature unified UX, markings and critical-flow WCAG 2.2 AA |
| 1 | STEAD-P2-004 | WS-06 | P1-012 | Trusted attributes, signed label profiles, propagation/downgrade and bypass suite |
| 1 | STEAD-P2-005 | WS-07 | P1-012 | Full inbox/channels and platform-wide audit coverage |
| 1 | STEAD-P2-006 | WS-08 | P1-012 | Complete search/work graph and permission-aware MCP beta |
| 1 | STEAD-P2-007 | WS-09 | P1-012 | Secure runner pools, approved actions, artifact and secret integration |
| 1 | STEAD-P2-008 | WS-10 | P1-012 | Filesystem/S3/Azure/GCS BlobStore contract conformance |
| 1 | STEAD-P2-009 | WS-11 | P1-012 | GitHub/Jira/Confluence discovery, dry run and initial import |
| 1 | STEAD-P2-010 | WS-12 | P1-012 | Kubernetes/Helm/external-services, backup/restore, upgrade and performance baseline |
| 2 | STEAD-P2-011 | WS-13 | P2-001…010 | Independent Pilot/Beta quality and security gate |

## Phase 3 Production 1.0

These issues are `BLOCKED_PENDING_PHASE_0_APPROVAL` and also depend on the successful Pilot/Beta gate.

| Order | Issue | Owner | Direct predecessors | Deliverable |
|---:|---|---|---|---|
| 1 | STEAD-P3-001 | WS-04 | P2-011 | Lossless Yjs real-time document collaboration |
| 1 | STEAD-P3-002 | WS-06 | P2-011 | Government label/FIPS-capable/OSCAL profile and cross-domain denial |
| 1 | STEAD-P3-003 | WS-07 | P2-011 | Tamper-evident audit checkpoints and production exports |
| 1 | STEAD-P3-004 | WS-08 | P2-011 | OpenSearch scale profile and production permission-aware MCP |
| 1 | STEAD-P3-005 | WS-09 | P2-011 | Signed SBOM/provenance/checksum/notices/scanning release set |
| 1 | STEAD-P3-006 | WS-11 | P2-011 | Delta sync, cutover, source transition and permanent redirects |
| 1 | STEAD-P3-007 | WS-12 | P2-011 | Government-airgap, HA, upgrade matrix and production SLO validation |
| 2 | STEAD-P3-008 | WS-13 | P3-001…007 | Independent Production 1.0 security and release decision |

## Mandatory issue contract

Every issue in the machine-readable catalog explicitly states:

- requirement IDs and one accountable owner;
- dependencies, module, and owned directories;
- prohibited boundaries;
- measurable acceptance criteria and named automated tests;
- authorization and classification behavior;
- observability and audit requirements;
- migration and backward-compatibility implications;
- upgrade and rollback behavior;
- documentation obligations.

Any future child implementation issue must restate these fields with a narrower scope. It may not rely on a parent link as a substitute. An implementation issue remains incomplete until its tests, documentation, observability, migration, authorization, classification, audit, upgrade, rollback, and independent review obligations are satisfied.

## Agent-ready compatibility boundary

Phase 0 models identity as a principal union containing at least `user`, `agent`, and `service_account`; permits an agent principal in canonical work-item assignment; reserves agent relationships and future delegation/task/runtime inputs in OpenFGA and OPA; and lets CloudEvents and audit records distinguish an acting principal from the initiating/requesting principal.

Future agent business access is through canonical Platform APIs and the platform-wide MCP boundary. Scoped direct Git credentials are the only allowed direct provider path described by the addendum. MCP is the preferred future agent-to-platform interoperability path; A2A and Agent Card semantics remain future `SHOULD` seams, not Phase 0 deliverables.

The future authorization result must be capable of intersecting delegator authority, agent-specific authority, task scope, runtime security domain, session/environment constraints, and resource classification/handling rules. The compatibility schema grants no authority by itself.

Phase 0 explicitly excludes implementation of agent orchestration, prompting, model hosting, memory, AgentRun execution, A2A dispatch, and a full MCP tool catalog. Introducing any of them requires a separately approved post-Phase-0 issue and any applicable ADR; it cannot be smuggled into a schema or integration task.

## Gate semantics

- Phase 0 review can reject, amend, or approve a contract. Amendments that alter a locked decision require an ADR and project-owner approval.
- WS-13 is independent of the implementation owner and may not approve its own implementation.
- A missing test, release artifact, required audit event, backup/restore result, install/upgrade result, clean license decision, or unresolved unauthorized-disclosure path fails the applicable candidate.
- A waiver for a critical/high vulnerability must be documented, authorized, and time bounded. There is no waiver for a known unauthorized disclosure path.
- Passing one phase does not waive unmet requirements assigned to a later release; the traceability register remains authoritative for release targeting.
