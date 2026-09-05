# Stead architecture constitution

**Status:** Phase 0 baseline approved at tag `phase0`; Phase 1 foundation active<br>
**Normative source:** [`MASTER_BUILD_DIRECTIVE.md`](./MASTER_BUILD_DIRECTIVE.md)<br>
**Scope:** Governance and architecture constraints; implementation authority remains issue- and gate-scoped.

## 1. Authority and interpretation

The Master Build Directive is the normative project specification. This constitution is an index of its operating rules, not a replacement or reinterpretation. If this document, a backlog item, a contract, an ADR, or implementation conflicts with the directive, the directive wins until the project owner explicitly approves a conforming amendment.

Normative terms use RFC 2119/RFC 8174 meanings. Conflicts are resolved in this order:

1. prevent unauthorized disclosure, data loss, or integrity loss;
2. preserve source-of-truth and module boundaries;
3. preserve the unified end-user experience;
4. preserve upgradeability and standards compatibility;
5. preserve infrastructure portability;
6. prefer implementation simplicity.

Subagents do not resolve genuine ambiguity by inventing semantics. They apply an explicit directive default or submit an ADR with the alternatives, impacts, security effects, migrations, rollback, and tests.

## 2. Phase gate

`GATE-P0-APPROVED` passed against tag `phase0`, commit `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31`. `STEAD-P1-001` is complete. Later Phase 1 issues remain dependency- and ADR-gated, while Phase 2 and Phase 3 remain phase-gated.

The gate approved all of the following versioned artifacts as the immutable Phase 0 baseline:

- this constitution and the directive's product principles;
- OWGP v0.1;
- canonical entity/resource/relationship schemas;
- the security-label schema, profile rules, and join/lattice contract;
- OpenFGA model v0.1 and model/migration tests;
- policy-decision input/output and decision contract;
- capability-specific provider interfaces;
- the OpenAPI 3.1.1 skeleton and RFC 9457 error profile;
- the AsyncAPI 3.1.x skeleton, CloudEvents profile, and event naming rules;
- the canonical principal, assignment, delegation/task-context, and future agent-compatibility seams required by AGENT-001–007;
- the database/table ownership map;
- the threat-model and classification-bypass baseline;
- the license and dependency policy;
- the repository layout and boundary rules;
- the separate general-work and software-development golden-slice test plans;
- the Phase 0 reconciliation report and closeout packet;
- release gates and independent QA/security approval rules.

Approval of an artifact means approval of a tagged or commit-addressed version. Silence, merge, or the creation of this repository is not approval. A later material change reopens affected approvals and blocks dependent implementation until reviewed. Phase 0 approval does not waive any issue dependency, ADR deadline, security/QA review, or later release gate.

## 3. Locked decisions

The following decisions are locked. Changing any one requires an ADR and explicit project-owner approval; ordinary issue or pull-request approval is insufficient.

1. Stock Gitea, with no fork or direct database access.
2. The Devlane-derived React/TypeScript frontend is the primary UI fork.
3. No permanent Commonplace fork.
4. Go for backend, worker, provider adapters, and CLI; React/TypeScript for the frontend.
5. PostgreSQL is the authoritative platform relational store.
6. NATS JetStream is present from the first vertical slice.
7. Domain events use a transactional outbox.
8. OpenFGA owns relationship and need-to-know authorization.
9. A separate deterministic policy layer owns classification, ABAC/context, handling, information-flow, infrastructure, and explicit-deny decisions; its implementation is selected by ADR, and OPA/Rego is an allowed option rather than a required dependency.
10. Documentation uses Git, Markdown, and an OKF-compatible profile.
11. The canonical ontology and workflow are fixed and opinionated, with universal `deliverable`, `task`, and `problem` Work Item semantics.
12. Every Platform Project has exactly one dedicated Gitea tracker repository.
13. A cloneable repository/container is a classification and access-control boundary.
14. The standards stack includes OpenAPI, JSON Schema, CloudEvents, AsyncAPI, OpenTelemetry, OCI, SPDX, SLSA-compatible provenance, and OSCAL.
15. Docker/local and Helm/Kubernetes are first-class deployment targets.
16. No cloud service is required.
17. The core product performs no built-in cross-domain transfer.
18. Essential security remains in the open-source distribution.
19. Newly authored core code uses Apache-2.0 unless a specific MIT exception receives ADR and legal approval.
20. No unapproved source-available, field-of-use-restricted, proprietary, or copyleft runtime dependency.
21. Work and Docs are universal; software delivery is additive and capability-driven.
22. Universal global navigation is Home, Inbox, My Work, Projects, Knowledge, and Teams; Search is omnipresent.
23. Project primary areas are Overview, Work, Docs, optional Code, and optional Delivery.
24. Team hierarchy is single-parent, cycle-free, at most twelve levels, and grants no implicit authorization.
25. Every Project has exactly one owning Team and may have contributing Teams.
26. Documents may be Organization-, Team-, or Project-scoped; Work Items remain Project-scoped.
27. User, Agent, Service Principal (`service_account`), and Directory Group are distinct reference types; only users, agents, and service accounts may act.
28. MCP is the agent-to-platform boundary and A2A is the preferred external-runtime interoperability boundary.
29. Project lifecycle states are planned, active, paused, completed, and canceled; archive is separate and reversible.
30. Canonical document types use universal semantics; software-specific names are display labels only.
31. Stable semantic concepts, domain types, interfaces, and internal ports are unversioned; compatibility boundaries and serialized contracts carry versions.
32. Signed deployment security-domain policy—not a security-label profile ID—selects `request_boundary` or `commit_boundary` disclosure/revocation assurance.
33. Primary UI reads use composed BFF responses over local rebuildable projections; NATS is never a synchronous response dependency; authorization, SQL, audit, and provider work is set-oriented and bounded.

The project/repository and deployable component names are **Stead**, `stead-web`, `stead-api`, `stead-worker`, and `steadctl`. These names are concrete interfaces; generic architectural uses of “platform” remain descriptive prose.

## 4. Architectural invariants

### 4.1 One product and one policy path

Routine users receive one shell, navigation model, search, inbox, identity, and authorization model. The browser calls only the versioned platform API. Raw upstream interfaces are restricted administrative escape routes and are never the normal workflow.

Every protected operation is deny-by-default and evaluates authentication, trusted attributes/session context, canonical resource and effective label, OpenFGA, the policy-decision layer, provider/path enforcement, and audit metadata. No administrator role implies a classification or need-to-know bypass. UI hiding is not authorization.

All new contracts distinguish a human identity from the acting principal. `PrincipalRef` permits `user`, `agent`, `service_account`, and non-acting `directory_group`; Agent and Agent Run are canonical entities, but runtime execution remains outside Phase 0. Actors, assignees, creators, reviewers, subscribers, and request principals are not assumed to be human. Agents inherit no broad human permission set. The authorization seam preserves explicit delegation, task scope, independently revocable agent authority, runtime/environment context, and the intersection of delegator, agent, task, runtime-domain/session, and resource-label constraints.

### 4.2 Source-of-truth and module boundaries

- Platform modules own their tables and migrations; a module never writes another module's tables.
- Gitea and OpenFGA retain supported datastore boundaries.
- Gitea integration uses supported APIs, webhooks, Git protocols, authentication, and configuration only.
- `stead-api` performs synchronous domain operations and writes its outbox atomically.
- `stead-worker` publishes/consumes/reconciles/indexes/notifies/audits/imports with idempotent at-least-once semantics.
- NATS, search, activity, graph, inbox-derived views, and analytics are transport or rebuildable projections, not authoritative business stores.
- Provider implementations sit behind narrow capability interfaces. Provider-specific locators and types do not leak into canonical clients or domain schemas.
- Future agents use canonical Platform APIs and the platform-wide MCP interface for business resources. They do not use provider-specific business APIs. Direct Git protocol access is permitted only with scoped credentials that remain subject to central/provider enforcement.

### 4.3 Fixed semantics and portable data

The canonical entities, universal work-item and document types, statuses, priorities, estimates, hierarchy, capability registry, and relationship directions in the directive are closed sets. Display labels and tags may vary; semantics may not. New first-class entities, workflow states, arbitrary custom fields, capabilities, primary tabs, or configurable ontology require ontology review and an approved ADR. A Project always has Overview, Work, and Docs; Code and Delivery exist only where their fixed capabilities are enabled.

Git repositories, Git/Markdown/OKF documents, portable attachment manifests, versioned JSON exports, CloudEvents, SCIM-compatible identity export, and documented standards mappings preserve exitability. No customer data may exist only in an opaque proprietary format.

### 4.4 Classification containers and data flow

A repository, tracker repository, docs repository, package namespace, runner pool, cache, artifact store, backup set, and deployment security domain are enforceable boundaries. Item labels may add markings but never grant access finer than the enclosing cloneable/provider container can enforce. Differing access requires a separate container.

Security-label policy profiles are declarative, schema-validated, versioned, and signed. Stable profile IDs have no privileged product or authorization semantics; deployment security-domain policy uses a profile-ID-keyed map to bind each permitted profile/version to one ceiling and selects environment assurance controls plus one closed `disclosure_revocation_mode`. Cross-profile composition fails closed; v0.1 rejects every non-empty bridge set pending a separately approved signed mapping/non-weakening contract. Profile-driven text/markings remain authoritative over supplemental color in the UI.

Derived resources take the defined join of all applicable source, explicit, container, and handling restrictions and never silently become less restrictive. Lowering or removing restrictions is denied by default, authorized and reasoned, fully audited, cache/projection invalidating, and subject to the approval threshold and custody/separation controls required by the active deployment security-domain policy. Core Stead never automates cross-domain or write-down transfer.

Audit and event contracts preserve the acting principal and type, a distinct initiating/requesting principal when applicable, delegation/task context, and correlation/causation. They can represent `requested_by = user:alice` with `actor = agent:backend-agent` without a schema revision.

### 4.5 Compatibility and standards

Public HTTP APIs use OpenAPI 3.1.1, JSON Schema 2020-12 payloads, RFC 9457 errors, UUIDv7 identifiers, ETags/conditional writes, and explicit compatibility periods. Events use CloudEvents 1.0 and AsyncAPI 3.1.x. Breaking API or event changes require a major version and migration period.

Semantic concepts, domain nouns, Go types, interfaces, and internal ports use stable unversioned names. Compatibility boundaries, serialized formats, schemas, APIs, protocols, media types, and events carry versions. A type suffix such as `FooV2` is reserved for a migration in which incompatible versions genuinely coexist; versioned packages or contract namespaces are preferred. This rule does not remove versions from `/api/v1`, `stead.*.v1`, schema IDs/paths and `schema_version`, media types, `POL-DECISION-IO-V0.1`, `stead.security-profile-rules.v1`, OWGP versions, provider/migration contracts, or Stead Policy Activation Set v1.

The platform publishes profiles/mappings instead of adding unnecessary standards machinery. RDF databases, SPARQL, XACML, cloud-specific core dependencies, required outbound telemetry, and unbounded in-process plugins are outside the baseline architecture.

Architecture remains compatible with external agent runtimes and does not require a model, model provider, agent SDK, or orchestration framework. MCP is the future agent-to-platform boundary; A2A and A2A Agent Card semantics are future interoperability profiles where applicable. Phase 0 builds no agent orchestration, prompting, model hosting, memory, AgentRun execution, A2A dispatch, or full MCP tool catalog unless another separately approved requirement already requires it.

### 4.6 Fast request and disclosure boundaries

The normal Phase 1 path is the signed deployment policy's `request_boundary` mode: one fresh central authorization decision and final revision check per composed protected request, one safe aggregate audit operation, and no per-row decision/audit/provider waterfall. A finite response that validly begins disclosure first may finish across a concurrent security mutation; every later operation observes the mutation. Streams, downloads, exports, print, credential issuance, provider mutations, direct-protocol effects, non-idempotent calls, long disclosures, and ambiguous external effects retain durable effect controls. On acceptance, ADR-0009's one closed bounded internal provider pagination/snapshot/verification/safe-idempotent-read plan may instead use one fresh decision-bound scope, one atomic single-holder execution claim, read-only per-call holder/scope/fence validation, and one closed logical audit without a durable permit transaction for every eligible HTTP read. Reuse, handoff, takeover, stale-holder dispatch, and post-terminal replay deny before provider I/O; ordinary UI reads remain local-projection-backed and make zero synchronous provider calls.

`commit_boundary` is a separately benchmarked high-assurance mode that preserves `BoundedReadGuard`, `DisclosureEgressFence`, serving leases/quiescence, and terminal transport-buffer proof. Phase 1 preserves its typed seam; complete operational evidence remains high-assurance work. Neither mode may be inferred from a label profile ID, weaken fail-closed decisions or nondisclosure, or introduce cross-domain/write-down behavior.

After the shell loads, useful primary content normally arrives through one composed BFF request backed by local rebuildable PostgreSQL projections. The browser never fans out to providers or policy infrastructure; ordinary reads never waterfall through Gitea; NATS is post-response distribution only. Lists, search, inbox, activity, rollups, overview, and graph paths are set-oriented and carry explicit request/query/authorization/provider/write budgets. The 250 KiB gzip universal-shell budget excludes source maps and lazy capability chunks and is enforced in CI. Performance targets, evidence, and the greater-than-ten-percent golden-path regression gate are those in `PERF-001` through `PERF-006`.

## 5. Contract and change control

Each contract has exactly one editing workstream at a time, named in the contract ownership matrix. Consumers may propose changes but do not merge edits to a contract they do not own. Cross-workstream changes require:

1. linked requirement IDs and impacted contracts/modules;
2. an owner and named reviewers;
3. compatibility, migration, upgrade, rollback, authorization, classification, observability, audit, and documentation analysis;
4. schema/model/contract tests and golden-scenario impact;
5. security review for any trust, label, identity, credential, export, direct-provider, or data-flow change;
6. architecture review for any public or cross-module contract;
7. an ADR plus project-owner approval for a locked decision or new ontology;
8. integration by the designated owner when more than one workstream participates.

Unapproved dependencies, unknown/disallowed licenses, direct upstream-database access, alternate authorization logic, or feature changes made ahead of their approved contract are merge blockers.

## 6. Issue and completion contract

Every implementation issue must declare:

- requirement IDs;
- owner;
- dependencies;
- module and owned directories;
- prohibited boundaries;
- acceptance criteria;
- automated tests;
- authorization and classification behavior;
- observability and audit requirements;
- migration and backward-compatibility implications;
- upgrade and rollback behavior;
- documentation obligations;
- a performance contract stating expected request count, SQL query behavior, external/provider calls, authorization strategy, synchronous writes, frontend bundle impact, and the applicable benchmark or a concrete reason the work is not performance-sensitive.

An issue is not complete until applicable contracts, server-side policy, direct-provider bypass coverage, tests, telemetry without sensitive leakage, audit, migration, compatibility, upgrade/rollback, backup/restore, accessibility, documentation, licenses/SBOM, performance budgets and regression evidence, and independent QA/security evidence are complete. An implementation author cannot grant final approval to their own release candidate.

## 7. Architecture approval record

| Artifact | Version/commit | Architecture review | QA/security review | Project-owner approval | Status |
|---|---|---|---|---|---|
| Constitution and principles | `phase0` / `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31` | `/root/directive_audit` | `/root/contract_audit`; `/root/independent_security` | explicit 2026-08-29 instruction to tag and begin Phase 1 when green | **Approved** |
| OWGP and canonical schemas | `phase0` / `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31` | `/root/directive_audit` | `/root/contract_audit`; `/root/independent_security` | explicit 2026-08-29 instruction to tag and begin Phase 1 when green | **Approved** |
| Authorization/classification contracts | `phase0` / `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31` | `/root/directive_audit`; `/root/security_contract` | `/root/contract_audit`; `/root/independent_security` | explicit 2026-08-29 instruction to tag and begin Phase 1 when green | **Approved** |
| Provider/API/event/database contracts | `phase0` / `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31` | `/root/directive_audit`; `/root/security_contract` | `/root/contract_audit`; `/root/independent_security` | explicit 2026-08-29 instruction to tag and begin Phase 1 when green | **Approved** |
| Threat, license, layout, and golden-test baselines | `phase0` / `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31` | `/root/directive_audit`; `/root/security_contract` | `/root/contract_audit`; `/root/independent_security` | explicit 2026-08-29 instruction to tag and begin Phase 1 when green | **Approved** |
| Phase 1 foundation decision packet (ADR-0002–ADR-0006) | `24c74d52ef0a78840ab147da48c3d66589e49e3e` | `/root/architecture_standards_review/profile_contract_audit`; `/root/contract_owner_review`; `/root/core_owner_review`; `/root/build_owner_review` | `/root/precommit_scope_audit`; `/root/revocation_mode_impact` | explicit 2026-08-30 approval of the immutable decision revision; ADR-0005 concurrence recorded but not required | **Approved** |

This approval activates dependency-ready Phase 1 work only. A material baseline change must be reviewed against the affected contract and immutable evidence before dependent implementation proceeds.
