# Phase 0 Workstream Ownership

Status: **Ready for architecture, security, independent QA, and project-owner approval**<br>
Normative source: `docs/architecture/MASTER_BUILD_DIRECTIVE.md` version 0.2<br>
Scope: Phase 0 planning and contract work only

This document allocates accountability to the thirteen required workstreams. It does not authorize Phase 1 feature implementation. If this document conflicts with the Master Build Directive, the directive governs. A locked architecture decision may change only through an approved ADR and project-owner approval.

## Ownership rules

- `Owner` means the single accountable workstream. It is the only workstream allowed to merge changes in its exclusive paths and contracts.
- A consumer may propose a change, but must send it to the owner as a contract change request. The consumer must not edit the contract concurrently.
- A required reviewer may reject a change in its review domain. Security/classification changes require `WS-06`; test/release-gate changes require `WS-13`; architecture and standards changes require `WS-01`.
- Final Phase 0 approval requires two distinct independent `WS-13` reviewer identities for QA and security; neither substitutes for `WS-01` architecture approval, `WS-06` security-contract approval, or project-owner approval.
- Shared application composition roots have one integration owner. Feature work remains in the owning module/provider and is wired into the composition root by that integration owner.
- Module code may use another module only through a stable public module contract. It must not write another module's tables.
- Browser code calls only the versioned platform API. Modules call provider interfaces, never provider-specific implementations or upstream databases.
- Authorization is the common `OpenFGA allow AND OPA allow AND provider/path enforcement allow AND no deny` decision. No workstream may create a private alternative.
- Repository, tracker repository, docs repository, package namespace, runner pool, cache, artifact store, and backup set are security boundaries. Per-item markings cannot grant access beyond the enclosing provider/container boundary.
- The exact path ledger and database ownership rules are in `repository-layout-and-boundaries.md`; contract authority is in `contract-ownership-matrix.md`.

## Phase 0 dependency milestones

| Milestone | Exit condition | Accountable workstreams |
|---|---|---|
| `M0-A — directive controlled` | Every directive requirement is in the machine-readable traceability register; locked decisions and non-goals are recorded; issue templates enforce all required fields. | `WS-13`, reviewed by `WS-01` and `WS-06` |
| `M0-B — constitution bounded` | Product principles, repository/module boundaries, logical database namespaces, ADR policy, license policy, and ownership ledgers are approved. | `WS-01`, with `WS-06` security and `WS-13` conformance review |
| `M0-C — contracts complete` | OWGP v0.1, canonical schemas, public API skeleton, event envelope/catalog, provider interfaces, OKF profile, and compatibility/deprecation rules are reviewable and have conformance-test plans. | `WS-01` plus the relevant contract owners |
| `M0-D — security contracts complete` | Security-label schema/lattice, OpenFGA model v0.1, OPA input/output contract, trusted-attribute contract, deployment-domain contract, threat baseline, and bypass inventory are approved. | `WS-06`, independently reviewed by `WS-13` |
| `M0-E — verification contract complete` | Golden-scenario plan, requirements-to-tests matrix, release gates, license/dependency workflow, migration/rollback expectations, and all required test harness backlogs are approved. | `WS-13`, with `WS-12` for operational paths |
| `M0-F — Phase 0 frozen` | `M0-A` through `M0-E` have architecture, security-contract, separate independent QA and security, and project-owner approval; contract versions are tagged; open ADRs are either resolved or explicitly block implementation. | Project owner; `WS-01`; `WS-06`; distinct independent `WS-13` QA and security identities |

Dependency order is `M0-A -> M0-B -> (M0-C and M0-D) -> M0-E -> M0-F`. Broad feature implementation is prohibited before `M0-F`.

## WS-01 — Architecture and standards

**Accountability.** Own the architecture constitution, OWGP, ontology governance, common/public schemas, ADR lifecycle, public API contract, standards profiles, compatibility/deprecation rules, and contract registry.

**Exclusive paths and contracts.** `/docs/architecture/constitution.md`, `/docs/architecture/agent-ready-compatibility.md`, `/docs/architecture/workstream-ownership.md`, `/docs/architecture/contract-ownership-matrix.md`, `/docs/architecture/repository-layout-and-boundaries.md`, planned `/docs/architecture/standards/` and `/docs/architecture/ontology/`, `/docs/adr/`, `/specs/openapi/`, `/specs/work-graph-profile/`, `/packages/domain-schemas/common/`, `/packages/domain-schemas/resources/` except the `work-assignment` leaf owned by `WS-02`, and `/packages/provider-sdk/core/`. Domain experts review resource schemas, but `WS-01` is the sole editor except for explicitly delegated leaf contracts.

**Assigned requirements.** `PRIN-002`, `PRIN-003`, `PRIN-004`, `PRIN-005`, `PRIN-006`, `PRIN-013`; `ARCH-001`, `ARCH-002`, `ARCH-005`; `STD-001`, `STD-002`; `DOM-001`, `DOM-002`, `DOM-003`, `DOM-006`; `AGENT-007`.

**Required verification contracts.** JSON Schema 2020-12 validation and compatibility tests; OWGP export/import conformance; OSLC/PROV/OKF mapping fixtures; UUIDv7, RFC 9457, ETag/conditional request, canonical URI, cardinality, and deprecation tests; OpenAPI linting and breaking-change detection.

**Dependencies and outputs.** Starts after `M0-A`; produces the architectural part of `M0-B` and most of `M0-C`. It must receive security review from `WS-06` and independent conformance review from `WS-13` before `M0-F`.

**Prohibited boundaries.** Must not add a first-class entity, configurable ontology, arbitrary workflow, technology exception, or changed locked decision without an approved ADR. Must not implement feature modules, encode provider internals in canonical schemas, or make RDF/SPARQL mandatory. Phase 0 must not expand into agent orchestration, prompting, model hosting, agent memory, `AgentRun` execution, A2A dispatch, or a full MCP tool catalog.

**Security/classification.** Every resource and relationship contract must carry organization, project/container context, effective-label reference, provenance, and non-leaking error semantics. Canonical schemas must not create a page/item-level access promise that cloneable containers cannot enforce.

**Phase 0 definition of done.** Contracts are versioned, machine validated, mapped to requirement IDs and planned tests, have owners/consumers/deprecation rules, include authorization/classification fields and migration/rollback notes, and have approvals from `WS-06`, `WS-13`, and the project owner.

## WS-02 — Platform core/domain

**Accountability.** Own the Go core composition root, organization/project/work modules, synchronous transactional boundaries, optimistic concurrency behavior, module ports, core migrations, and transactional outbox implementation contract.

**Exclusive paths and contracts.** `/apps/core/`, `/modules/organization/`, `/modules/project/`, `/modules/work/`, `/packages/domain-schemas/resources/work-assignment/`, their module-scoped integration tests, and the logical `organization.*`, `project.*`, `work.*`, and `core_outbox.*` relational namespaces. Other workstreams provide modules through ports; only `WS-02` edits core composition/wiring.

**Assigned requirements.** `ARCH-003`, `ARCH-004`; `DOM-004`, `DOM-008`, `DOM-009`, `DOM-011`; `EVT-002`; `AGENT-002`.

**Required verification contracts.** Go unit/property tests with at least 80% line and branch coverage; module-boundary and forbidden-import tests; optimistic concurrency and conditional-write tests; migration forward/backward/expand-contract tests; atomic domain-write-plus-outbox tests; rollback/failure-injection tests; assignment contract tests proving `user` and `agent` assignees are provider-independent and that Gitea-native user limits do not leak into the canonical model. Service accounts remain valid acting principals where a contract permits them, but are not Work assignees.

**Dependencies and outputs.** Requires `M0-B`, canonical resource/API conventions from `WS-01`, authorization decision ports from `WS-06`, and event/outbox envelope semantics from `WS-07`. Its transaction and module-port contracts are inputs to `M0-C`.

**Prohibited boundaries.** No provider-specific code in core, direct Gitea/Commonplace/OpenFGA/OPA/NATS/storage database access from domain modules, cross-module table writes, browser coupling, or `commit then publish` event flow. Core may invoke authorization and provider ports; it may not reproduce their policy logic.

**Security/classification.** Every protected mutation must resolve authenticated acting principal and principal type, requesting/initiating principal when different, task/delegation context when present, canonical resource/container, effective label, central authorization decision, audit metadata, correlation/causation IDs, and transactional event intent. Work assignment accepts an `agent` principal without granting execution authority. Failures fail closed and use non-leaking Problem Details.

**Phase 0 definition of done.** Module APIs, logical table ownership, transaction/outbox sequence, consistency model, migrations, failure modes, telemetry/audit hooks, authorization call points, and compatibility/rollback test plans are approved without feature implementation.

## WS-03 — Gitea/provider integration

**Accountability.** Own the stock-Gitea adapter, capability-specific SCM provider interfaces, tracker repository and canonical Gitea mapping, repository-policy reconciliation, webhook ingestion, supported-version matrix, and direct-provider enforcement mapping.

**Exclusive paths and contracts.** `/modules/scm/`, `/providers/gitea/`, `/packages/provider-sdk/scm/`, Gitea contract fixtures, and the logical `scm.*` namespace. It owns the twelve SCM capability interfaces enumerated in the contract matrix.

**Assigned requirements.** `SCM-001`, `SCM-002`, `SCM-003`, `SCM-004`, `SCM-005`, `SCM-006`.

**Required verification contracts.** Full `TEST-006` Gitea provider suite; webhook HMAC, replay, and fuzz tests; reconciliation drift and idempotency tests; Git SSH/HTTPS, API token, package, artifact, and runner bypass tests; current pinned, previous two supported minors, and next RC/nightly compatibility; outage/rate/error handling; upgrade preflight.

**Dependencies and outputs.** Requires `M0-B`, provider SDK conventions and canonical schemas from `WS-01`, resource/module ports from `WS-02`, decision/reconciliation rules from `WS-06`, and event contracts from `WS-07`. Its approved capability contracts are part of `M0-C`.

**Prohibited boundaries.** No Gitea fork, internal Go import, database query/write, undocumented file/endpoint dependency, template-patch primary integration, unbounded provider interface, or presentation of raw Gitea as the routine UI. Direct changes that violate canonical semantics must be reset/rejected and audited.

**Security/classification.** Repository permissions and security-domain/container labels must be reconciled from central policy. Unsupported contextual controls require an access gateway, constrained credential issuance, or network/security-domain control; documentation alone is not enforcement.

**Phase 0 definition of done.** Each capability has a versioned port, failure/capability semantics, canonical mapping, auth/classification enforcement point, audit/event contract, compatibility matrix, migration/reconciliation behavior, and contract-test plan approved by `WS-01`, `WS-06`, and `WS-13`.

## WS-04 — Knowledge/Commonplace

**Accountability.** Own the knowledge module, OKF document contract implementation, Commonplace provider and upstream proposal plan, deterministic Markdown/editor boundary, document review model, stable document IDs, attachment references, and Git repository security-container behavior.

**Exclusive paths and contracts.** `/modules/knowledge/`, `/providers/commonplace/`, `/packages/provider-sdk/knowledge/`, `/specs/okf-profile/`, knowledge/Commonplace contract fixtures, and logical `knowledge.*` namespace.

**Assigned requirements.** `DOM-005`; `DOC-001`, `DOC-002`, `DOC-003`, `DOC-004`, `DOC-005`.

**Required verification contracts.** Commonplace compatibility suite in `TEST-006`; OKF parse/write and deterministic Markdown golden tests; move/rename stable-ID tests; manual Markdown round trips; unsafe HTML/MDX/script rejection fuzzing; optimistic conflict, reconnect/no-loss, branch/PR review, approved-hash, supersession, markings, and export tests.

**Dependencies and outputs.** Requires `M0-B`, canonical document/resource schemas from `WS-01`, Git/provider contracts from `WS-03`, authorization/label/container contracts from `WS-06`, BlobStore contract from `WS-10`, and event/audit contracts from `WS-07`. The OKF and headless/provider contracts complete its part of `M0-C`.

**Prohibited boundaries.** No permanent Commonplace fork, platform ontology or authorization logic in a temporary patch queue, iframe as the primary docs experience, executable MDX/arbitrary script/unsafe HTML by default, or claim of page-level secrecy inside a cloneable repository. A native fallback requires an ADR and preserves the same Git/OKF contracts.

**Security/classification.** Access differences require separate repositories/security containers. Review, approval, immutable revision hash, classification/handling, export/print marking, and audit evidence are mandatory for controlled content.

**Phase 0 definition of done.** The Git/OKF storage and edit/review state machines, Commonplace upstream/patch/fallback boundaries, container mapping, concurrency behavior, export/import compatibility, observability/audit hooks, and automated test plan are approved.

## WS-05 — Unified frontend/design system

**Accountability.** Own the Devlane-derived visual foundation, universal navigation, capability-driven Project information architecture, shared interaction vocabulary, design constitution/system, generated API client integration, accessibility, performance budgets, and classification/handling presentation. Devlane routes and ontology are explicitly noncanonical.

**Exclusive paths and contracts.** `/apps/web/`, `/packages/design-system/`, `/packages/api-client/` (generated from the approved OpenAPI contract), frontend test fixtures/components, and user-facing UI documentation. Only generated code may mirror public schemas; the OpenAPI source remains owned by `WS-01`.

**Assigned requirements.** `PRIN-001`, `PRIN-014`; `UX-001`, `UX-002`, `UX-003`, `UX-004`, `UX-005`, `UX-006`, `UX-007`, `UX-008`, `UX-009`.

**Required verification contracts.** Browser E2E for all critical/golden flows; WCAG 2.2 AA automated and manual keyboard/screen-reader checks; contract-generated client tests; deep-link stability; performance budgets; persistent classification banners/markings; export/copy/share warnings; tests proving no direct provider or local-authorization calls.

**Dependencies and outputs.** May design shell prototypes after `M0-B`, but implementation waits for `M0-F`. It consumes the public API/schema contracts from `WS-01`, authorization/classification display contract from `WS-06`, and domain capabilities from all functional owners.

**Prohibited boundaries.** No browser calls to Gitea, Commonplace, OpenFGA, OPA, NATS, object stores, or other providers; no local authorization decision; no hidden admin bypass; no user-configurable core navigation/workflow semantics; no separate upstream product branding in normal workflows. Code and Delivery must not appear for Projects lacking those capabilities, and Devlane Modules, Epics, Pages, Board, Intake, Archives, Drafts, or route structure must not become canonical contracts.

**Security/classification.** UI hiding is supplemental only. Effective labels must remain visible wherever protected content is rendered; unauthorized content, identifiers, counts, snippets, autocomplete, relationship metadata, and errors must never be cached or displayed.

**Phase 0 definition of done.** Shell/navigation and shared-component contracts, API-only boundary, label/handling presentation rules, accessibility criteria, performance budgets, deep-link rules, observability-without-content policy, and golden E2E plan are approved.

## WS-06 — Identity/authorization/classification

**Accountability.** Own OIDC/SCIM and trusted identity/attribute interfaces, central authorization service contract, OpenFGA model, OPA input/output and Rego bundles, SecurityLabel schema/lattice/profiles, deployment security-domain decision rules, downgrade workflow, and provider-path bypass controls.

**Exclusive paths and contracts.** `/modules/identity/`, `/modules/authorization/`, `/modules/classification/`, `/providers/identity-oidc/`, `/providers/identity-scim/`, `/policies/openfga/`, `/policies/opa/`, `/policies/security-label-profiles/`, `/packages/domain-schemas/identity/`, `/packages/domain-schemas/security/`, `/packages/provider-sdk/identity/`, and logical `identity.*`, `authorization.*`, and `classification.*` namespaces.

**Assigned requirements.** `PRIN-007`, `PRIN-011`, `PRIN-012`, `PRIN-015`; `DOM-007`, `DOM-010`; `AUTH-001`, `AUTH-002`, `AUTH-003`, `AUTH-004`, `AUTH-005`, `AUTH-006`; `CLS-001`, `CLS-002`, `CLS-003`, `CLS-004`, `CLS-005`, `CLS-006`, `CLS-007`, `CLS-008`; `AGENT-001`, `AGENT-003`, `AGENT-006`.

**Required verification contracts.** OIDC/SCIM/provider contract tests; OpenFGA model and migration tests including first-class `agent` principals; 100% Rego decision-table/rule coverage and at least 90% mutation score for critical policy; signed-bundle verification; property tests for lattice join/no-lowering; the complete `TEST-004` matrix; every direct-provider bypass path; cache/projection invalidation and non-disclosure tests. Future-agent seam fixtures must show delegation, task scope, independently revocable agent authority, and classification/environment intersection without implementing execution.

**Dependencies and outputs.** Requires canonical resource/relationship/schema conventions and repository-boundary map from `WS-01`; collaborates with every resource/provider owner. It produces `M0-D` and is a blocking reviewer for `M0-C`, `M0-E`, and `M0-F`.

**Prohibited boundaries.** No administrator/role bypass, self-asserted trusted attribute, default allow, unlogged downgrade, built-in cross-domain/write-down transfer, claim of certification/validation, free-form label fields, or duplicate module-local policy logic. OpenFGA, OPA, and provider enforcement are complementary, not alternatives. An agent must not broadly inherit a delegating human's permissions; its future effective authority is the intersection of delegator, agent, task, runtime domain, session/environment, and resource classification/handling constraints.

**Security/classification.** This workstream owns the authoritative decision sequence and fail-closed behavior. Security officers may administer policy metadata without automatically reading content. Attributes have authority, provenance, issue/review/expiry metadata, and expired or unverifiable values deny.

**Phase 0 definition of done.** Models/contracts are versioned, signed where required, exhaustively testable, mapped to every resource and bypass path, define cache/search/event/export behavior, include migration/rollback and emergency recovery rules, and pass independent `WS-13` review.

## WS-07 — Events/activity/inbox/audit

**Accountability.** Own NATS/JetStream topology, CloudEvents envelope and event catalog, AsyncAPI, outbox publisher/consumer semantics, worker composition root, activity projection, canonical in-app inbox, external notification interfaces, and append-only audit model/export interfaces.

**Exclusive paths and contracts.** `/apps/worker/` composition and eventing framework, `/modules/notification/`, `/modules/audit/`, `/providers/notifications-email/`, `/providers/notifications-webhook/`, `/packages/event-schemas/`, `/packages/provider-sdk/notifications/`, `/specs/asyncapi/`, and logical `notification.*` and `audit.*` namespaces. Domain worker behavior remains in its owning module and is registered through `WS-07` interfaces.

**Assigned requirements.** `EVT-001`, `EVT-003`, `EVT-004`; `ACT-001`; `NOTIF-001`, `NOTIF-002`; `AUD-001`, `AUD-002`; `AGENT-004`.

**Required verification contracts.** CloudEvents/JSON Schema/AsyncAPI conformance; subject authorization; publish retry, consumer restart, processed-event/idempotency, out-of-order, dead-letter, controlled replay, and projection rebuild tests; notification grouping/redaction/channel-policy tests; append-only audit/tamper-evidence tests; protected-content telemetry/event minimization tests. Actor-context fixtures must represent `requested_by=user:alice` with `actor=agent:backend-agent`, principal type, delegation/task context, and correlation/causation IDs without a future schema break.

**Dependencies and outputs.** Requires `M0-B`, common envelope from `WS-01`, transactional outbox API from `WS-02`, and label/authorization decision metadata from `WS-06`. It produces the event portion of `M0-C`; search, migration, CI, and operations consume it.

**Prohibited boundaries.** NATS, activity, inbox, and audit projections are not authoritative business stores. No global-order assumption, non-idempotent durable effect, direct post-commit publish reliability model, secret/body leakage in events/audit, or external notification that violates domain/channel policy.

**Security/classification.** Every event carries organization, security domain, label reference, acting principal and type, initiating/requesting principal when different, delegation/task context when present, correlation, causation, source, and subject while minimizing protected payload. Subscription, replay, DLQ access, inbox content, activity, audit views, and external channels are authorized and classification-aware.

**Phase 0 definition of done.** Stream/subject, envelope, schema-version, retention/replay/DLQ, idempotency, projection, notification/redaction, audit, telemetry, migration, and rollback contracts are approved and have executable-test backlogs.

## WS-08 — Search/work graph/AI access

**Accountability.** Own the search module/providers, rebuildable multi-resource search and Work Graph projections, authorization-aware query protocol, canonical relationship traversal, and permission-aware MCP/A2A/Platform API compatibility boundary.

**Exclusive paths and contracts.** `/modules/search/` (including graph projection), contract-only `/modules/agent/`, `/providers/search-postgres/`, `/providers/search-opensearch/`, contract-only `/providers/agent-a2a/`, `/packages/provider-sdk/search/`, `/specs/mcp/`, `/specs/a2a/`, `/docs/architecture/search-graph/mcp-a2a-compatibility.md`, search/graph/future-agent compatibility fixtures, and logical `search.*` projection namespace.

**Assigned requirements.** `SRCH-001`, `SRCH-002`, `SRCH-003`; `GRAPH-001`, `GRAPH-002`; `AGENT-005`.

**Required verification contracts.** SearchProvider contract suite across PostgreSQL/OpenSearch; full rebuild/replay and parity tests; authorized result/count/facet/snippet/suggestion tests; graph endpoint/edge-label propagation tests; stale-index/failure degradation; future MCP boundary tests for principal identity, Platform API reuse, attribution, audit, controlled writes, and refusal of provider business APIs; compatibility fixtures for future A2A Agent Card semantics without A2A dispatch; published search performance load shape.

**Dependencies and outputs.** Requires `M0-C` canonical schemas/relationships and event contracts, plus `M0-D` authorization/filtering contracts. Provider choices beyond the mandated baseline/scale profiles cannot alter canonical semantics.

**Prohibited boundaries.** Search/graph are projections, never systems of record; no direct unrestricted repository/database/NATS/object-store access for agents; no provider-specific business API for agents; no post-filter-only design that leaks totals or metadata; no graph database requirement without ADR; no bypass of the Platform API for MCP. Direct Git protocol access is the only future provider exception and requires scoped credentials. Phase 0 does not implement an MCP tool catalog, agent registry, A2A dispatch, runtime, model, orchestration, or memory.

**Security/classification.** Coarse organization/domain/container/label partition filtering precedes retrieval, followed by authoritative OpenFGA/OPA filtering before any result or aggregate. Edges inherit the maximum restrictions of endpoints and relationship metadata.

**Phase 0 definition of done.** Provider interface, projection/event inputs, index partitions, authoritative filter sequence, rebuild/rollback, graph edge rules, MCP boundary, audit/telemetry rules, and leakage/performance tests are approved.

## WS-09 — CI/runners/artifacts/secrets

**Accountability.** Own the CI and artifact domain modules, Gitea Actions visibility/policy mapping, runner-pool isolation model, approved action catalog, package/release/artifact semantics, SecretProvider interface, and release supply-chain outputs.

**Exclusive paths and contracts.** `/modules/ci/`, `/modules/artifact/`, `/packages/provider-sdk/ci/`, `/packages/provider-sdk/secrets/`, CI/artifact/runner test fixtures, and logical `ci.*` and `artifact.*` namespaces. `WS-10` owns blob implementations; `WS-09` owns canonical artifact/package/release records that reference blobs.

**Assigned requirements.** `ART-001`; `CICD-001`, `CICD-002`, `CICD-003`, `CICD-004`, `CICD-005`.

**Required verification contracts.** Actions/provider contracts; workflow visibility and traceability E2E; immutable action pin/mirror and license tests; runner isolation/cleanup/egress/cache/credential/secret-redaction tests; lower-pool denial; OCI distribution; SBOM/signature/provenance/checksum/notice verification; secret non-persistence scans.

**Dependencies and outputs.** Requires Gitea capabilities from `WS-03`, label/policy decisions from `WS-06`, event/audit contracts from `WS-07`, BlobStore from `WS-10`, and release/license gates from `WS-13`.

**Prohibited boundaries.** No arbitrary public action fetch in secure profiles, mutable action pin, cross-domain/shared runner cache, persistent job credential, uncontrolled privileged runner, secret in Git/event/log/search/frontend, direct higher-domain storage access from a lower pool, or unsupported compliance/SLSA/FIPS claim.

**Security/classification.** Runner pools, caches, packages, artifacts, release attachments, and secret scopes are enforceable containers. Privileged runners need a policy exception and dedicated pool; external secret stores remain optional adapters.

**Phase 0 definition of done.** CI/artifact/runner/secret ports, policy inputs, isolation and data-flow diagrams, supply-chain evidence contract, storage/event/audit bindings, provider migration behavior, and security test plan are approved.

## WS-10 — Storage

**Accountability.** Own the BlobStore interface and four implementations, attachment/large-object provider behavior, portable manifests, provider-independent locators, retention/malware metadata behavior, authorized downloads, and domain/security partitioning.

**Exclusive paths and contracts.** `/providers/blob-filesystem/`, `/providers/blob-s3/`, `/providers/blob-azure/`, `/providers/blob-gcs/`, `/packages/provider-sdk/blobstore/`, BlobStore contract fixtures, and provider-owned operational metadata. Canonical Artifact/Attachment records remain in the owning domain, not provider tables.

**Assigned requirements.** `STOR-001`, `STOR-002`, `STOR-003`.

**Required verification contracts.** One contract suite for all four providers; content hash/size/type/provenance/retention/malware-state parity; locator opacity; short-lived authorized URL lifetime/scope; organization/domain/classification partitioning; cache/temp cleanup; fail-closed provider outage; backup/restore/export and provider-migration round trips.

**Dependencies and outputs.** Requires provider SDK conventions from `WS-01`, canonical Attachment/Artifact schemas from `WS-01`/`WS-09`, authorization/labels from `WS-06`, audit/events from `WS-07`, and backup/export contracts from `WS-12`.

**Prohibited boundaries.** No provider locator exposed to normal clients, direct browser/provider authorization, cross-domain cache/temp/backup sharing, provider-specific fields in canonical UI/domain contracts, opaque-only export, or object access beyond the enclosing security container.

**Security/classification.** Download authorization, signed-URL policy, object/cache/temp/backup partition, malware status, retention, and deletion evidence must use trusted server decisions and preserve the object's effective label.

**Phase 0 definition of done.** Interface semantics, four-provider capability/error matrix, object metadata contract, security partitions, URL/credential model, export/restore/provider-migration behavior, observability/audit fields, and contract/security tests are approved.

## WS-11 — Migration

**Accountability.** Own the resumable migration subsystem and GitHub/Jira/Confluence source connectors, inventory/capability analysis, identity/ontology/label mapping, dry run/import/delta/cutover, validation/reconciliation, redirects, provenance, and final reporting.

**Exclusive paths and contracts.** `/modules/migration/`, `/packages/provider-sdk/migration/`, migration source fixtures, migration integration/fuzz tests, and logical `migration.*` namespace. Source-specific connectors live under the migration module until a layout ADR approves additional provider roots.

**Assigned requirements.** `MIG-001`, `MIG-002`, `MIG-003`, `MIG-004`, `MIG-005`.

**Required verification contracts.** Resumability/idempotency and restart/failure injection; discovery/dry-run/cutover/delta state-machine tests; identity and fixed-ontology mapping; unsupported-construct completeness; timestamps/authors/comments/attachments/links/history/provenance preservation; redirect stability; importer/parser fuzzing; rollback/reconciliation and classification non-downgrade.

**Dependencies and outputs.** Requires all destination canonical schemas and provider ports in `M0-C`, security-label/authorization mappings in `M0-D`, storage contract from `WS-10`, and event/audit contracts from `WS-07`. Source capability gaps become explicit report entries, not new semantics.

**Prohibited boundaries.** No one-off scripts as the product migration path, silent discard, user-defined status/type/entity creation, source-internal database dependency, loss of source ID/URL/provenance, automatic cross-domain transfer, or unapproved compatibility API emulation.

**Security/classification.** Imports require trusted identity and label mapping before write; uncertain/unmapped values fail closed or quarantine. Reports, source metadata, attachments, redirect maps, temporary data, and logs inherit appropriate protection.

**Phase 0 definition of done.** State machine, source capability contracts, canonical mapping tables, quarantine/error/restart behavior, reconciliation/rollback, redirect/provenance schema, security decisions, audit/telemetry, and comprehensive test fixtures are approved.

## WS-12 — Installation/operations

**Accountability.** Own `platformctl`, Compose/Helm/air-gap packaging, configuration/profile contracts, install/doctor/upgrade/backup/restore/export/import flows, OpenTelemetry and health conventions, portability, reliability/load profiles, and recovery orchestration.

**Exclusive paths and contracts.** `/apps/platformctl/`, `/deploy/compose/`, `/deploy/helm/`, `/deploy/airgap/`, `/deploy/examples/`, `/packages/domain-schemas/config/`, operator documentation, operational test fixtures, and deployment/backup metadata owned by the CLI rather than a domain module.

**Assigned requirements.** `PRIN-008`, `PRIN-009`; `DEP-001`, `DEP-002`, `DEP-003`, `DEP-004`, `DEP-005`; `OPS-001`, `OPS-002`, `OPS-003`, `OPS-004`, `OPS-005`.

**Required verification contracts.** All `TEST-007` profiles and upgrades; no-network air-gap test; Helm values schema/lint/tests and amd64/arm64 matrix; health/doctor dependency checks; OTel context and sensitive-data exclusion; representative consistent backup/restore; failure/chaos and rollback; published reproducible load datasets for all SLOs.

**Dependencies and outputs.** Requires component/config/provider/security/license contracts and supported-version matrices from all owners. Backup coverage is jointly reviewed by every authoritative-store owner, `WS-06`, and `WS-13`. Its operational contracts complete `M0-E`.

**Prohibited boundaries.** No required SaaS/cloud service, cloud-specific CRD in the core chart, unapproved outbound air-gap call, required manual giant config, production local bootstrap identity, sensitive content in telemetry, upgrade without compatibility/preflight/backup/migration plan, or recovery that depends on NATS being authoritative.

**Security/classification.** Effective config defines deployment domain/ceiling, integrations, channels, destinations, pools, and network zones. Backup, restore, diagnostics, telemetry, and upgrade reports are classified/authorized artifacts and avoid secret/content leakage.

**Phase 0 definition of done.** Profile/config schema, component/version order, health/doctor, backup consistency, restore, upgrade/rollback, air-gap inventory, OTel/SLO/benchmark, security-domain, audit, and test contracts are approved.

## WS-13 — QA/security/release

**Accountability.** Own requirement traceability and test governance, independent QA/security approval, release gates, threat-model process/baseline, classification bypass inventory, license/dependency approval workflow, security/supply-chain scanning policy, OSCAL evidence, and cross-suite test harnesses.

**Exclusive paths and contracts.** `/docs/security/`, `/docs/governance/`, `/docs/testing/`, `/specs/traceability/`, `/specs/oscal/`, `/tests/` harness and cross-system suites (module owners retain their named subtrees as specified in the layout ledger), `/docs/contributor/quality/`, release-gate configuration, and `/packages/test-fixtures/` shared fixture contracts. `/docs/planning/` has a separate project-manager integration owner and requires `WS-13` validation.

**Assigned requirements.** `PRIN-010`; `SEC-001`, `SEC-002`, `SEC-003`, `SEC-004`, `SEC-005`, `SEC-006`; `TEST-001`, `TEST-002`, `TEST-003`, `TEST-004`, `TEST-005`, `TEST-006`, `TEST-007`, `TEST-008`, `TEST-009`, `TEST-010`.

**Required verification contracts.** All nineteen required test layers; traceability/schema validation; coverage/mutation floors; threat and bypass regression tests; SAST/secret/dependency/license/container/IaC scans; SBOM/signature/provenance checks; accessibility and load reviews; backup/restore/install/upgrade gates; golden scenario; release waiver expiration enforcement.

**Dependencies and outputs.** Begins with `M0-A`, independently reviews `M0-C` and `M0-D`, owns `M0-E`, and co-signs `M0-F`. Receives testable contracts and evidence from every workstream.

**Prohibited boundaries.** An implementation owner cannot be its own final approver. `WS-13` cannot waive locked decisions, disclosure paths, failed authorization/classification models, missing backup/restore, missing release evidence, or disallowed/unknown distributed licenses. A critical/high vulnerability waiver must be documented and time-bounded; a known unauthorized disclosure has no release waiver.

**Security/classification.** Threat findings become tracked requirements/tests. Test data, logs, failure artifacts, SBOMs, waivers, vulnerability reports, and OSCAL statements are handled according to their contents and never imply certification, accreditation, FIPS validation, or compliance outcomes.

**Phase 0 definition of done.** All 128 requirement IDs have owners and planned tests; the threat/bypass and license workflows are actionable; release gates have objective evidence; both golden scenarios and classification matrices are executable plans; independent approval identities and separation-of-duties rules are recorded; `M0-F` may be signed only with no unresolved blocking gap.

## Completeness check

The allocation above assigns one accountable owner to every directive ID family:

`PRIN-001..015`, `ARCH-001..005`, `STD-001..002`, `DOM-001..011`, `SCM-001..006`, `DOC-001..005`, `UX-001..009`, `AUTH-001..006`, `CLS-001..008`, `EVT-001..004`, `ACT-001`, `NOTIF-001..002`, `AUD-001..002`, `SRCH-001..003`, `GRAPH-001..002`, `STOR-001..003`, `ART-001`, `CICD-001..005`, `MIG-001..005`, `DEP-001..005`, `OPS-001..005`, `SEC-001..006`, `TEST-001..010`, and `AGENT-001..007`.

This is an accountability allocation, not permission to implement before Phase 0 approval.
