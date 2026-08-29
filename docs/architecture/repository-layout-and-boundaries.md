# Phase 0 Repository Layout and Boundary Constitution

Status: **Ready for Phase 0 approval**<br>
Normative source: `docs/architecture/MASTER_BUILD_DIRECTIVE.md` version 0.2

This document records the required monorepo shape, exclusive edit ownership, dependency direction, integration roots, and logical data ownership. It is a planning contract, not authorization to scaffold or implement Phase 1 features. Top-level names and boundaries may change only through an approved ADR.

## Required layout and exclusive owners

```text
/apps
  /web                    WS-05  Devlane-derived unified frontend
  /core                   WS-02  Go public API/BFF and composition root
  /worker                 WS-07  Go async composition root and eventing runtime
  /platformctl            WS-12  install/upgrade/backup/restore/doctor CLI

/modules
  /organization           WS-02
  /identity               WS-06  generalized principal seams; no Phase 0 agent runtime
  /authorization          WS-06
  /classification         WS-06
  /project                WS-02
  /work                   WS-02  provider-independent principal assignment
  /knowledge              WS-04
  /scm                    WS-03
  /ci                     WS-09
  /artifact               WS-09
  /search                 WS-08  includes graph projection and future platform-wide MCP boundary
  /notification           WS-07
  /audit                  WS-07  includes activity and actor/requester/delegation context
  /migration              WS-11
  /agent                  WS-08  contract-only future Agent Registry/run interoperability; no Phase 0 execution

/providers
  /gitea                  WS-03
  /commonplace            WS-04
  /blob-filesystem        WS-10
  /blob-s3                WS-10
  /blob-azure             WS-10
  /blob-gcs               WS-10
  /search-postgres        WS-08
  /search-opensearch      WS-08
  /identity-oidc          WS-06
  /identity-scim          WS-06
  /notifications-email    WS-07
  /notifications-webhook  WS-07
  /agent-a2a              WS-08  compatibility contract only; no Phase 0 dispatch

/packages
  /domain-schemas         WS-01 integration owner; WS-06 owns identity/security subtrees
  /provider-sdk           WS-01 base conventions; each interface subtree has one domain owner
  /event-schemas          WS-07
  /design-system          WS-05
  /api-client             WS-05; generated from WS-01 OpenAPI source
  /test-fixtures          WS-13 shared-fixture integration owner

/policies
  /openfga                WS-06
  /opa                    WS-06
  /security-label-profiles WS-06

/specs
  /openapi                WS-01
  /asyncapi               WS-07
  /work-graph-profile     WS-01
  /okf-profile            WS-04
  /oscal                  WS-13
  /traceability           WS-13  Phase 0 requirement inventory and matrix
  /mcp                    WS-08  platform-wide compatibility seam; no Phase 0 tool catalog
  /a2a                    WS-08  Agent Card/message compatibility seam; no Phase 0 dispatch

/deploy
  /compose                WS-12
  /helm                   WS-12
  /airgap                 WS-12
  /examples               WS-12

/tests
  /contract               WS-13 harness; isolated owner subtrees below
  /integration            WS-13 harness; isolated owner subtrees below
  /e2e                    WS-13
  /security               WS-13
  /performance            WS-13 harness; WS-12 benchmark-data subtree
  /upgrade                WS-12, independently approved by WS-13
  /backup-restore         WS-12, independently approved by WS-13
  /classification         WS-13; WS-06 supplies policy-unit suites under /policies

/docs
  /architecture           split by the explicit ledger below
  /adr                    WS-01
  /governance             WS-13  license/dependency and release-gate artifacts
  /planning               project-manager integration owner; WS-13 validates
  /security               WS-13  threat model and bypass inventory
  /testing                WS-13  golden scenario and cross-suite test plans
  /operator               WS-12
  /user                   WS-05 integration owner
  /contributor            WS-13 integration owner
```

The missing top-level `activity`, `graph`, and `storage` modules are deliberate. Activity is a rebuildable projection under `audit`; the work graph is a rebuildable projection under `search`; BlobStore is a provider interface used by canonical domain modules. Creating a new module, provider root, or first-class entity requires an ADR and ontology/boundary review.

## Fine-grained shared-directory ledger

The following subpaths override only their parent integration owner. A path not delegated here remains editable only by the parent owner.

| Path | Sole editor | Boundary purpose |
|---|---|---|
| `/packages/domain-schemas/common/` | `WS-01` | common resource envelope, relationship, provenance, external reference, errors, exports |
| `/packages/domain-schemas/resources/` | `WS-01` | canonical entity schemas; domain owners review but do not concurrently edit |
| `/packages/domain-schemas/identity/` | `WS-06` | PrincipalRef (`user`, `agent`, `service_account`, `directory_group`), User, Directory Group, Service Principal, Agent, Agent Run, trusted attributes; only user/agent/service_account may act |
| `/packages/domain-schemas/security/` | `WS-06` | SecurityLabel and deployment-domain schemas |
| `/packages/domain-schemas/config/` | `WS-12` | installation/effective configuration schema |
| `/packages/domain-schemas/resources/work-assignment/` | `WS-02` | provider-independent Work Item assignee reference; leaf override under the WS-01 resource-schema integration tree |
| `/packages/provider-sdk/core/` | `WS-01` | provider contract conventions, error/capability/version rules |
| `/packages/provider-sdk/scm/` | `WS-03` | twelve capability-specific Gitea/SCM ports |
| `/packages/provider-sdk/knowledge/` | `WS-04` | Commonplace Git/auth, headless, and shell-hook ports |
| `/packages/provider-sdk/identity/` | `WS-06` | OIDC, SCIM, and trusted-attribute authority ports |
| `/packages/provider-sdk/notifications/` | `WS-07` | NotificationChannel |
| `/packages/provider-sdk/audit-export/` | `WS-07` | audit object-store/syslog/SIEM-webhook export |
| `/packages/provider-sdk/search/` | `WS-08` | SearchProvider |
| `/modules/agent/`, `/providers/agent-a2a/`, `/specs/mcp/`, `/specs/a2a/` | `WS-08` | contract-only future Agent Registry, MCP, and A2A seams; no execution, tool catalog, or dispatch in Phase 0 |
| `/packages/provider-sdk/ci/` | `WS-09` | runner-pool/control contracts |
| `/packages/provider-sdk/secrets/` | `WS-09` | SecretProvider |
| `/packages/provider-sdk/blobstore/` | `WS-10` | BlobStore |
| `/packages/provider-sdk/migration/` | `WS-11` | resumable source-connector contract |
| `/packages/test-fixtures/architecture/` | `WS-01` | schema/OWGP/API conformance fixtures |
| `/packages/test-fixtures/core/` | `WS-02` | core/module/outbox fixtures |
| `/packages/test-fixtures/gitea/` | `WS-03` | supported-version/provider fixtures |
| `/packages/test-fixtures/knowledge/` | `WS-04` | Markdown/OKF/Commonplace fixtures |
| `/packages/test-fixtures/frontend/` | `WS-05` | accessible component/API-client fixtures |
| `/packages/test-fixtures/security/` | `WS-06` | principals, labels, attributes, policy cases; no live secrets |
| `/packages/test-fixtures/events/` | `WS-07` | CloudEvents/replay/DLQ fixtures |
| `/packages/test-fixtures/search/` | `WS-08` | authorized search/graph corpora |
| `/packages/test-fixtures/ci/` | `WS-09` | actions/runner/artifact/secret fixtures |
| `/packages/test-fixtures/storage/` | `WS-10` | BlobStore parity/partition fixtures |
| `/packages/test-fixtures/migration/` | `WS-11` | GitHub/Jira/Confluence import corpora |
| `/packages/test-fixtures/operations/` | `WS-12` | install/upgrade/restore/air-gap datasets |
| `/packages/test-fixtures/harness/` | `WS-13` | cross-suite metadata and golden expected outcomes |
| `/docs/architecture/constitution.md` | `WS-01` | current Phase 0 principles, locked decisions, and boundary constitution |
| `/docs/architecture/agent-ready-compatibility.md` | `WS-01` | current AGENT-001..007 compatibility overlay; `WS-02`, `WS-06`, `WS-07`, `WS-08`, and `WS-13` are required reviewers |
| `/docs/architecture/standards/` | `WS-01` | standards profiles and compatibility rules |
| `/docs/architecture/ontology/` | `WS-01` | OWGP and canonical ontology governance |
| `/docs/architecture/core/` | `WS-02` | core transactions/outbox/module integration |
| `/docs/architecture/scm/` | `WS-03` | Gitea capability and reconciliation design |
| `/docs/architecture/knowledge/` | `WS-04` | Git/OKF/Commonplace/editor/review design |
| `/docs/architecture/frontend/` | `WS-05` | shell/design/accessibility/performance decisions |
| `/docs/architecture/identity-authorization-classification/` | `WS-06` | identity, models, labels, bypass enforcement design |
| `/docs/architecture/events-audit-notifications/` | `WS-07` | NATS, events, activity, inbox, audit design |
| `/docs/architecture/search-graph/` | `WS-08` | projection, provider, MCP, authorization filtering design |
| `/docs/architecture/ci-artifacts-secrets/` | `WS-09` | Actions, runners, supply chain, SecretProvider design |
| `/docs/architecture/storage/` | `WS-10` | BlobStore, object security, retention/export design |
| `/docs/architecture/migration/` | `WS-11` | import state machine, mappings, redirects |
| `/docs/architecture/operations/` | `WS-12` | install, OTel, backup/restore, upgrade, air gap |
| `/docs/architecture/workstream-ownership.md` | `WS-01` Phase 0 integration lane | thirteen-workstream accountability ledger |
| `/docs/architecture/contract-ownership-matrix.md` | `WS-01` Phase 0 integration lane | sole-editor contract registry |
| `/docs/architecture/repository-layout-and-boundaries.md` | `WS-01` Phase 0 integration lane | this boundary ledger |
| `/docs/adr/` | `WS-01` | current ADR template and unresolved implementation-choice register |
| `/docs/security/threat-model.md` | `WS-13` | current baseline/system/module threat model and finding ledger |
| `/docs/security/classification-bypass-inventory.md` | `WS-13` | current direct-path bypass inventory and planned proofs |
| `/docs/governance/license-and-dependency-approval.md` | `WS-13` | current license/dependency intake and legal approval workflow |
| `/docs/governance/release-gates.md` | `WS-13` | current independent QA/security release gates and waiver rules |
| `/docs/testing/golden-vertical-slice.md` | `WS-13` | current golden scenario and test plan |
| `/specs/traceability/directive-inventory.yaml` | `WS-13` | current machine-readable normative directive inventory |
| `/specs/traceability/requirements.yaml` | `WS-13` | current machine-readable requirements-to-issues/tests/doc matrix |
| `/docs/planning/epic-issue-hierarchy.md` | project-manager integration owner | current dependency-ordered epic/issue hierarchy; `WS-01`, `WS-06`, and `WS-13` review |
| `/docs/planning/implementation-issue-catalog.yaml` | project-manager integration owner | current machine-readable implementation issue contracts; `WS-13` validates required fields |
| `/docs/planning/phase-0-artifact-backlog.md` | project-manager integration owner | current Phase 0 artifact backlog; all artifact owners review their rows |

No two rows overlap at the same leaf path. Parent owners integrate directory-wide tooling and moves but must not change a delegated leaf contract without its owner.

`/packages/event-schemas/common/actor-context/` is owned solely by `WS-07`. It is the shared audit/event representation for acting principal and type, initiating/requesting principal when different, delegation/task context when present, and correlation/causation IDs. Domain owners consume it rather than define human-only actor fields.

## Test-tree edit ownership

Implementation unit/property tests live beside owned module/provider code. Cross-boundary tests live under `/tests` and have these edit rules:

| Test path | Sole editor | Required contributors/reviewers |
|---|---|---|
| `/tests/contract/harness/` | `WS-13` | all contract owners |
| `/tests/contract/architecture/` | `WS-01` | `WS-06`, `WS-13` review |
| `/tests/contract/gitea/` | `WS-03` | `WS-06`, `WS-13` review |
| `/tests/contract/commonplace/` | `WS-04` | `WS-03`, `WS-05`, `WS-06`, `WS-13` review |
| `/tests/contract/identity-authorization/` | `WS-06` | `WS-01`, `WS-13` review |
| `/tests/contract/events/` | `WS-07` | producer/consumer owners, `WS-06`, `WS-13` review |
| `/tests/contract/search/` | `WS-08` | `WS-06`, `WS-13` review |
| `/tests/contract/ci/` | `WS-09` | `WS-03`, `WS-06`, `WS-13` review |
| `/tests/contract/blobstore/` | `WS-10` | `WS-06`, `WS-12`, `WS-13` review |
| `/tests/contract/migration/` | `WS-11` | destination owners, `WS-06`, `WS-13` review |
| `/tests/contract/operations/` | `WS-12` | all component owners, `WS-06`, `WS-13` review |
| `/tests/integration/<module-or-provider>/` | owner of that module/provider | `WS-06` and `WS-13`; `WS-02` or `WS-07` for composition boundary |
| `/tests/e2e/` | `WS-13` | `WS-05` and scenario-step owners contribute expected behavior by CCR |
| `/tests/security/` | `WS-13` | `WS-06` and affected owner review; implementation owner cannot final-approve |
| `/tests/classification/` | `WS-13` | `WS-06` supplies decision tables and reviews expected policy behavior |
| `/tests/performance/harness/` | `WS-13` | `WS-12`, `WS-08`, affected owners |
| `/tests/performance/datasets/` | `WS-12` | `WS-08`, `WS-13` review |
| `/tests/upgrade/` | `WS-12` | provider/module owners; `WS-13` independent approval |
| `/tests/backup-restore/` | `WS-12` | every authoritative-store owner; `WS-06`, `WS-13` approval |

`WS-13` owns final golden-scenario assertions and release-gate configuration. An implementation workstream may not weaken or edit away an independent expected result to make its implementation pass.

## Dependency direction

Allowed compile-time/runtime dependency direction is:

```text
platform-web
  -> generated api-client + design-system
  -> versioned platform HTTP API only

platform-core composition root
  -> module public contracts
  -> central authorization/classification contract
  -> provider interfaces
  -> platform PostgreSQL through module-owned repositories

platform-worker composition root
  -> event/outbox framework
  -> module-owned handlers/reconcilers/projectors through registered ports
  -> provider interfaces

domain module
  -> common canonical schemas/value types
  -> Principal references for actors, assignees, creators, reviewers, subscribers, and request principals
  -> its own repositories/tables
  -> another module's public port only when an approved dependency exists
  -> provider interface, never provider implementation

provider implementation
  -> its capability-specific provider-sdk interface
  -> documented upstream API/protocol/client
  -> no domain table and no alternate authorization logic

platformctl
  -> supported administrative platform API and deployment/backup interfaces
  -> never ad hoc writes to module or upstream tables

future external agent runtime
  -> platform-wide MCP interface
  -> canonical versioned Platform API and shared authorization/classification/audit path
  -> scoped direct Git protocol credentials only when Git operations are required
  -> never provider-specific business APIs or unrestricted provider/storage/database access
```

Cross-module cycles are prohibited. A proposed module dependency must be documented with direction, transaction/consistency semantics, failure behavior, authorization context, event alternative, and cycle check. Prefer synchronous ports only when the caller needs an immediate authoritative decision/result; use versioned events for decoupled projections and retryable side effects.

### Shared composition roots

- `WS-02` alone edits `/apps/core` wiring. Other owners expose module/provider constructors and submit an integration request; `WS-02` binds them after contract and boundary tests pass.
- `WS-07` alone edits `/apps/worker` wiring. Other owners expose idempotent handlers through module contracts and submit a registration request; `WS-07` binds subjects, queues, DLQ, telemetry, and shutdown behavior.
- `WS-05` alone edits `/apps/web`; no backend owner may add a direct provider call to accelerate a feature.
- `WS-12` alone edits `/apps/platformctl` and deployment composition; component owners contribute health/config/backup/upgrade contracts, not ad hoc CLI code.
- `WS-08` alone edits the Phase 0 future-agent interoperability seam under `/docs/architecture/search-graph/mcp-a2a-compatibility.md`. It preserves MCP, A2A, and Agent Card compatibility without implementing a tool catalog, registry behavior, dispatch, runtime, model, orchestration, prompting, or memory.

## Database and system-of-record boundaries

Exact physical PostgreSQL schema naming is a Phase 0 implementation choice, but the following logical namespaces and write owners are fixed. Whether implemented as PostgreSQL schemas or another enforceable namespacing convention must be resolved before database implementation and may not weaken owner isolation.

| Logical namespace | Sole migration/write owner | System-of-record qualification |
|---|---|---|
| `organization.*` | `WS-02` | authoritative platform organization/team state |
| `identity.*` | `WS-06` | authoritative platform principal-reference/linkage/sync state; trusted assertions remain sourced from configured authorities; Phase 0 defines Agent/AgentRun schemas but no runtime, dispatch, or execution tables |
| `authorization.*` | `WS-06` | authoritative platform model/bundle/reconciliation metadata; OpenFGA supported datastore holds model/tuples |
| `classification.*` | `WS-06` | authoritative label/profile/derivation/approval state |
| `project.*` | `WS-02` | authoritative Initiative/Project/Cycle platform state |
| `work.*` | `WS-02` | authoritative platform-only work metadata/graph and Gitea mapping; mapped issue body/comments/labels/board state reside in Gitea |
| `knowledge.*` | `WS-04` | authoritative platform document identity/workflow/relationship metadata; Git Markdown/frontmatter/history is the content system of record |
| `scm.*` | `WS-03` | authoritative mapping/reconciliation/declared policy state; not a copy of Gitea internals |
| `ci.*` | `WS-09` | canonical CI/deployment/runner metadata and policy state |
| `artifact.*` | `WS-09` | canonical Package/Artifact/Release/Attachment metadata and blob references; bytes remain in Gitea/BlobStore as mapped |
| `search.*` | `WS-08` | rebuildable search/work-graph projection only |
| `notification.*` | `WS-07` | authoritative in-app notification/read/archive/channel-delivery state |
| `audit.*` | `WS-07` | append-only authoritative audit records plus rebuildable activity projection |
| `migration.*` | `WS-11` | authoritative migration jobs/checkpoints/mappings/quarantine/redirects/reports |
| `core_outbox.*` | `WS-02` | authoritative undelivered event intent coupled atomically to platform domain transactions |
| `<module>.*processed_event*` | destination module owner | local consumer idempotency/checkpoint state only |

Special access to `core_outbox.*` is narrow: modules request insertion through a `WS-02` transaction-scoped outbox port, and the `WS-07` publisher claims/marks delivery through a reviewed repository port. Neither receives unrestricted SQL ownership. Consumer processed-event records live in the destination owner's namespace.

External boundaries are absolute:

- Gitea uses its own database/schema. Only stock Gitea writes or queries it; the platform uses documented REST, webhook, Git, authentication, and configuration surfaces.
- OpenFGA uses its supported separate datastore. Only OpenFGA owns its tables; `WS-06` uses supported model/tuple/check APIs and migrations.
- Git repositories are authoritative for source and Markdown/OKF document content and form clone/read/security-label boundaries.
- Blob/object storage owns bytes behind `BlobStore`; canonical metadata and portable manifests remain provider-independent.
- NATS JetStream is transport/replay/work storage, never authoritative business data.
- OpenSearch and PostgreSQL search structures are rebuildable projections.
- Commonplace may not become a divergent document system of record; Git/OKF remains authoritative.

## Prohibited boundary inventory

The following are merge blockers, not style preferences:

| Boundary ID | Prohibited behavior | Required automated guard |
|---|---|---|
| `BND-001` | web/browser calls Gitea, Commonplace, OpenFGA, OPA, NATS, object storage, or another provider directly | frontend import/URL allowlist plus E2E network assertion |
| `BND-002` | platform queries/writes Gitea or OpenFGA internal tables | SQL/import static rule, runtime least-privilege DB credentials, provider contract tests |
| `BND-003` | module writes another module namespace | migration/path ownership check, DB role/privilege tests, integration mutation audit |
| `BND-004` | module imports provider implementation rather than port | Go dependency/layer rule and architecture test |
| `BND-005` | module implements local authorization/classification logic | protected-operation registry test and central-decision call assertion |
| `BND-006` | direct provider path exceeds central policy | SSH/HTTPS/LFS/API/token/package/artifact/runner/object/webhook bypass suite |
| `BND-007` | domain commit followed by best-effort direct publish | atomic outbox failure-injection test and forbidden publish dependency from domain modules |
| `BND-008` | projection becomes source of truth or leaks unauthorized aggregate metadata | rebuild-from-authority test and no-result/count/facet/snippet/graph leakage suite |
| `BND-009` | cloneable repository promises finer read secrecy than repository permission | schema/policy constraint and direct-clone classification test |
| `BND-010` | secret/protected body enters event, log, telemetry, search, frontend state, or audit unnecessarily | taint fixtures, log/event snapshot scans, secret scanning, telemetry assertions |
| `BND-011` | provider-specific fields or locators become canonical behavior | schema/API compatibility check and provider-parity contract suite |
| `BND-012` | source migration creates new ontology/workflow or silently drops data | canonical-enum validation and unsupported-construct completeness test |
| `BND-013` | air-gap/government profile makes an unapproved network call | network-disabled install/runtime test and egress capture |
| `BND-014` | implementation owner changes shared contract/test/gate concurrently or self-approves | contract lock/CODEOWNERS check and approval identity/separation gate |
| `BND-015` | unapproved license/dependency/action/image enters distributed output | dependency/SBOM/license/action pin/image digest gates |
| `BND-016` | actor/assignee/reviewer/subscriber/request contracts assume a human user rather than the principal kinds allowed at that field | schema lint and fixtures for acting `user`/`agent`/`service_account` contexts and the narrower `user`/`agent` Work-assignee union across API, event, and audit contracts |
| `BND-017` | agent broadly inherits delegator authority or omits task/runtime/classification intersection seams | OpenFGA/OPA model tests for explicit delegation, independent revocation, task scope, principal type, and reserved runtime/environment attributes |
| `BND-018` | future agent uses provider business API or unrestricted access instead of Platform API/MCP | agent-access architecture tests; only scoped direct Git protocol credentials are exempt |
| `BND-019` | Phase 0 implements agent orchestration, prompting, model hosting, agent memory, AgentRun execution, Agent Registry behavior, A2A dispatch, or full MCP tool catalog | scope/backlog and dependency guard; such work requires later approved issue/phase and any applicable ADR |

## Change integration sequence

For any cross-boundary change, merge in this order:

1. approved ADR if the change affects a locked decision, topology, ontology, security boundary, or breaking contract;
2. canonical/public schema or policy contract from its sole editor;
3. provider/module/event contract from its sole editor;
4. compatibility, security, and contract tests plus fixtures;
5. owner implementation in the isolated module/provider path;
6. database expand migration owned by that module, if any;
7. `WS-02` core or `WS-07` worker composition registration;
8. generated `WS-05` API client and UI integration, or `WS-12` CLI/deployment integration;
9. cross-system E2E, upgrade, backup/restore, and rollback evidence;
10. separate independent QA and security approvals from distinct `WS-13` reviewer identities.

Contract source, generated outputs, consumer implementations, and destructive/contract migrations must not be combined into an unreviewable concurrent edit. Expand/contract migrations keep old and new readers/writers compatible through the documented migration period.

## Phase 0 approval gate

This repository boundary contract is approved only when:

- all thirteen workstreams accept their exclusive paths and integration handoffs;
- every required module and provider appears exactly once with one sole editor;
- all canonical/public schemas, APIs, provider interfaces, policy models, events, and data namespaces appear in the contract matrix;
- architecture import and database-privilege tests exist in the Phase 0 artifact backlog;
- the threat/bypass inventory covers every direct provider and storage path;
- `WS-01`, `WS-06`, two distinct independent `WS-13` QA/security reviewer identities, and the project owner record approval against the same revision.

Until then, only Phase 0 documents, schemas, contracts, test plans, and validation scaffolding may be prepared; broad feature implementation remains blocked.

Agent-readiness in Phase 0 is limited to contract seams: generalized principals, provider-independent assignment, future delegation/task-aware authorization inputs, complete actor/requester audit/event context, and a platform-wide MCP/A2A compatibility boundary. It does not authorize agent execution functionality.
