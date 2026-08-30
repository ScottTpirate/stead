# Phase 0 Contract Ownership Matrix

Status: **Ready for Phase 0 sign-off; no Phase 1 implementation is authorized**<br>
Normative source: `docs/architecture/MASTER_BUILD_DIRECTIVE.md` version 0.2

This registry gives every Phase 0 contract one editor and one merge lane. “Sole editor” is literal: consumers and reviewers may propose patches or review diffs, but they may not concurrently edit the registered contract. The contract owner integrates accepted changes.

## Mandatory change and merge protocol

Every contract change request (`CCR`) must contain:

1. contract ID and current/target semantic version;
2. linked requirement IDs and implementation issues;
3. reason and compatibility classification: `editorial`, `compatible-additive`, `behavioral`, or `breaking`;
4. machine-readable diff where applicable;
5. affected producers, consumers, modules, provider versions, policies, and direct access paths;
6. authorization, classification, non-disclosure, and audit impact;
7. migration, coexistence/deprecation window, backward compatibility, upgrade order, and rollback behavior;
8. tests and fixtures added or changed;
9. documentation and observability impact;
10. required approvals listed below.

The contract registry/lock ledger must record `contract_id`, `owner`, `active_ccr`, `editor`, `base_revision`, `opened_at`, and `state`. Only one active editing CCR is allowed for a contract ID. Parallel analysis is allowed; parallel contract edits are not. If a change spans contracts, one integration CCR lists the ordered sub-changes and each sole editor lands its part in dependency order.

Generated artifacts are never hand-edited. The source contract lands first, its validation and compatibility tests pass, then the owning generator regenerates consumers. Implementation and database migrations land only after the contract change. A breaking public API, event, schema, provider, ontology, security, or locked-decision change requires a new major version, migration/coexistence period, ADR, and project-owner approval. There is no emergency route that bypasses `WS-06` security or `WS-13` independent validation.

### Protocol codes

| Code | Applies to | Required approval and integration rule |
|---|---|---|
| `C-ARCH` | OWGP, common/canonical schema, OpenAPI, standards profile | Sole editor integrates after domain review, `WS-01` architecture approval, `WS-06` security approval, and `WS-13` conformance approval. If the sole editor is `WS-01`, another named `WS-01` reviewer must perform the review. Locked/breaking changes also need ADR and project owner. |
| `C-PUBLIC` | Public/BFF HTTP API | `WS-01` alone edits/merges source OpenAPI. Relevant domain owner reviews semantics; `WS-02` reviews feasibility/transaction behavior; `WS-05` reviews client usability; `WS-06` and `WS-13` approve security and compatibility. Generated clients follow in a separate `WS-05` change. |
| `C-PROVIDER` | Provider port, adapter-facing contract, provider webhook | Named capability owner alone edits/merges its isolated provider-sdk subtree after `WS-01`, `WS-06`, `WS-13`, and all implementation owners approve. Adapters may not expand the interface locally. |
| `C-POLICY` | OpenFGA, deterministic policy-decision contracts, label/lattice, security/deployment policy | `WS-06` alone edits executable security contracts. Domain policy owners propose inputs and review semantics; `WS-13` independently approves test coverage/mutation and bypass results; `WS-01` approves compatibility. Lowering or weakening policy also needs project owner and ADR when a locked decision is affected. |
| `C-EVENT` | CloudEvents envelope, payload, subject, AsyncAPI, retention/replay | `WS-07` alone edits/merges. Producer and every known consumer review; `WS-06` approves payload/subject protection; `WS-13` approves schema/replay/idempotency tests; `WS-01` approves versioning. Producer code lands before/with compatible consumers; breaking changes use dual-publish/dual-read migration. |
| `C-MODULE` | Module public port and module behavior contract | Named module owner alone edits its module. `WS-02` integrates core wiring or `WS-07` integrates worker wiring. `WS-06` approves enforcement points and `WS-13` approves tests. A module must not expose its tables as an API. |
| `C-DB` | Logical namespace, tables, indexes, migrations | Namespace owner alone edits migrations. `WS-02` reviews transaction/module boundaries; `WS-06` reviews labels/tenancy/security; `WS-12` reviews upgrade/backup/restore; `WS-13` approves forward/backward/rollback tests. Cross-namespace writes are rejected. |
| `C-QA` | Traceability, threat/release/license/test contracts | `WS-13` alone edits/merges after the relevant contract owner, `WS-01`, and `WS-06` review. The implementation owner cannot provide final QA/security approval. Gate weakening requires project-owner approval; locked-decision impact requires ADR. |

Approval means an explicit recorded approval against the reviewed commit. “Project owner” is not a workstream and may not be substituted by the implementation agent.

## Canonical and public schema registry

All canonical JSON schemas use JSON Schema 2020-12. Resource schemas compose the common envelope; they do not fork or copy it. These rows are the complete Phase 0 canonical schema inventory. Adding another first-class resource is prohibited without ontology ADR and project-owner approval.

Within `SCH-PRINCIPAL`, the `service_account` discriminator denotes the DOM-002 **Service Principal** entity; it does not define a second service-identity entity. `directory_group` is a membership/authorization subject but cannot act. Agent and Agent Run are canonical schemas, while orchestration and AgentRun execution remain outside Phase 0.

| Contract ID / schema | Source path | Sole editor | Required reviewers / approvers | Primary consumers | Protocol / merge rule |
|---|---|---|---|---|---|
| `SCH-COMMON-RESOURCE` | `/packages/domain-schemas/common/resource-envelope/` | `WS-01` | domain owners; approve `WS-06`, `WS-13` | all modules, API, events, exports | `C-ARCH`; land before resource schemas |
| `SCH-RELATIONSHIP` | `/packages/domain-schemas/common/relationship/` | `WS-01` | `WS-02`, `WS-08`; approve `WS-06`, `WS-13` | all resources, graph, search, migration | `C-ARCH`; cardinality/direction compatibility required |
| `SCH-PROVENANCE` | `/packages/domain-schemas/common/provenance/` | `WS-01` | `WS-04`, `WS-11`; approve `WS-06`, `WS-13` | resources, migration, export, audit | `C-ARCH`; W3C PROV mapping test required |
| `SCH-EXTERNAL-REFERENCE` | `/packages/domain-schemas/common/external-reference/` | `WS-01` | `WS-03`, `WS-11`; approve `WS-06`, `WS-13` | provider mappings, redirects, migration | `C-ARCH` |
| `SCH-PROBLEM-DETAILS` | `/packages/domain-schemas/common/problem-details/` | `WS-01` | `WS-02`, `WS-05`; approve `WS-06`, `WS-13` | API/client/CLI | `C-ARCH`; RFC 9457 and non-leak tests |
| `SCH-EXPORT-MANIFEST` | `/packages/domain-schemas/common/export-manifest/` | `WS-01` | `WS-10`, `WS-11`, `WS-12`; approve `WS-06`, `WS-13` | export/import/backup/exitability | `C-ARCH`; round-trip and portable-locator tests |
| `SCH-INSTANCE` | `/packages/domain-schemas/resources/instance/` | `WS-01` | `WS-02`, `WS-12`; approve `WS-06`, `WS-13` | core, config, API, export | `C-ARCH` |
| `SCH-ORGANIZATION` | `/packages/domain-schemas/resources/organization/` | `WS-01` | `WS-02`; approve `WS-06`, `WS-13` | organization, auth, providers, API | `C-ARCH` |
| `SCH-PRINCIPAL` discriminated reference: `user`, `agent`, `service_account`, `directory_group` | `/packages/domain-schemas/identity/principal/` | `WS-06` | `WS-01`, `WS-02`, `WS-07`, `WS-08`; approve `WS-13`, project owner | actors, assignments, ownership, OpenFGA/policy-decision, API/events/audit | `C-POLICY`; only user/agent/service_account may act; Work assignment uses the narrower user/agent `SCH-WORK-ASSIGNMENT`; human-only assumptions forbidden |
| `SCH-USER` | `/packages/domain-schemas/identity/user/` | `WS-06` | `WS-01`, `WS-07`, `WS-11`; approve `WS-13` | identity, auth, SCIM, audit, export | `C-ARCH`; trusted/self-asserted fields separated |
| `SCH-DIRECTORY-GROUP` | `/packages/domain-schemas/identity/directory-group/` | `WS-06` | `WS-01`, `WS-02`; approve `WS-13` | identity, Team membership sync, authorization, export | `C-POLICY`; never an acting principal |
| `SCH-SERVICE-PRINCIPAL` | `/packages/domain-schemas/identity/service-principal/` | `WS-06` | `WS-01`, `WS-07`, `WS-09`; approve `WS-13` | identity, auth, CI, MCP, audit | `C-ARCH`; short-lived credential semantics |
| `SCH-AGENT` | `/packages/domain-schemas/identity/agent/` | `WS-06` | `WS-01`, `WS-02`, `WS-08`; approve `WS-07`, `WS-13`, project owner | identity, assignment, authorization, events/audit, future registry/MCP/A2A | `C-POLICY`; registration metadata only in Phase 0; no runtime coupling |
| `SCH-AGENT-RUN` | `/packages/domain-schemas/identity/agent-run/` | `WS-06` | `WS-01`, `WS-02`, `WS-07`, `WS-08`; approve `WS-13`, project owner | future task-scoped authorization, events/audit, MCP/A2A | `C-POLICY`; state/provenance contract only; no Phase 0 execution |
| `SCH-TEAM` | `/packages/domain-schemas/resources/team/` | `WS-01` | `WS-02`, `WS-06`; approve `WS-13` | organization, auth, SCM, API | `C-ARCH`; stable parent relation is acyclic and never implies authorization |
| `SCH-INITIATIVE` | `/packages/domain-schemas/resources/initiative/` | `WS-01` | `WS-02`, `WS-08`; approve `WS-06`, `WS-13` | project/work/graph/API | `C-ARCH` |
| `SCH-PROJECT` | `/packages/domain-schemas/resources/project/` | `WS-01` | `WS-02`, `WS-03`, `WS-04`, `WS-05`; approve `WS-06`, `WS-13` | project, work, knowledge, optional SCM/delivery, API | `C-ARCH`; owning/contributing Teams, lifecycle, preset, capabilities; repository is optional |
| `SCH-PROJECT-CAPABILITY` fixed capability and preset registry | `/packages/domain-schemas/resources/project-capability/` | `WS-01` | `WS-02`, `WS-03`, `WS-04`, `WS-05`; approve `WS-06`, `WS-13`, project owner | Project schema/API, navigation, providers, migration | `C-ARCH`; system-defined only; dependencies validated; no configurable ontology |
| `SCH-CYCLE` | `/packages/domain-schemas/resources/cycle/` | `WS-01` | `WS-02`, `WS-03`; approve `WS-06`, `WS-13` | work, milestone mapping, API | `C-ARCH` |
| `SCH-WORK-ITEM` | `/packages/domain-schemas/resources/work-item/` | `WS-01` | `WS-02`, `WS-03`, `WS-04`; approve `WS-06`, `WS-13` | work, optional Gitea mapping, knowledge, search, migration | `C-ARCH`; general types deliverable/task/problem, fixed statuses/priorities/nesting |
| `SCH-WORK-ASSIGNMENT` provider-independent assignee reference | `/packages/domain-schemas/resources/work-assignment/` | `WS-02` | `WS-01`, `WS-03`; approve `WS-06`, `WS-13` | Work Item schema/API, Gitea mapping, search/events/audit | `C-MODULE`; accepts `agent` principal even where Gitea projection must map only native users; assignment grants no execution authority |
| `SCH-DOCUMENT` | `/packages/domain-schemas/resources/document/` | `WS-01` | `WS-02`, `WS-04`; approve `WS-06`, `WS-13` | organization/team/project knowledge, search, migration, API | `C-ARCH`; exactly one Organization/Team/Project container, general fixed type/state, Git/OKF identity |
| `SCH-REPOSITORY` | `/packages/domain-schemas/resources/repository/` | `WS-01` | `WS-03`; approve `WS-06`, `WS-13` | SCM, project, CI, search, migration | `C-ARCH`; one effective container label |
| `SCH-BRANCH` | `/packages/domain-schemas/resources/branch/` | `WS-01` | `WS-03`; approve `WS-06`, `WS-13` | SCM, knowledge review, CI | `C-ARCH` |
| `SCH-COMMIT` | `/packages/domain-schemas/resources/commit/` | `WS-01` | `WS-03`, `WS-09`; approve `WS-06`, `WS-13` | SCM, CI, graph, search | `C-ARCH` |
| `SCH-PULL-REQUEST` | `/packages/domain-schemas/resources/pull-request/` | `WS-01` | `WS-03`, `WS-04`; approve `WS-06`, `WS-13` | SCM, knowledge review, work, inbox | `C-ARCH` |
| `SCH-BUILD` | `/packages/domain-schemas/resources/build/` | `WS-01` | `WS-09`; approve `WS-06`, `WS-13` | CI, search, graph, release | `C-ARCH` |
| `SCH-DEPLOYMENT` | `/packages/domain-schemas/resources/deployment/` | `WS-01` | `WS-09`, `WS-12`; approve `WS-06`, `WS-13` | CI, release, audit, graph | `C-ARCH` |
| `SCH-RELEASE` | `/packages/domain-schemas/resources/release/` | `WS-01` | `WS-03`, `WS-09`; approve `WS-06`, `WS-13` | SCM, artifact, graph, API | `C-ARCH` |
| `SCH-PACKAGE` | `/packages/domain-schemas/resources/package/` | `WS-01` | `WS-03`, `WS-09`; approve `WS-06`, `WS-13` | SCM package, artifact, search | `C-ARCH` |
| `SCH-ARTIFACT` | `/packages/domain-schemas/resources/artifact/` | `WS-01` | `WS-09`, `WS-10`; approve `WS-06`, `WS-13` | CI, BlobStore, release, search | `C-ARCH` |
| `SCH-ATTACHMENT` | `/packages/domain-schemas/resources/attachment/` | `WS-01` | `WS-04`, `WS-10`; approve `WS-06`, `WS-13` | knowledge, work, storage, migration | `C-ARCH`; provider locator excluded |
| `SCH-COMMENT` | `/packages/domain-schemas/resources/comment/` | `WS-01` | `WS-02`, `WS-03`, `WS-04`, `WS-07`; approve `WS-06`, `WS-13` | work/docs/PR/inbox/activity | `C-ARCH` |
| `SCH-ACTIVITY` | `/packages/domain-schemas/resources/activity/` | `WS-01` | `WS-07`, `WS-08`; approve `WS-06`, `WS-13` | activity projection, API, search | `C-ARCH`; ActivityStreams mapping |
| `SCH-NOTIFICATION` | `/packages/domain-schemas/resources/notification/` | `WS-01` | `WS-07`; approve `WS-06`, `WS-13` | inbox/channels/API | `C-ARCH`; reason/thread/redaction semantics |
| `SCH-AUDIT-RECORD` | `/packages/domain-schemas/resources/audit-record/` | `WS-01` | `WS-07`, `WS-12`; approve `WS-06`, `WS-13` | audit store/export/security review | `C-ARCH`; append-only and controlled-delta semantics |
| `SCH-ACTOR-CONTEXT` acting principal/type, initiating/requesting principal, delegation/task context, correlation/causation | `/packages/event-schemas/common/actor-context/` | `WS-07` | `WS-01`, `WS-02`, `WS-08`; approve `WS-06`, `WS-13` | CloudEvents, audit, activity, notifications, API request context | `C-EVENT`; supports `requested_by=user:alice` and `actor=agent:backend-agent` without schema change |
| `SCH-SECURITY-LABEL` | `/packages/domain-schemas/security/security-label/` | `WS-06` | `WS-01` plus every container owner; approve `WS-13`, project owner | all resources/policies/providers/search/events/exports | `C-POLICY`; lattice and downgrade tests block merge |
| `SCH-TRUSTED-ATTRIBUTE` | `/packages/domain-schemas/identity/trusted-attribute/` | `WS-06` | `WS-01`; approve `WS-13` | identity, OpenFGA context, policy-decision layer | `C-POLICY`; authority/provenance/expiry mandatory |
| `SCH-DEPLOYMENT-DOMAIN` | `/packages/domain-schemas/security/deployment-domain/` | `WS-06` | `WS-12`, `WS-01`; approve `WS-13`, project owner | install config, policy-decision layer, providers, runners | `C-POLICY` |
| `SCH-PLATFORM-CONFIG` | `/packages/domain-schemas/config/` | `WS-12` | all provider owners, `WS-01`; approve `WS-06`, `WS-13` | steadctl/deploy/stead-api/stead-worker | `C-ARCH`; no secret values in rendered/exported schema |
| `PROFILE-OWGP` | `/specs/work-graph-profile/` | `WS-01` | all domain owners; approve `WS-06`, `WS-13`, project owner | schemas/API/export/import/graph | `C-ARCH`; v0.1 required before domain implementation |
| `PROFILE-OKF` | `/specs/okf-profile/` | `WS-04` | `WS-01`, `WS-11`; approve `WS-06`, `WS-13` | knowledge/Commonplace/migration/export | `C-ARCH`; compatible with OKF 0.2 and deterministic Markdown |
| `PROFILE-OSCAL` | `/specs/oscal/` | `WS-13` | `WS-06`, `WS-01`; project owner acknowledges claims | security evidence/operator docs | `C-QA`; no authorization/compliance claim |

## Public and provider-facing API registry

`WS-01` is the sole editor for `/specs/openapi/`, including all operation groups. Domain workstreams own implementation semantics but do not directly edit OpenAPI; they submit a CCR to `WS-01`.

| Contract ID / operation group | Sole editor | Required domain reviewers | Approvers | Consumers | Merge/integration rule |
|---|---|---|---|---|---|
| `API-HTTP-BASE` authentication context, canonical IDs/URIs, pagination, RFC 9457, ETags, versioning | `WS-01` | `WS-02`, `WS-05`, `WS-12` | `WS-06`, `WS-13` | web, CLI, MCP, external clients | `C-PUBLIC`; lands before every group |
| `API-ORGANIZATION` Instance/Organization/Team | `WS-01` | `WS-02` | `WS-06`, `WS-13` | web, CLI, SCIM/admin | `C-PUBLIC` |
| `API-IDENTITY` Principal/User/Directory Group/Agent/Agent Run/Service Principal schemas and provisioning status | `WS-01` | `WS-06`, `WS-08` | `WS-13` | web admin, CLI, integrations, future MCP/A2A | `C-PUBLIC`; Phase 0 publishes representation seams only, not Agent Registry behavior or execution; trusted attributes never self-editable |
| `API-AUTHORIZATION` permission/explanation-safe decision operations | `WS-01` | `WS-06` | `WS-13`, project owner | core, provider gateways, admin UI | `C-PUBLIC`; explanation cannot leak protected existence |
| `API-PROJECT-WORK` Initiative/Project/preset/capabilities/Team ownership/Cycle/Work Item/assignment/Comment/relationship | `WS-01` | `WS-02`, `WS-03`, `WS-05` | `WS-06`, `WS-13` | web, CLI, future MCP, migration | `C-PUBLIC`; Work is provider-neutral and assignee may be an agent despite Gitea limits |
| `API-KNOWLEDGE` Organization/Team/Project-scoped Document/edit/review/publish/attachment | `WS-01` | `WS-04`, `WS-10` | `WS-06`, `WS-13` | web, Commonplace headless client, CLI, MCP | `C-PUBLIC`; container authorization and Git security boundary remain explicit |
| `API-SCM` Repository/Branch/Commit/Pull Request/provider admin escape | `WS-01` | `WS-03` | `WS-06`, `WS-13` | web, CLI, MCP | `C-PUBLIC`; never proxies undocumented Gitea internals |
| `API-CI-ARTIFACT` Build/Deployment/Release/Package/Artifact/runner/action catalog | `WS-01` | `WS-09`, `WS-10` | `WS-06`, `WS-13` | web, CLI, automation | `C-PUBLIC` |
| `API-SEARCH-GRAPH` typed multi-resource search/count/facet/suggestion/relationship traversal | `WS-01` | `WS-08` | `WS-06`, `WS-13` | web, CLI, future MCP | `C-PUBLIC`; canonical resource discriminator and authoritative filtering before any response metadata |
| `API-AGENT-ACCESS-SEAM` canonical resource operations reusable by future platform-wide MCP | `WS-01` | `WS-08`, all affected domain owners | `WS-06`, `WS-13`, project owner | future external agent runtimes/MCP gateway | `C-PUBLIC`; Phase 0 preserves API compatibility only and defines no full MCP tool catalog, runtime, orchestration, model, memory, or A2A dispatch |
| `API-ACTIVITY-INBOX` Activity/Notification/subscription | `WS-01` | `WS-07` | `WS-06`, `WS-13` | web, external channel workers | `C-PUBLIC` |
| `API-AUDIT` authorized audit query/export | `WS-01` | `WS-07`, `WS-12` | `WS-06`, `WS-13`, project owner | security/admin UI, SIEM export | `C-PUBLIC`; content administration does not imply read access |
| `API-MIGRATION` discover/dry-run/import/delta/cutover/report/redirect | `WS-01` | `WS-11` | `WS-06`, `WS-13` | web, steadctl | `C-PUBLIC` |
| `API-OPERATIONS` health/version/migration/config-safe-view/backup/restore/upgrade reports | `WS-01` | `WS-12` | `WS-06`, `WS-13` | steadctl, operator tooling | `C-PUBLIC`; secrets and protected data excluded |
| `API-EXPORT-IMPORT` portable organization/resource export/import | `WS-01` | `WS-10`, `WS-11`, `WS-12` | `WS-06`, `WS-13` | steadctl, external portability clients | `C-PUBLIC`; cross-domain/write-down remains denied |

Provider-facing ingress APIs are owned with their interfaces: Gitea webhook/API compatibility by `WS-03`, Commonplace headless/auth contract by `WS-04`, OIDC/SCIM callbacks by `WS-06`, external notification adapters by `WS-07`, storage signed-URL callbacks by `WS-10`, and migration source APIs by `WS-11`. None becomes a second public product API.

Future agents use canonical Platform APIs and the platform-wide MCP seam owned by `WS-08`; they must not use provider-specific business APIs. Direct Git protocol operations against the configured SCM provider are the sole stated exception and require scoped credentials. Future A2A interoperability and Agent Registry records should remain compatible with A2A Agent Card semantics, but Phase 0 does not implement registry behavior or dispatch.

## Provider interface registry

| Contract ID / interface | Source path | Sole editor | Reviewers / approvers | Implementations and consumers | Protocol / merge rule |
|---|---|---|---|---|---|
| `P-SCM-REPOSITORY` `RepositoryProvider` | `/packages/provider-sdk/scm/repository/` | `WS-03` | approve `WS-01`, `WS-06`, `WS-13` | Gitea; scm/project/core | `C-PROVIDER` |
| `P-SCM-GIT` `GitProvider` | `/packages/provider-sdk/scm/git/` | `WS-03` | approve `WS-01`, `WS-06`, `WS-13` | Gitea; scm/knowledge/core | `C-PROVIDER`; SSH/HTTPS/LFS bypass semantics explicit |
| `P-SCM-PR` `PullRequestProvider` | `/packages/provider-sdk/scm/pull-request/` | `WS-03` | `WS-04`; approve `WS-01`, `WS-06`, `WS-13` | Gitea; scm/work/knowledge | `C-PROVIDER` |
| `P-SCM-ISSUE` `IssueProvider` | `/packages/provider-sdk/scm/issue/` | `WS-03` | `WS-02`; approve `WS-01`, `WS-06`, `WS-13` | Gitea; work/scm | `C-PROVIDER`; canonical fixed mapping |
| `P-SCM-BOARD` `ProjectBoardProvider` | `/packages/provider-sdk/scm/project-board/` | `WS-03` | `WS-02`; approve `WS-01`, `WS-06`, `WS-13` | Gitea; work/scm | `C-PROVIDER`; fixed columns only |
| `P-SCM-MILESTONE` `MilestoneProvider` | `/packages/provider-sdk/scm/milestone/` | `WS-03` | `WS-02`; approve `WS-01`, `WS-06`, `WS-13` | Gitea; work/scm | `C-PROVIDER` |
| `P-SCM-ACTIONS` `ActionsProvider` | `/packages/provider-sdk/scm/actions/` | `WS-03` | `WS-09`; approve `WS-01`, `WS-06`, `WS-13` | Gitea; ci | `C-PROVIDER` |
| `P-SCM-PACKAGE` `PackageProvider` | `/packages/provider-sdk/scm/package/` | `WS-03` | `WS-09`; approve `WS-01`, `WS-06`, `WS-13` | Gitea; artifact | `C-PROVIDER` |
| `P-SCM-RELEASE` `ReleaseProvider` | `/packages/provider-sdk/scm/release/` | `WS-03` | `WS-09`; approve `WS-01`, `WS-06`, `WS-13` | Gitea; artifact | `C-PROVIDER` |
| `P-SCM-ORGANIZATION` `OrganizationProvider` | `/packages/provider-sdk/scm/organization/` | `WS-03` | `WS-02`, `WS-06`; approve `WS-01`, `WS-13` | Gitea; organization/scm | `C-PROVIDER` |
| `P-SCM-PERMISSION` `PermissionSyncProvider` | `/packages/provider-sdk/scm/permission-sync/` | `WS-03` | approve `WS-01`, `WS-06`, `WS-13` | Gitea; authorization/scm | `C-PROVIDER`; central policy remains authoritative |
| `P-SCM-WEBHOOK` `WebhookProvider` | `/packages/provider-sdk/scm/webhook/` | `WS-03` | `WS-07`; approve `WS-01`, `WS-06`, `WS-13` | Gitea; worker/scm | `C-PROVIDER`; HMAC/replay/idempotency mandatory |
| `P-KNOWLEDGE-GIT-AUTH` Commonplace Gitea Git/auth provider | `/packages/provider-sdk/knowledge/git-auth/` | `WS-04` | `WS-03`; approve `WS-01`, `WS-06`, `WS-13` | Commonplace; knowledge/scm | `C-PROVIDER`; upstream-first |
| `P-KNOWLEDGE-HEADLESS` embeddable/headless docs interface | `/packages/provider-sdk/knowledge/headless/` | `WS-04` | `WS-05`; approve `WS-01`, `WS-06`, `WS-13` | Commonplace/native fallback; web/knowledge | `C-PROVIDER`; no iframe or platform ontology in patch |
| `P-KNOWLEDGE-SHELL` design-token/navigation hooks | `/packages/provider-sdk/knowledge/shell-hooks/` | `WS-04` | `WS-05`; approve `WS-01`, `WS-06`, `WS-13` | Commonplace; design system/web | `C-PROVIDER` |
| `P-IDENTITY-OIDC` human authentication provider | `/packages/provider-sdk/identity/oidc/` | `WS-06` | `WS-12`; approve `WS-01`, `WS-13` | identity-oidc; core/web/steadctl | `C-PROVIDER` |
| `P-IDENTITY-SCIM` user/group provisioning provider | `/packages/provider-sdk/identity/scim/` | `WS-06` | `WS-11`; approve `WS-01`, `WS-13` | identity-scim; identity/migration | `C-PROVIDER` |
| `P-IDENTITY-ATTRIBUTE` trusted attribute authority | `/packages/provider-sdk/identity/trusted-attributes/` | `WS-06` | approve `WS-01`, `WS-13` | configured authorities; identity/policy-decision layer | `C-PROVIDER`; unverifiable/expired denies |
| `P-BLOBSTORE` `BlobStore` | `/packages/provider-sdk/blobstore/` | `WS-10` | `WS-04`, `WS-09`, `WS-12`; approve `WS-01`, `WS-06`, `WS-13` | filesystem/S3/Azure/GCS; knowledge/artifact/backup | `C-PROVIDER`; one suite must pass all implementations |
| `P-SEARCH` `SearchProvider` | `/packages/provider-sdk/search/` | `WS-08` | approve `WS-01`, `WS-06`, `WS-13` | PostgreSQL/OpenSearch; search/graph | `C-PROVIDER`; identical non-disclosure and rebuild semantics |
| `P-AGENT-A2A` `AgentA2AProvider` | `/specs/a2a/` and contract-only `/providers/agent-a2a/` | `WS-08` | all exposed domain owners; approve `WS-01`, `WS-06`, `WS-07`, `WS-13`, project owner | future external agent runtimes; `/modules/agent/` | `C-PROVIDER`; Phase 0 defines compatibility metadata only and prohibits dispatch, execution, runtime/model coupling, and provider-business-API access; it is the provider-interface alias of `INT-A2A-COMPAT` |
| `P-NOTIFICATION-CHANNEL` `NotificationChannel` | `/packages/provider-sdk/notifications/` | `WS-07` | approve `WS-01`, `WS-06`, `WS-13` | email/webhook and later Teams/Slack; notification | `C-PROVIDER`; channel authorization/redaction required |
| `P-SECRET` `SecretProvider` | `/packages/provider-sdk/secrets/` | `WS-09` | `WS-12`; approve `WS-01`, `WS-06`, `WS-13` | Kubernetes/basic and external adapters; CI/core/worker | `C-PROVIDER`; secrets never enter canonical payloads |
| `P-RUNNER-POOL` runner-pool execution/control interface | `/packages/provider-sdk/ci/runner-pool/` | `WS-09` | `WS-03`, `WS-12`; approve `WS-01`, `WS-06`, `WS-13` | Gitea Actions/runners; ci/steadctl | `C-PROVIDER`; domain/pool isolation explicit |
| `P-AUDIT-EXPORT` audit object-store/syslog/SIEM-webhook export | `/packages/provider-sdk/audit-export/` | `WS-07` | `WS-10`, `WS-12`; approve `WS-01`, `WS-06`, `WS-13` | audit exporters; audit/operator | `C-PROVIDER` |
| `P-MIGRATION-SOURCE` resumable migration source | `/packages/provider-sdk/migration/` | `WS-11` | affected destination owners; approve `WS-01`, `WS-06`, `WS-13` | GitHub/Jira/Confluence connectors; migration | `C-PROVIDER`; capability/unsupported inventory required |

### Future agent interoperability seam

| Contract ID / interface | Source | Sole editor | Reviewers / approvers | Consumers | Phase 0 rule |
|---|---|---|---|---|---|
| `INT-MCP-PLATFORM` platform-wide MCP-to-Platform-API boundary | `/docs/architecture/search-graph/mcp-a2a-compatibility.md` | `WS-08` | all exposed domain owners; approve `WS-01`, `WS-06`, `WS-07`, `WS-13`, project owner | future external agent runtimes | Compatibility contract only: same principal/auth/classification/audit/API path as human clients; no full tool catalog in Phase 0 |
| `INT-A2A-COMPAT` A2A and Agent Card compatibility constraints | `/docs/architecture/search-graph/mcp-a2a-compatibility.md` | `WS-08` | `WS-01`, `WS-06`; approve `WS-07`, `WS-13`, project owner | future Agent Registry and external agents | Reserve compatible identifiers/metadata only; no A2A dispatch, Agent Registry behavior, runtime, model, orchestration, prompting, or memory in Phase 0 |
| `INT-AGENT-GIT` scoped direct Git credential boundary | `/docs/architecture/search-graph/mcp-a2a-compatibility.md` | `WS-08` | `WS-03`, `WS-09`; approve `WS-01`, `WS-06`, `WS-13` | future external agents and configured SCM | Direct Git protocol only; scoped/short-lived credentials and provider/path enforcement; provider business APIs prohibited |

No generic “provider” escape hatch exists. A new capability or provider implementation must be added to this registry, pass the common contract suite, and satisfy license review before implementation.

## Provider implementation ownership

| Required provider directory | Sole editor | Contract(s) implemented | Mandatory integration reviewers |
|---|---|---|---|
| `/providers/gitea/` | `WS-03` | all `P-SCM-*` | `WS-01`, `WS-06`, `WS-07`, `WS-09`, `WS-13` |
| `/providers/commonplace/` | `WS-04` | `P-KNOWLEDGE-*` | `WS-01`, `WS-03`, `WS-05`, `WS-06`, `WS-13` |
| `/providers/blob-filesystem/` | `WS-10` | `P-BLOBSTORE` | `WS-06`, `WS-12`, `WS-13` |
| `/providers/blob-s3/` | `WS-10` | `P-BLOBSTORE` | `WS-06`, `WS-12`, `WS-13` |
| `/providers/blob-azure/` | `WS-10` | `P-BLOBSTORE` | `WS-06`, `WS-12`, `WS-13` |
| `/providers/blob-gcs/` | `WS-10` | `P-BLOBSTORE` | `WS-06`, `WS-12`, `WS-13` |
| `/providers/search-postgres/` | `WS-08` | `P-SEARCH` | `WS-06`, `WS-07`, `WS-13` |
| `/providers/search-opensearch/` | `WS-08` | `P-SEARCH` | `WS-06`, `WS-07`, `WS-12`, `WS-13` |
| `/providers/agent-a2a/` (contract-only in Phase 0) | `WS-08` | `P-AGENT-A2A` / `INT-A2A-COMPAT` | `WS-01`, `WS-06`, `WS-07`, `WS-13`, project owner |
| `/providers/identity-oidc/` | `WS-06` | `P-IDENTITY-OIDC` | `WS-01`, `WS-12`, `WS-13` |
| `/providers/identity-scim/` | `WS-06` | `P-IDENTITY-SCIM` | `WS-01`, `WS-11`, `WS-13` |
| `/providers/notifications-email/` | `WS-07` | `P-NOTIFICATION-CHANNEL` | `WS-06`, `WS-12`, `WS-13` |
| `/providers/notifications-webhook/` | `WS-07` | `P-NOTIFICATION-CHANNEL` | `WS-06`, `WS-12`, `WS-13` |

## Authorization, classification, and governance policy contracts

`/policies/policy-decision/` is the canonical, implementation-neutral contract root for deterministic classification, contextual/attribute, handling, information-flow, CI/infrastructure, and explicit-deny decisions. No row requires OPA or Rego. An approved ADR may later select an implementation such as an adapter under `/providers/policy-opa/` without changing these contracts.

| Contract ID / policy model | Source | Sole editor | Required reviewers / approvers | Consumers | Protocol / merge rule |
|---|---|---|---|---|---|
| `POL-FGA-V0.1` organization/team/project inheritance; repository reader/writer/maintainer; document reader/editor/reviewer; work viewer/editor/assignee; release approver; security officer/classification manager; delegated service/agent access | `/policies/openfga/` | `WS-06` | every module/provider owner; approve `WS-01`, `WS-13`, project owner | core, provider sync/gateways, tests | `C-POLICY`; reserves first-class `agent`, explicit user-to-agent delegation, task scope, independent revocation, and resource assignment; no broad human permission inheritance; model migration/tuple compatibility required |
| `POL-DECISION-IO-V0.1` decision input/output, reason-safe result, bundle metadata | `/policies/policy-decision/` | `WS-06` | all policy-input owners; approve `WS-01`, `WS-13`, project owner | stead-api, provider gateways, steadctl, audit | `C-POLICY`; principal type is mandatory and future inputs reserve agent runtime, security domain, profile-qualified classification ceilings, compartment, model provider, tool scope, and execution environment; contract lands before evaluator-specific implementation |
| `POL-DECISION-CLASSIFICATION` profile-defined dominance, handling, categories/compartments, dissemination/releasability, export, and trusted-subject restrictions | `/policies/policy-decision/classification/` | `WS-06` | `WS-13`; approve `WS-01`, project owner | all protected operations | `C-POLICY`; 100% decision-table coverage; no profile-ID-specific branches |
| `POL-DECISION-CONTEXT` auth strength, device, network/zone, session profile-qualified ceilings, time/expiry | `/policies/policy-decision/context/` | `WS-06` | `WS-12`; approve `WS-01`, `WS-13` | all protected operations/provider paths | `C-POLICY` |
| `POL-DECISION-FLOW` export/download/share, downgrade/write-down, cross-domain deny | `/policies/policy-decision/data-flow/` | `WS-06` | `WS-10`, `WS-11`, `WS-12`; approve `WS-01`, `WS-13`, project owner | exports, blobs, migration, backups | `C-POLICY`; no built-in cross-domain allow |
| `POL-DECISION-CI` runner, artifact, deployment, secret, action-catalog policy | `/policies/policy-decision/ci/` | `WS-06` | `WS-09`; approve `WS-01`, `WS-13` | CI/runners/artifacts | `C-POLICY` |
| `POL-DECISION-INFRA` infrastructure admission and deployment-domain policy | `/policies/policy-decision/infrastructure/` | `WS-06` | `WS-12`; approve `WS-01`, `WS-13` | steadctl/Helm/admission integrations | `C-POLICY` |
| `POL-DECISION-ORG-DENY` explicit organization denies | `/policies/policy-decision/organization-deny/` | `WS-06` | `WS-02`; approve `WS-01`, `WS-13` | central authorization | `C-POLICY`; cannot redefine ontology/workflow |
| `POL-LABEL-PROFILE` profile schema, vocabulary, normalization, dominance/join, presentation, and lowering rules | `/policies/security-label-profiles/` | `WS-06` | all container owners; approve `WS-01`, `WS-13`, project owner | domains, events, UI, search, exports, providers | `C-POLICY`; declarative signed/versioned data only, property/mutation tests, stable IDs have no code semantics |
| `POL-LABEL-STARTERS` checked-in starter/reference profile sources | `/policies/security-label-profiles/*.yaml` | `WS-06` | `WS-01`, `WS-12`; approve `WS-13`, project owner | conformance and deployment examples | `C-POLICY`; authoritative mappings state sources/scope/version/provenance/limitations and make no completeness or compliance claim |
| `POL-DEPLOYMENT-DOMAIN` profile-qualified ceilings, trusted authorities, signed bridges, integration/egress/storage/backup/runner and assurance controls | `/policies/deployment-domains/` | `WS-06` | `WS-12`; approve `WS-01`, `WS-13`, project owner | stead-api, stead-worker, steadctl, providers, deployment, release | `C-POLICY`; every ceiling names a profile/version; assurance and signature thresholds are data-driven; cross-profile composition fails closed without an approved signed bridge |
| `POL-SCM-REPOSITORY` branch/review/check/signing/visibility/runner/retention declaration | `/modules/scm/contracts/repository-policy/` | `WS-03` | `WS-02`, `WS-09`; approve `WS-01`, `WS-06`, `WS-13` | organization/team/project policy reconciliation | `C-MODULE`; scope declarations cannot bypass OpenFGA or the deterministic policy-decision layer |
| `POL-LICENSE-DEPENDENCY` license allow/deny/review and dependency intake | `/docs/governance/license-and-dependency-approval.md` plus gate config | `WS-13` | all owners; approve `WS-01`, project owner/legal approver | CI, release, contributors | `C-QA`; disallowed/unknown default reject |
| `POL-RELEASE-GATES` objective release/evidence/waiver policy | `/docs/governance/release-gates.md` plus release-gate config | `WS-13` | all owners; approve `WS-01`, `WS-06`, project owner | CI/release management | `C-QA`; implementation owner cannot self-approve |

## Event contract catalog

All rows use the `EVT-CLOUDEVENT-BASE` envelope, the subject form `stead.<domain>.<action>.v<major>`, JSON Schema 2020-12, and AsyncAPI 3.1.x. `WS-07` is the sole editor of every event schema and channel; the named producer owner defines semantics by review rather than editing the shared contract.

| Contract ID / subject family | Producer owner(s) | Required reviewers / approvers | Consumers | Merge/integration rule |
|---|---|---|---|---|
| `EVT-CLOUDEVENT-BASE` envelope, actor/delegation/task context, retention/replay/idempotency metadata | `WS-07` framework | all producers; approve `WS-01`, `WS-06`, `WS-13` | every publisher/consumer | `C-EVENT`; uses `SCH-ACTOR-CONTEXT`; base lands first |
| `EVT-ORGANIZATION` `stead.organization.*` and team changes | `WS-02` | `WS-03`, `WS-06`; approve `WS-13` | auth, scm, search, audit, notification | `C-EVENT` |
| `EVT-IDENTITY` `stead.identity.*` | `WS-06` | `WS-11`; approve `WS-13` | auth, audit, notification, migration | `C-EVENT` |
| `EVT-AUTHORIZATION` model/tuple/decision-policy changes (no sensitive decision content) | `WS-06` | approve `WS-13` | audit, cache invalidation, provider sync | `C-EVENT` |
| `EVT-CLASSIFICATION` label/profile/attribute/profile-qualified-ceiling/approval changes | `WS-06` | all projection/container owners; approve `WS-13`, project owner for downgrade semantics | search, notification, audit, providers, exports, caches | `C-EVENT`; invalidation/reconciliation acknowledgment required |
| `EVT-PROJECT` `stead.project.*`, initiative/cycle | `WS-02` | `WS-03`, `WS-04`; approve `WS-06`, `WS-13` | scm, knowledge, search, graph, activity | `C-EVENT` |
| `EVT-WORKITEM` `stead.workitem.*` and Work Item relationships | `WS-02` | `WS-03`; approve `WS-06`, `WS-13` | scm reconciliation, search, graph, activity, inbox | `C-EVENT` |
| `EVT-COMMENT` `stead.comment.*` across Work, Docs, and Pull Requests | `WS-02`, `WS-03`, `WS-04` through their owned domain operations | all three producers; approve `WS-06`, `WS-13` | activity, inbox, audit, search where enabled | `C-EVENT`; one canonical schema despite multiple provider/container origins |
| `EVT-KNOWLEDGE` `stead.document.*` and document review | `WS-04` | `WS-03`, `WS-10`; approve `WS-06`, `WS-13` | search, graph, activity, inbox, audit | `C-EVENT` |
| `EVT-SCM` repository/branch/commit/PR/provider reconciliation | `WS-03` | `WS-02`, `WS-04`, `WS-09`; approve `WS-06`, `WS-13` | work, knowledge, CI, search, graph, activity | `C-EVENT` |
| `EVT-CI` build/deployment/runner/action events | `WS-09` | `WS-03`; approve `WS-06`, `WS-13` | artifact, search, graph, activity, inbox, audit | `C-EVENT` |
| `EVT-ARTIFACT` package/artifact/release events | `WS-09` | `WS-03`, `WS-10`; approve `WS-06`, `WS-13` | search, graph, activity, inbox, audit | `C-EVENT` |
| `EVT-ATTACHMENT` canonical attachment metadata/lifecycle | `WS-09` | `WS-02`, `WS-04`, `WS-10`; approve `WS-06`, `WS-13` | work, knowledge, storage, migration, audit | `C-EVENT`; bytes and provider locators excluded |
| `EVT-STORAGE` blob scan/retention/provider-operation events | `WS-10` | `WS-04`, `WS-09`; approve `WS-06`, `WS-13` | artifact/knowledge/audit/notification | `C-EVENT`; provider locator excluded |
| `EVT-SEARCH-GRAPH` projection lifecycle/rebuild diagnostics | `WS-08` | approve `WS-06`, `WS-13` | operations/audit only | `C-EVENT`; never becomes authoritative resource change |
| `EVT-NOTIFICATION` notification lifecycle/channel delivery | `WS-07` | approve `WS-06`, `WS-13` | inbox, adapters, audit | `C-EVENT`; redaction decision attached without protected body |
| `EVT-AUDIT` checkpoint/export lifecycle (not duplicate business contents) | `WS-07` | `WS-12`; approve `WS-06`, `WS-13` | audit export/operations | `C-EVENT` |
| `EVT-MIGRATION` migration job/stage/reconciliation/cutover | `WS-11` | destination owners; approve `WS-06`, `WS-13` | UI/CLI, audit, notification, search | `C-EVENT` |
| `EVT-OPERATIONS` install/upgrade/backup/restore/doctor lifecycle | `WS-12` | authoritative-store owners; approve `WS-06`, `WS-13` | audit, operator UI/CLI | `C-EVENT`; no config secret or backup content |
| `EVT-DEAD-LETTER` controlled failure diagnostic/replay | `WS-07` framework | producer/consumer owners; approve `WS-06`, `WS-13` | authorized operators/audit | `C-EVENT`; diagnostic content minimized and protected |

## Module contract and integration registry

| Required module | Sole editor | Owned public module contract | Required reviewers / approvers | Consumers and integration rule |
|---|---|---|---|---|
| `/modules/organization/` | `WS-02` | Instance/Organization/Team operations and ports | `WS-01`, `WS-06`, `WS-13` | core integrated only by `WS-02`; providers consume ports |
| `/modules/identity/` | `WS-06` | principal kinds/references, provisioning, trusted-attribute operations | `WS-01`, `WS-02`, `WS-07`, `WS-08`, `WS-13` | core wiring by `WS-02`; worker wiring by `WS-07`; permits future `agent` principals without implementing Agent Registry/execution |
| `/modules/authorization/` | `WS-06` | central combined-decision service and audit-safe result | `WS-01`, all module owners, `WS-13` | every protected module/provider calls it; reserves agent/delegation/task authority seams; no substitute logic |
| `/modules/classification/` | `WS-06` | effective label/join/raise/downgrade/container decision | `WS-01`, all container owners, `WS-13` | every protected module/projection/provider; fail closed |
| `/modules/project/` | `WS-02` | Initiative/Project/Cycle operations and ports | `WS-01`, `WS-03`, `WS-04`, `WS-06`, `WS-13` | core integrated only by `WS-02` |
| `/modules/work/` | `WS-02` | fixed Work Item workflow/relationship/assignment operations | `WS-01`, `WS-03`, `WS-06`, `WS-13` | core by `WS-02`; Gitea via SCM port; canonical assignment accepts agent principals without execution behavior |
| `/modules/knowledge/` | `WS-04` | Git/OKF document/edit/review operations | `WS-01`, `WS-03`, `WS-06`, `WS-10`, `WS-13` | core by `WS-02`; worker by `WS-07` through registered ports |
| `/modules/scm/` | `WS-03` | canonical SCM operations, mapping, reconciliation | `WS-01`, `WS-02`, `WS-06`, `WS-13` | core/worker integration by respective composition owners |
| `/modules/ci/` | `WS-09` | workflow/build/deployment/runner operations | `WS-01`, `WS-03`, `WS-06`, `WS-13` | core/worker integration via ports |
| `/modules/artifact/` | `WS-09` | Package/Artifact/Release and blob-reference operations | `WS-01`, `WS-03`, `WS-06`, `WS-10`, `WS-13` | BlobStore is a port; no provider locator in domain |
| `/modules/search/` | `WS-08` | search/work-graph projection and query ports | `WS-01`, all resource owners, `WS-06`, `WS-13` | worker registration by `WS-07`; API core wiring by `WS-02` |
| `/modules/agent/` (contract-only in Phase 0) | `WS-08` | future Agent Registry/Card/Run interoperability port and MCP/A2A boundary | `WS-01`, `WS-02`, `WS-03`, `WS-06`, `WS-07`, `WS-13`, project owner | may consume canonical Platform API and scoped-Git contracts only; Phase 0 permits schemas/compatibility fixtures but no registry behavior, dispatch, execution, orchestration, prompting, model hosting, memory, or full MCP catalog |
| `/modules/notification/` | `WS-07` | inbox/grouping/subscription/channel operations | `WS-01`, all event producers, `WS-06`, `WS-13` | worker/core composition owned by `WS-07`/`WS-02` |
| `/modules/audit/` | `WS-07` | append-only audit/activity projection/export operations | `WS-01`, all audited owners, `WS-06`, `WS-12`, `WS-13` | no module may suppress required audit; worker registration by `WS-07` |
| `/modules/migration/` | `WS-11` | migration job/stage/mapping/redirect operations | all destination owners, `WS-01`, `WS-06`, `WS-13` | core/worker/CLI integrate through approved ports |

All module changes follow `C-MODULE`; module data changes additionally follow `C-DB`. The absence of a separate `activity`, `graph`, or `storage` module is intentional: activity is a projection under audit, graph is a projection under search, and BlobStore implementations are providers referenced by canonical domain modules. Creating another top-level module requires an ADR because the required layout and fixed ontology are controlled.

## Relational and external datastore ownership

These are logical namespaces. Phase 0 must decide physical PostgreSQL schema mechanics without weakening this ownership; changing a namespace owner requires an ADR. “Write authority” includes migrations, DDL, DML repositories, and repair tools.

| Namespace/store | Authoritative contents | Sole schema/table editor and write authority | Permitted consumers | Boundary and merge rule |
|---|---|---|---|---|
| `organization.*` | platform Instance/Organization/Team domain state | `WS-02` | other modules through organization port | `C-DB`; no foreign writes |
| `identity.*` | platform principal references/kinds, links, provisioning state, trusted-authority sync metadata; external IdP remains source for asserted attributes | `WS-06` | through identity port | `C-DB`; no self-asserted trusted attributes and no Phase 0 Agent Registry/runtime tables |
| `authorization.*` | platform authorization model/bundle/version references and reconciliation metadata; OpenFGA store holds supported model/tuples | `WS-06` | through authorization port | `C-DB`; no local substitute decisions |
| `classification.*` | labels, profile versions, derivation/review/approval records | `WS-06` | through classification port | `C-DB`; downgrade records immutable/audited |
| `project.*` | Initiative/Project/Cycle and owned relationships | `WS-02` | through project port | `C-DB` |
| `work.*` | canonical work metadata/relationships not stored in Gitea, plus provider mapping | `WS-02` | through work port; `WS-03` reconciles via port | `C-DB`; Gitea issues remain mapped engine state, no table reads |
| `knowledge.*` | stable document identity, workflow/relationship/approval metadata; Git Markdown is document body/system of record | `WS-04` | through knowledge port | `C-DB`; no body-only authoritative database copy |
| `scm.*` | canonical provider mappings, reconciliation and declared policy state | `WS-03` | through scm port | `C-DB`; Gitea DB strictly inaccessible |
| `ci.*` | canonical workflow/build/deployment/runner metadata and policy state | `WS-09` | through ci port | `C-DB` |
| `artifact.*` | canonical Package/Artifact/Release/Attachment metadata and blob references | `WS-09` | `WS-10` only through BlobStore reference contract | `C-DB`; binary/provider locator not exposed |
| `search.*` | rebuildable search and relationship-graph projections/checkpoints | `WS-08` | authorized search/graph port only | `C-DB`; never authoritative; full rebuild required |
| `notification.*` | canonical in-app notification, thread/grouping, channel-delivery state | `WS-07` | notification port only | `C-DB`; protected content minimized |
| `audit.*` | append-only audit and rebuildable activity projection/checkpoints | `WS-07` | authorized audit/activity ports | `C-DB`; append-only; no destructive mutation API |
| `migration.*` | job/stage/checkpoint/mapping/quarantine/redirect/report state | `WS-11` | migration port, steadctl/API | `C-DB`; resumable/idempotent and protected |
| `core_outbox.*` | transactional event intents and delivery claims | `WS-02` | domain modules invoke transaction-scoped outbox port; `WS-07` publisher uses the owned delivery repository | `C-DB`; no raw table access outside the two reviewed ports; domain change and insert atomic |
| consumer-local processed-event tables | idempotency keys/checkpoints for a consumer's durable effects | the destination module owner | `WS-07` framework through consumer port | `C-DB`; located in destination namespace; no shared global ordering assumption |
| Gitea database/schema | Gitea-owned engine state | stock Gitea only | platform uses documented APIs/webhooks/Git protocols | no platform DDL/DML/query; version/digest pinned and contract tested |
| OpenFGA database/schema | OpenFGA model/tuple datastore | stock OpenFGA only | `WS-06` module uses supported API/tools | no platform DDL/DML/query; separate DB/schema boundary |
| Git repositories | source code and Markdown/OKF document contents/history | Git/Gitea through supported Git/provider operations | authorized SCM/knowledge ports | repository is clone/access/classification boundary |
| Blob/object stores | attachment and large binary bytes | `WS-10` provider implementations through `P-BLOBSTORE` | authorized domain operations and backup/restore | portable manifest; provider locator hidden; partitioned by domain |
| NATS JetStream | transport, replay, work distribution | `WS-07` stream administration | authorized publishers/consumers | never authoritative business database |
| OpenSearch | optional rebuildable search projection | `WS-08` through `P-SEARCH` | authorized search module | never authoritative; label/domain partitioning |

No owner may grant a migration, importer, analytics job, support utility, MCP server, or test harness direct write access to another namespace. Repairs use the owning module contract or an owner-authored, audited migration.

## Integration freeze rule

Phase 1 work may start only after every Phase 0 row required by the golden slice has:

- an approved version and immutable baseline revision;
- no active conflicting CCR;
- requirement/test/document links;
- named producer/consumer and schema compatibility tests;
- authorization/classification/audit behavior;
- migration, upgrade, backward-compatibility, and rollback behavior;
- architecture (`WS-01`), security-contract (`WS-06`), separate independent QA and security approvals from distinct `WS-13` reviewer identities, and project-owner approval.

After freeze, owners may work in parallel only on distinct registered paths/contracts. Any integration conflict returns to the sole editor/integration owner; it is not resolved by concurrent edits to the shared contract.
