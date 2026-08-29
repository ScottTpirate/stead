# Golden vertical-slice scenarios and executable test plan

Status: **Approved Phase 0 test contract; Phase 1 implementation is dependency-ordered**
Primary requirements: `TEST-009`, `TEST-010`, `TEST-002`–`TEST-008`, `AUTH-006`, `CLS-006`–`CLS-008`, `EVT-001`–`EVT-004`, `AGENT-001`–`AGENT-007`

Phase 1 must prove two paths in one product and canonical model. The general-work path is independently useful and never creates a code repository. The software path is an additive capability extension. A pass requires all positive and negative assertions before and after restore and supported upgrade; retries preserve the first failure and cannot convert it to pass.

## Shared fixture and environment

- `ORG-ALPHA`; parent `TEAM-OPERATIONS`; child `TEAM-PEOPLE`; contributing `TEAM-LEGAL`.
- `ID-AUTHOR`, `ID-REVIEWER`, `ID-LOW`, `ID-NO-NTK`, and `ID-SECURITY-OFFICER` with synthetic trusted attributes.
- `AGENT-BACKEND` and contract-only `AGENT-RUN-SHAPE`; no runtime or execution endpoint.
- commercial protected label below the deployment ceiling plus negative compartment/ceiling fixtures.
- clean local install with pinned Gitea, PostgreSQL, NATS, OpenFGA, the policy-decision layer, filesystem BlobStore, and PostgreSQL SearchProvider.

The harness records source revision; component/image/provider/schema/model/policy/profile versions and digests; fixture versions; OpenTelemetry correlation; safe state hashes; test results; retries; and reviewer identities.

## TEST-009 — General-work scenario

| ID | Action | Required assertions |
|---|---|---|
| `GWS-001-INSTALL` | Install the supported local profile. | NATS exists from start; no unapproved outbound call; health/config/install audit; no agent runtime. |
| `GWS-002-IDENTITY` | Authenticate `ID-AUTHOR`. | Trusted attributes include authority/version/review-or-expiry; short session; audit; no browser service credential. |
| `GWS-003-TEAMS` | Create Organization `ORG-ALPHA`, then parent/child Teams and explicit memberships. | Organization has a stable canonical ID; Team IDs are stable; same Organization; no cycle; depth ≤12; reparent audited; parent membership/view does not grant child view and inverse does not grant parent view. |
| `GWS-004-PROJECT` | Create `general` Project `ONB`, owned by People and contributed to by Legal. | Capabilities exactly Work+Docs; Project lifecycle `active`; ownership/contribution grants no access; Overview/Work/Docs only; no Code/Delivery/provider vocabulary. |
| `GWS-005-PROVISION` | Observe provisioning. | One hidden Gitea tracker repo/board and one docs repo; **no code repository**; provider APIs only; effective container policy reconciled. |
| `GWS-006-WORK` | Create `ONB-1` deliverable, update status, assign User then Agent. | Canonical type/status/priority/key; Gitea-backed content; agent assignment accepted canonically but grants neither view nor execution; ETag conflict; outbox/audit atomic. |
| `GWS-007-KNOWLEDGE` | Create an Organization policy, Team procedure, and Project specification. | Exactly one correct container each; stable ID/path independence; deterministic safe Markdown/OKF; separate Git container where policy differs. |
| `GWS-008-CONNECT` | Embed a live Work view, convert document text to Work, link Work and specification. | Live query is authorized at render; typed links/deep links/context strip; no copied stale task table; current context preserved in peek. |
| `GWS-009-EVENTS` | Process create/update/webhook events; force duplicate, restart, out-of-order, DLQ, replay. | Atomic outbox; one durable effect; per-resource order only; controlled replay; projections rebuild; actor/requester/correlation/causation preserved. |
| `GWS-010-ATTENTION` | Inspect Home, Inbox, Team/Project rollups, Activity, notifications, and search. | Useful authorized results across Team/Project/Work/Document/Person/Agent; counts/facets/suggestions/relationships filtered before response. |
| `GWS-011-NONDISCLOSURE` | Probe as low, no-need-to-know, security-officer, and parent-only principals via UI/API/search/graph/inbox/export/errors/raw Gitea/Git. | No title, ID, existence, count, snippet, suggestion, notification, relationship, timing/error distinction, or direct-path access. Security officer can manage policy metadata without content read. |
| `GWS-012-AGENT-SEAM` | Validate Agent, AgentRun, assignment, OpenFGA/policy-decision, audit/event, MCP/A2A schemas. | `requested_by=user:alice` and `actor=agent:backend-agent`; task/delegation/runtime/classification inputs; explicit independent revocation; no broad inheritance, runtime endpoint, dispatch, model/prompt/memory, or tool catalog. |
| `GWS-013-RECOVERY` | Backup; destroy only disposable deployment; restore cleanly. | All authoritative state/config/policy/audit/Git/blob data restored; IDs, hashes, labels, access, links stable; projections rebuild without NATS as sole source. |
| `GWS-014-UPGRADE` | Upgrade within supported matrix with injected failure. | Preflight, backup, expand/contract order, smoke, report, audit, and documented rollback or forward recovery; no acknowledged-write loss. |

TEST-009 fails if a code repository exists, Code/Delivery UI or software terminology appears, Team hierarchy causes access, or any denied metadata is observable.

## TEST-010 — Software-capability extension

Begin from the same shell/model and create a `software` Project `STEAD`, owned by an Engineering Team. Do not alter global navigation, canonical Work/Document values, object surfaces, or authorization flow.

| ID | Action | Required assertions |
|---|---|---|
| `SWS-001-CAPABILITIES` | Create software preset and inspect navigation. | Work+Docs+SCM+review+CI+packages+releases active; Code and Delivery visible only when authorized; Pull Requests under Code and build/package/release/artifact under Delivery. |
| `SWS-002-WORK-DOC` | Create `deliverable` and `problem`, specification and decision. | UI may display Feature/Bug and Architecture Decision; API/events/exports retain universal values. |
| `SWS-003-CODE` | Create code repo, branch, commit, and Pull Request linked to Work/Doc. | Project ≠ repository; tracker hidden; supported Gitea APIs/Git only; central permission reconciliation; canonical links. |
| `SWS-004-REVIEW-EVENT` | Request review and merge. | Authorized grouped Inbox/Activity; idempotent webhook; Work/Doc/PR graph; correlation/causation and audit complete. |
| `SWS-005-DELIVERY` | Run pinned approved action; create Build, SBOM, Artifact, Package, Release. | Isolated permitted runner, short credential, no secret leakage, OCI/SPDX/provenance/digest links, authorized download. |
| `SWS-006-SEARCH` | Query connected Project as allowed and denied principals. | Authorized Work/Docs/Code/Delivery results and graph only; no disabled/denied capabilities or aggregates. |
| `SWS-007-PROVIDER` | Run current, prior two minor, and next-candidate Gitea suites as applicable. | No database/internal API; compatibility/preflight evidence; raw provider remains restricted escape route. |
| `SWS-008-RECOVERY` | Repeat restore and supported upgrade smoke. | Canonical IDs/links/provenance remain; no permission/label weakening; provider rollback/forward recovery documented. |
| `SWS-009-CAPABILITY-CHANGE` | Restrict, deactivate, then re-enable an optional software capability. | Existing provider data and canonical links are preserved; hidden capability routes, navigation, counts, suggestions, events, and notifications do not leak; authorization is rechecked; re-enable restores the surface without identity or provenance changes. |

## Cross-cutting suites

| Layer | Required coverage |
|---|---|
| Schema/API/event | OWGP examples; OpenAPI/RFC 9457; AsyncAPI/CloudEvents; principal/container/capability/lifecycle; compatible evolution. |
| OpenFGA/policy-decision | Every relation/decision row; hierarchy non-inheritance; assignment non-grant; trusted expiry; agent intersection/revocation; 100% decision-row and ≥90% critical mutation coverage. |
| Unit/property/fuzz | fixed enums/cardinality, UUIDv7, hierarchy cycles/depth, capability dependencies, label join/no-lowering, Markdown/frontmatter, webhooks/importers. |
| Integration/replay | transaction+outbox, provider reconciliation, duplicate/out-of-order/restart/DLQ, authorized projection rebuild, audit completeness. |
| Browser/accessibility | both paths, six persona journeys, keyboard/screen reader parity, WCAG 2.2 AA, deep links/context preservation, no Devlane route/ontology dependency. |
| Security/classification | lower sensitivity, missing compartment/need-to-know, admin/security officer, expired data, downgrade, every bypass, export/backup/log/runner/cross-domain denial. |
| Operations | fresh install, doctor, no-network air gap when applicable, consistent backup/restore, supported upgrade, injected rollback/forward recovery. |
| Supply chain/performance | dependency/license/SBOM/signature/provenance gates and published reproducible SLO/load/chaos fixtures without leakage. |

## Evidence and release rule

The signed evidence manifest maps every assertion to requirements, source revision, artifacts, safe hashes, versions, duration, first failure, and independent reviewers. An unauthorized disclosure, acknowledged-write loss, label weakening, missing audit, non-restorable backup, secret leakage, prohibited dependency, unavailable general path, or accidental agent execution surface is release-blocking and has no ordinary waiver.
