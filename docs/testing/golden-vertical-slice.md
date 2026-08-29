# Golden vertical-slice scenario and test plan

**Status:** Draft Phase 0 test contract<br>
**Implements later:** Phase 1 executable slice; every release thereafter<br>
**Primary requirements:** TEST-009, TEST-002–008, AUTH-002, CLS-006–008, EVT-001–004, OPS-003–004, AGENT-001–007

This plan defines the first end-to-end proof of Stead's architecture. It does not authorize or implement the slice. The approved version becomes a release-blocking executable specification.

## 1. Purpose and pass rule

The scenario proves one identity, one authorization path, one Project, one Gitea-backed Work Item, one Git/OKF Document, one code repository and Pull Request, one reliable event stream, one inbox, one unified search result, one audit trail, and one supported installation.

The run passes only when all functional and negative assertions pass in one traceable run before and after backup/restore and supported upgrade. A UI success with a failing direct-provider, non-disclosure, audit, event, recovery, or compatibility assertion is a failure. Retrying a failed assertion without preserving the first failure evidence is prohibited.

## 2. Versioned fixtures

Fixture IDs are logical names; exact schema values come from the approved OWGP, security-label, OpenFGA, OPA, API, and event contracts.

| Fixture | Purpose |
|---|---|
| `ORG-ALPHA` / `TEAM-ATLAS` / `PROJ-STEAD` | One canonical organization, owning team, and project |
| `ID-AUTHOR` | Authenticated project member with the relationship, trusted attributes, session ceiling, and container access needed for the scenario |
| `ID-REVIEWER` | Authenticated designated reviewer with sufficient attributes and repository access |
| `ID-LOW` | Authenticated principal whose sensitivity/handling attributes do not dominate the protected project |
| `ID-NO-NTK` | Principal whose attributes dominate the label but who lacks the OpenFGA project relationship |
| `ID-SEC-OFFICER` | Security officer allowed to administer policy metadata but not granted content-read relationship |
| `SP-WORKER` | Short-lived, narrowly delegated worker principal |
| `PRINCIPAL-AGENT-SHAPE` | Non-executing schema/model fixture proving `agent` can be actor/assignee with separate `requested_by`, delegation/task context, revocation, and future runtime/policy attributes |
| `LABEL-PROTECTED` | Approved profile label below the installation ceiling and requiring a compartment/handling attribute |
| `WI-1` | Canonical `task`, initially `todo`, estimate from the fixed set, human key allocated from the tracker issue number |
| `DOC-1` | OKF-compatible `specification` stored as deterministic Markdown with stable ID and a typed `specifies` relationship to `WI-1` |
| `REPO-CODE-1` | Code repository linked to the Project and assigned the same enforceable container label/domain |
| `PR-1` / `BUILD-1` / `ART-1` / `REL-1` | Pull request, Gitea Action build, SBOM-bearing artifact, and release chain |

Test data must be synthetic and contain no credentials or protected real-world content. Time, UUIDv7 generation, provider responses, and failure injection are controllable by the harness. Secrets are injected out of band and redacted from all captured evidence.

## 3. Environment matrix

Every release runs the full golden scenario on at least one mandated installation profile. Profile-specific release suites expand the matrix under TEST-007.

| Run | Required topology | Identity | Search | Provider versions |
|---|---|---|---|---|
| Phase 1 architecture proof | Fresh `local` supported install | Test OIDC or documented local bootstrap followed by the normal platform session flow | PostgreSQL | Pinned current supported Gitea digest |
| Routine release candidate | Fresh local plus fresh lightweight Kubernetes | OIDC | PostgreSQL | Current and previous two supported Gitea minors |
| Compatibility signal | Contract/golden subset | OIDC | PostgreSQL | Next Gitea release candidate/nightly when available; informational until declared supported |
| Production-profile release | Required DEP-001 profiles applicable to the release | Profile-required external identity | PostgreSQL and optional OpenSearch when claimed | Supported matrix |
| Government/air-gap release | Network-disabled `government-airgap` | Approved test gateway | Approved separated index topology | Offline pinned digest set |

The harness records platform, schema/model/policy, Gitea, PostgreSQL, NATS, OpenFGA, OPA, browser, chart/Compose, and fixture versions.

## 4. Ordered executable scenario

| Step / test ID | Action | Required assertions and evidence |
|---|---|---|
| `GVS-001-INSTALL` | Run one supported `platformctl install` command/profile from a clean host/cluster. | Guided/noninteractive inputs are within DEP-002; all baseline components including NATS start; no unapproved outbound call; health, digest, config, and install audit evidence captured. |
| `GVS-002-AUTH` | Authenticate `ID-AUTHOR` through the configured identity flow. | Trusted claims have source/version/expiry; a platform session is established; no long-lived service credential reaches the browser; authentication is audited. |
| `GVS-003-ORG` | Create `ORG-ALPHA`, `TEAM-ATLAS`, and `PROJ-STEAD` in the unified UI. | Canonical UUIDv7 IDs/URIs and resource envelopes validate; Team owns Project; default label/domain is applied; server performs OpenFGA+OPA checks; mutation and audit/outbox rows share the required transaction boundary. |
| `GVS-004-PROVISION` | Observe automatic Project provisioning. | Exactly one hidden tracker repository, fixed project board, managed labels/milestone capability, and a default docs repository exist in stock Gitea; provider calls—not database access—created them; permissions and label/domain reconcile. |
| `GVS-005-WORK` | Create and update `WI-1` from the Work view. | Gitea issue number produces stable `<PROJECTKEY>-<NUMBER>`; fixed type/status/priority/estimate validate; managed labels/board mapping matches SCM-003; ETag conflict behavior works; canonical event and audit record emitted. |
| `GVS-006-DOC` | Create, edit, and publish/review `DOC-1` referencing `WI-1`. | Safe editor output is deterministic Markdown with OKF frontmatter and stable ID; Git history is readable; executable MDX/script/unsafe HTML negative samples fail; relationship is typed; optimistic-concurrency conflict is intelligible and loses no edits. |
| `GVS-007-CODE` | Create/link `REPO-CODE-1`; create branch and commit referencing `WI-1` and `DOC-1`; open `PR-1`. | Repo remains distinct from Project/tracker; canonical deep links resolve; PR changes the linked repository and addresses the Work Item; Gitea access uses supported contracts; direct permission is reconciled from central policy. |
| `GVS-008-REVIEW` | `ID-AUTHOR` requests `ID-REVIEWER` review. | One grouped in-app notification records event, reason, actor, resource, label, state, and canonical link; reviewer sees authorized content; external channel, if enabled, honors redaction policy. |
| `GVS-009-MERGE` | Review and merge `PR-1`. | Required review/branch policy is enforced; Work/Document/PR relationships and activity update; all consumers are idempotent; correlation/causation IDs link mutation, provider webhook, activity, inbox, graph, search, and audit. |
| `GVS-010-PROJECT` | Inspect Activity and related-resource panels. | Activity uses Actor–Action–Object–Target semantics; graph edges carry endpoint restrictions; canonical links remain provider-independent; rebuilding the projection reproduces the authorized view. |
| `GVS-011-CI` | Run a pinned approved Gitea Action and create `BUILD-1`, SPDX SBOM, `ART-1`, and `REL-1`. | Runner is assigned to the permitted pool with short-lived credentials; output chain and provenance links validate; secrets are absent from logs/events/search/frontend; artifact download is policy enforced and audited. |
| `GVS-012-SEARCH` | Search once as `ID-AUTHOR`. | Authorized grouped results include Work, Docs, Code, PR, Build, and Release with canonical links; useful content meets the published latency fixture; authoritative OpenFGA+OPA filtering precedes return of results/counts/facets/snippets/suggestions. |
| `GVS-013-NONDISCLOSURE` | Repeat UI, API, search, graph, inbox, and direct-provider probes as `ID-LOW`, `ID-NO-NTK`, and `ID-SEC-OFFICER`. | No protected title, ID, existence, relationship count, snippet, notification text, or distinguishable error leaks; direct Git/API/LFS/package/artifact paths cannot exceed central policy; security officer manages allowed metadata without content read; denials are safely audited. |
| `GVS-014-BACKUP` | Create a supported backup, destroy only the disposable test deployment, and restore into a clean target. | Backup includes every OPS-003 authoritative store/config/policy/audit component; restored IDs, labels, permissions, relationships, Git hashes/history, attachments, URLs, and audit records match; projections rebuild even without NATS history. |
| `GVS-015-UPGRADE` | Upgrade within the supported platform/Gitea matrix. | Preflight, capacity/health, verified backup, migration plan, safe service order, smoke/contract checks, report, and audit record exist; injected failure follows the documented recovery/rollback route without acknowledged-write loss. |
| `GVS-016-REGRESSION` | Repeat create/read/update, search, authorization/non-disclosure, Git, event, audit, and provider checks. | Canonical IDs/links and compatibility are preserved; no permission/label weakening or duplicate durable side effect; the golden evidence manifest closes with all required signatures. |

`GVS-005-WORK` also validates, without executing an agent, that the canonical assignment contract accepts `PRINCIPAL-AGENT-SHAPE` while the Gitea adapter may map only its supported native-user projection. The provider limitation must not appear as the canonical assignment type.

`GVS-009-MERGE` event/audit schema tests encode both `requested_by = user:alice` and `actor = agent:backend-agent`, with principal type, delegation/task context, correlation, and causation, without a schema change or actual agent run.

## 5. Cross-cutting automated assertions

### Authorization and classification

The test suite includes, at minimum, the complete TEST-004 matrix: lower sensitivity, missing compartment, missing need-to-know, administrator-without-clearance, security-officer-without-content-access, expired attribute, label raise propagation, controlled downgrade approvals, every direct provider path, existence leakage surfaces, protected backups/logs, runner separation, and cross-domain export denial.

Each protected operation asserts the same ordered decision path and records the OpenFGA model ID, OPA bundle version, label version, context inputs by safe hash/reference, outcome, and non-sensitive reason code. Network errors, stale/unverifiable attributes, missing model/bundle, provider-sync lag beyond the approved bound, and policy evaluation errors fail closed.

Contract/model tests reserve `agent` as a first-class OpenFGA principal, prohibit broad inheritance from a delegating user, prove independently revocable task/resource assignments, and prove OPA inputs can carry principal type plus future runtime, security-domain, classification-ceiling, compartment, model-provider, tool-scope, and execution-environment attributes. These are seam tests only.

### Events, projections, and audit

- `EVT-GOLD-001`: domain mutation and outbox insert are atomic under commit/rollback fault injection.
- `EVT-GOLD-002`: duplicate publish/webhook deliveries yield one durable outcome.
- `EVT-GOLD-003`: worker restart resumes; failures enter the controlled dead-letter stream and replay succeeds.
- `EVT-GOLD-004`: resource-scoped out-of-order events do not corrupt projections.
- `EVT-GOLD-005`: schema incompatibility is rejected/quarantined with an audit trail.
- `EVT-GOLD-006`: an unauthorized consumer cannot subscribe to protected subjects.
- `EVT-GOLD-007`: search, graph, activity, and inbox projections rebuild from authoritative stores/events.
- `AUD-GOLD-001`: every mandated action/decision has the required append-only fields, while bodies, secrets, tokens, and excessive protected content are absent.

### Contracts and portability

The run validates canonical resources against JSON Schema 2020-12, HTTP behavior against OpenAPI 3.1.1, errors against RFC 9457, events against CloudEvents/AsyncAPI, OKF Markdown/frontmatter determinism, provider behavior against the Gitea contract suite, and export/import against OWGP conformance. No assertion may inspect or mutate a Gitea internal table.

Static/contract tests also prove that future agent business access routes through Platform APIs or the platform-wide MCP boundary; provider-specific business APIs are absent from the agent-facing contract. Scoped direct Git credentials remain a separately authorized exception. No Phase 0 executable endpoint for orchestration, prompting, model hosting, memory, AgentRun, A2A dispatch, or a full MCP tool catalog may exist.

## 6. Test implementation layers

| Layer | Golden responsibility |
|---|---|
| Unit/property/fuzz | Fixed ontology, UUID/envelope, label join, Markdown/frontmatter, parsers, importer/webhook inputs, idempotency keys |
| OpenFGA/OPA model tests | Every relationship and policy decision cell, migration, expiry, deny/error, and mutation coverage floor |
| Schema/contract | OWGP, JSON Schema, OpenAPI, AsyncAPI/CloudEvents, provider capabilities, supported Gitea versions |
| Module/integration | Transactional state/outbox, provider reconciliation, projection rebuild, notification grouping, audit completeness |
| Browser/accessibility | Entire unified-shell path, stable deep links, keyboard operation, WCAG 2.2 AA critical flow |
| Security/classification | Non-disclosure and bypass inventory, credential/secret boundaries, downgrade/export, malicious payloads |
| Installation/upgrade/recovery | Compose/Kubernetes/air-gap as applicable, doctor, backup/restore, compatibility, fault rollback |
| Performance/chaos | Published fixtures/load shapes, p95 targets, provider/search/worker failures, no acknowledged-write loss |

## 7. Failure, retry, and rollback rules

- The harness preserves logs, traces, reports, and safe state hashes from the first failure before retry.
- A retry may establish flakiness but cannot convert the original run to pass.
- Destructive recovery tests run only in disposable, uniquely identified environments after target validation.
- An upgrade failure exercises the documented forward-recovery or rollback path selected by migration reversibility; database rollback is never assumed.
- Any unauthorized disclosure, acknowledged-write loss, missing audit event, label weakening, unrecoverable backup, or secret in evidence is release blocking and has no ordinary waiver.

## 8. Evidence manifest

The test harness emits one machine-readable, signed evidence manifest containing:

- scenario/run ID, source commit, build provenance, dependency lock/SBOM references, and timestamps;
- exact component/image/chart/provider/schema/model/policy/fixture versions and digests;
- test IDs, requirement IDs, outcomes, duration, retry history, and artifact links;
- safe hashes of expected/restored canonical state and Git revisions;
- coverage/mutation/accessibility/performance/security/scan reports;
- backup, restore, upgrade, rollback/recovery, and `platformctl doctor` reports;
- known deviations and separately approved time-bounded waivers;
- implementation-owner attestation plus independent WS-13 QA and security approval identities.

The manifest and test artifacts inherit the appropriate security domain/label; sanitization must not erase evidence needed to prove a denial or control.
