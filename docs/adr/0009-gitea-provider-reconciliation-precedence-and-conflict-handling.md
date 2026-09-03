# ADR-0009: Gitea provider reconciliation precedence and conflict handling

- **Status:** Proposed
- **Date:** 2026-08-30
- **Decision owners:** WS-03, with WS-02 canonical-domain, WS-06 authorization/classification, WS-07 event/audit, and WS-12 deployment/operations integration
- **Project-owner approval required:** yes; this proposal narrowly changes locked per-provider-HTTP-call durable-permit clauses in the Master Build Directive's CLS-003/CLS-007 rules, constitution section 4.6, ADR-0005, and ADR-0007 for one closed bounded internal read plan
- **Requirement IDs:** `PRIN-002`, `ARCH-004`, `DOM-004`, `SCM-001`, `SCM-002`, `SCM-003`, `SCM-004`, `SCM-005`, `AUTH-002`, `AUTH-006`, `CLS-003`, `CLS-006`, `CLS-007`, `SEC-006`, `EVT-003`, `AUD-001`, `AUD-002`, `TEST-006`, `PERF-003`, `PERF-004`
- **Affected contracts/modules/directories:** `docs/architecture/MASTER_BUILD_DIRECTIVE.md`, `docs/architecture/constitution.md`, `docs/architecture/authorization-contract.md`, `specs/provider-reconciliation/`, the Phase 1 issue catalog and traceability map, `/modules/scm/`, `/providers/gitea/`, `/tests/contract/gitea/`, and the typed WS-02, WS-06, WS-07, and WS-12 integration ports named below
- **Resolves on acceptance:** `ADR-CAND-008`
- **Supersedes / superseded by:** only on acceptance at an exact immutable commit SHA with explicit project-owner approval, supersedes only the Master Build Directive CLS-003 final durable-effect sentence and CLS-007 durable-effect paragraph, constitution section 4.6's provider-effect sentence, ADR-0005 option 6/decision item 15/`T-ADR-0005-REQUEST-BOUNDARY` provider-call clauses, and ADR-0007's durable-effects provider-call sentence, and only for the bounded internal pagination/snapshot/verification/safe-idempotent-read plan defined here

## Context

Stead uses stock, upgradeable Gitea through documented APIs, authenticated webhooks, and Git. Gitea owns provider state; Stead owns its canonical ontology, identities, authorization, classification, and user-facing behavior. Ordinary UI reads use local rebuildable PostgreSQL projections and make zero synchronous Gitea calls.

Reconciliation must settle disagreement among canonical state, managed provider configuration, provider-owned mapped state, direct Gitea changes, pending Stead mutations, and stale projections. It must tolerate duplicate or missed webhooks, pagination, restarts, rate limits, and ambiguous external effects without making Gitea an authorization authority or a second canonical database.

Existing locked language requires a durable one-use `AuthorizationEffectPermit` for every provider HTTP call. Applying that transaction lifecycle to every page or verification read would make database writes grow with provider pagination and would turn one logical reconciliation into many durable authorization effects. This proposal preserves a fresh central decision and every security fence while changing only that per-read-call persistence granularity.

The detailed closed values, bindings, bounds, ownership, and test cases live once in the machine-readable [Gitea reconciliation v1 specification](../../specs/provider-reconciliation/gitea-v1.yaml). The ADR selects their semantics; executable fixtures implement the specification rather than duplicating test vectors in this record.

This record is non-operative while Proposed. A branch, pull request, moving head, tag, or review of an unspecified revision is not approval.

## Decision drivers

- Preserve canonical Stead IDs, ontology, authorization, classification, and module ownership.
- Accept useful direct provider edits only when exact actor, change, and current authorization are proven.
- Keep ordinary reads provider-free and bounded reconciliation free of per-page database writes.
- Fail closed on permission, mapping, identity, capability, version, or external-effect ambiguity.
- Avoid PostgreSQL transactions across provider I/O and blind retries of uncertain effects.
- Support documented Gitea APIs and Git through exact compatibility profiles.
- Make replay, recovery, upgrade, rollback, audit, and performance evidence deterministic.

## Considered options

1. **Treat Gitea as canonical and import every direct change.** Rejected because provider values and permissions could redefine Stead semantics or authority.
2. **Treat every Stead value as provider-managed and overwrite all direct changes.** Rejected because it loses valid provider-owned edits and contradicts the supported reconciliation model.
3. **Use field-class precedence, fresh scoped authorization, read-reconcile-write verification, and durable ambiguity handling.** Selected.
4. **Use a durable permit transaction for every provider read/page.** Rejected for the eligible bounded internal read plan because it adds write amplification without adding authority or a stronger fence.
5. **Use last-write-wins timestamps, CRDT merging, or routine manual conflict resolution.** Rejected because Gitea has no universal causal token and provider data cannot extend the fixed ontology. Manual action remains an authorized recovery tool for genuine ambiguity.

## Decision

### Closed source precedence

Every represented provider field belongs to exactly one server-owned class. Unknown or multiply classified fields quarantine. Callers, plugins, webhooks, and deployment profiles cannot select or change the class.

| Class | Authority and examples | Disagreement outcome |
|---|---|---|
| `canonical_only` | Stead owns canonical IDs, capabilities, Team hierarchy, relationships, Agent assignment, and effective labels. | Ignore an absent representation; quarantine any attempted provider representation, remap, ontology, or capability creation. |
| `provider_content` | Gitea owns supported Work content, comments/reactions, and software data when that capability is active. | Accept exactly one proven, currently authorized delta; otherwise reset only when the exact prior state is safe, or quarantine. |
| `mapped_value` | Gitea stores a value from a Stead-owned closed vocabulary, such as Work status, type, priority, Cycle milestone, or an active mapped User assignee. | Accept the exact existing mapping or reset; never create a vocabulary value or principal. |
| `managed_configuration` | Stead declares hidden trackers, board/column shape, labels, repository purpose/settings, and webhook registration. | Reset and verify; failed or ambiguous repair quarantines. |
| `central_security` | Stead owns relationships, permissions, security domain/container, classification, handling, and provider-path eligibility. | Fence the path, reset and verify; uncertainty remains denied and quarantined. |
| `provider_identity` | Gitea supplies opaque installation/resource IDs, issue numbers, Git SHAs, creation times, and supported endpoint tokens. | Map only to an already authorized canonical resource or explicit provisioning operation; collision or reuse quarantines. |
| `derived_projection` | Local normalized snapshots and search/activity/inbox inputs are rebuildable and authoritative nowhere. | Rebuild or suppress; never settle a conflict or grant access. |

Provider discovery never creates an Organization, Team, Project, Work type, capability, or navigation item. A general Project never gains Code or a code repository. An unknown or provider-only assignee never becomes a canonical User or Agent.

### One bounded logical provider-read authorization

For one reconciliation or provider operation, WS-06 issues one fresh, unique, nonrenewable, nontransferable `ProviderAuthorizationScope`. It binds the acting service principal; initiating principal or explicit system initiator; Organization and security domain; exact canonical container and closed resource set or container-inventory scope; provider installation/path/resource and reconciliation generation; one allowed operation class and closed call plan; activation and authorization consistency revisions; provider-enforcement and resource fences; compatibility profile; original deadline; immutable earliest expiry; a persisted conservative whole-plan attempt/call/page/item/byte envelope; and a unique WS-03 execution claim, process-instance holder identity, monotonic fencing token, and claim deadline.

Before the first provider call, WS-03 atomically changes the claim from issued to active for exactly one holder. The holder binding covers replica boot identity, current PID/start identity, and a fresh process nonce; every dispatch rechecks the current process identity. A keyed process-local single-flight guard prevents same-holder concurrency, while a fork or clone inherits an invalid parent binding and must rekey under a new scope. A second process therefore cannot claim or use the same scope. Before every dispatch and local outcome commit, WS-03 proves that the claim remains active for that exact process-instance holder and fencing token and is before its deadline, then invokes the WS-06 read-only scope/fence validator and enforces execution-local monotonic counters. A forked claimant, stale holder, expired claim, changed fence, or terminal scope denies before provider I/O. Claim handoff, takeover, renewal, and resume are prohibited; completion, abandonment, or expiry is a permanent compare-and-swap terminal transition, and recovery requires a new scope.

The only eligible calls are declared pagination reads, snapshot reads, bounded verification reads, and compatibility-profile-declared safe retries of idempotent reads. Every dispatched or uncertain read consumes its local allowance. The operation performs one atomic start/claim transaction and one terminal logical-audit transaction, but zero durable reservation, permit, audit, claim-renewal, or accounting writes per eligible call or page. Clean completion records exact counts; interruption conservatively records the reserved upper bound and an abandoned/crash outcome. Write count therefore remains constant as page count grows.

A predeclared bounded container-list call may observe opaque provider keys within its exact container and item budget. Those keys are inventory-drift evidence only: they do not widen authority, authorize canonical acceptance, or add an undeclared resource-specific call. A follow-up must match a predeclared deterministic rule already authorized for that container scope or obtain a fresh decision and scope.

Process loss abandons or expires the scope through the fenced terminal compare-and-swap and conservatively consumes its remaining envelope. A stale holder fails its claim/fence/deadline check before another dispatch. Recovery starts from the last trusted job cursor only after the old claim is terminal and a fresh decision creates a new scope. A scope is never resumed, renewed, transferred, taken over, or extended by provider output, retry, restore, or an administrator.

The scope does not authorize a provider mutation, credential issuance, direct Git/protocol access, export/download, non-idempotent call, ambiguous external effect, or operation that may outlive the logical request/job. Each such effect retains its own fresh decision, durable one-use `AuthorizationEffectPermit`, immediate pre-effect fence validation, and terminal or reconciling lifecycle.

Before canonical state accepts provider-originated data, Stead performs a separate fresh central decision for the effective provider principal and any impersonator, the exact canonical delta, and current post-read state. The owning transaction performs the final activation, authorization, provider-enforcement, resource, operation, and optimistic revision checks. The service actor's read scope, webhook signature, historical permission, or provider-local permission cannot authorize acceptance.

### Webhooks, snapshots, and direct changes

Webhooks are authenticated dirty notifications, not ordered change logs or canonical deltas. The v1 profile verifies the exact raw-body Gitea HMAC before parsing, enforces the specification's body/depth/type bounds, deduplicates an installation/hook/secret-epoch/delivery attempt, and treats the same attempt with different bytes as a security incident.[^gitea-webhooks] A verified delivery durably marks the mapped resource dirty and schedules reconciliation; the response does not wait for NATS.

Snapshots normalize only compatibility-profile-declared fields and use the strongest documented endpoint precondition plus a canonical digest; endpoint-specific inputs such as Gitea issue `content_version` remain profile capabilities rather than a fabricated global version.[^gitea-issue-edit] Timestamps are informational and never form a total order. Direct-change acceptance requires a provider-authenticated contiguous predecessor/delta/result proof for exactly one normalized change and a mapped effective actor/impersonator chain. A sender, HMAC, delivery UUID, partial `changes`, snapshot, or provider permission is insufficient.

### Deterministic reconciliation and external effects

WS-03 serializes one resource generation with an optimistic lease and never holds a PostgreSQL transaction across Gitea I/O. It selects exactly one outcome:

- `in_sync`: persist the verified token;
- `accept`: invoke the canonical owner with an optimistic precondition, then atomically record projection plus audit/outbox intent;
- `reset`: use a separate durable permit for each minimum provider mutation, then verify;
- `quarantine`: fence the unsafe path, suppress unproven projection data, and retain safe recovery evidence.

Unknown actors or fields, unsupported mappings, concurrent edits, identity collisions, unsafe deletes/renames, failed repair, permission drift, and ambiguous results quarantine rather than merge or fabricate success. Canonical UUIDs, URIs, links, capabilities, and history remain stable across provider repair or replacement.

Provider mutations use canonical idempotency keys and separate prepare, execute, confirm, and resolve transactions. Network I/O occurs outside PostgreSQL transactions. A timeout or lost response remains `reconciling` until provider- or transport-authenticated terminal proof exists. Snapshot equality, absence, elapsed time, or a user-editable marker cannot prove success or no effect. An ambiguous create may be adopted automatically only through a compatibility-profile-proven, provider-enforced, operation-bound immutable uniqueness key and exactly one verified candidate. Otherwise recovery is a new authorized/audited operation and never blindly replays the original effect.

### Scheduling, outage, and compatibility

Verified webhooks, immediate post-mutation confirmation, and checkpointed full inventory use the same reconciliation function. The Phase 1 full-scan default is 15 minutes and supported maximum is 60 minutes. Backoff applies only to profile-declared transient failures within the original bounds.

During provider outage, an ordinary local read may continue only after current central authorization and only when no security, mapping, deletion, or unsafe-content ambiguity is pending. Provider mutations, raw/direct paths, credential issuance, and unsafe fields deny. Outage never fabricates an empty state, deletes canonical data, or leaks existence.

Compatibility profiles bind an exact Gitea version and API/schema digest and declare fields, mappings, preconditions, pagination, visibility horizon, retry classes, read safety, proof capabilities, and call bounds. Unknown versions or missing capabilities make affected mutations unready. Implementation evidence covers the pinned current version, two prior supported minors, and the next candidate when upstream exists.

### Ownership and persistence

- WS-02 owns canonical compare/write ports and their transaction semantics.
- WS-06 owns central decisions, provider-enforcement fences, `ProviderAuthorizationScope` issuance/read-only validation, and durable effect permits.
- WS-03 owns compatibility profiles, provider calls, webhook verification, field classification, mappings, snapshots, scope references, whole-plan envelopes, atomic execution-claim state and single-flight enforcement, execution-local accounting, projections, operation/quarantine state, and outcome selection.
- WS-07 owns audit/event schemas and delivery; NATS is never a request-path correctness dependency.
- WS-12 owns effective configuration, secret-reference rotation orchestration, provider health/version preflight, backup/restore, upgrade/rollback orchestration, and operational performance evidence.

All persistence follows ADR-0007 module ownership. No Stead code accesses Gitea tables or internal Go packages. Shared outbox and authorization state are used only through their owning typed ports. Evidence needed to explain an external effect remains durable; projections remain rebuildable.

## Consequences

The selected scope reduces write amplification while preserving one fresh central authorization, current fences before every read, no scope expansion, one logical audit, and a separate effective-principal authorization before canonical acceptance. It deliberately trades crash-resumable per-page accounting for conservative whole-plan reservation: process loss abandons the old scope and accounts its full remaining envelope.

Hidden trackers and quarantined mappings stay absent from routine navigation, search, counts, errors, activity, inbox, and provider-specific browser code. Public errors use stable non-disclosing RFC 9457 types. The provider-reconciliation logical audit and event/outbox/DLQ payloads use closed allowlists. The logical audit may carry safe canonical references, operation/outcome codes, revisions, bounded counts, and per-operation opaque random references to protected WS-03 provider-binding and call-plan records; those references are non-content-derived, require at least 128 bits of CSPRNG entropy, and are resolvable only through authorized access to the protected record. Event, outbox, and DLQ payloads omit provider-binding and call-plan references. No propagation surface carries a raw plan, provider path/resource/cursor, body, header, query, webhook secret/signature, credential, authorization input, protected title/comment/document content, exception text, or stack. The same forbidden-value rule covers audit, event, outbox, DLQ, log, trace, metric, diagnostic, and support evidence and is enforced with canaries, offline-guessing checks, and checks that provider-binding/call-plan evidence cannot be correlated across events.

Every performance-sensitive implementation reports endpoint/scenario, p50/p95/p99, SQL query and PostgreSQL write counts, OpenFGA and provider calls, response size, frontend chunk impact, and baseline delta. Ordinary UI reads assert zero provider calls. Full scans assert bounded memory/calls and constant PostgreSQL writes as page count grows.

This decision adds no dependency. Any client, generator, retry library, or test container still requires normal version, digest, license, notice, provenance, and security evidence before activation.

## Migration, upgrade, rollback, and recovery

The first implementation adds versioned empty WS-03 state and exact compatibility profiles, inventories provider state, and runs shadow reconciliation before accepts or resets. Activation proceeds from webhook dirtiness/projections to canonical accepts, then managed resets/mutations only after mapping, authorization, bypass, backup/restore, and performance evidence pass.

Upgrade preflight verifies the target Gitea and adapter profiles, drains or owns nonterminal effects, completes a full scan, and takes a consistent supported Gitea-plus-Stead backup. Shadow reads and reconciliation pass before mutations resume. Rollback is allowed only when the prior adapter profile supports both the active Gitea version and persisted schema; otherwise Stead restores the consistent pre-upgrade set or recovers forward with mutations denied. Restore never infers success from backup age and restarts abandoned read scopes under fresh authorization.

Abort activation on an unknown capability, mapping collision, unexplained permission widening, unbounded work, unowned nonterminal effect, provider identity leak, or unauthorized accept. Aborting retains evidence and reconciles forward; it cannot undo or misreport a possibly completed external effect.

Accepted ADR-0005 and ADR-0007 remain immutable historical records. On acceptance, this later decision governs only the exact provider-read call-granularity clauses named above; the Directive, constitution, authorization contract, issue catalog, traceability map, and structured specification in the same immutable decision revision carry the prospective implementation rule. A future broader exception, changed precedence, provider authority, scope reuse, or weaker ambiguity handling requires a superseding ADR.

## Verification

Decision acceptance adopts these future obligations; it does not claim runtime implementation or evidence exists. The structured specification is normative for the closed case lists and ownership.

| Test ID | Required evidence |
|---|---|
| `T-ADR-0009-PRECEDENCE` | Every field class and unknown/multiple-class denial; no canonical ID, ontology, or capability creation. |
| `T-ADR-0009-WEBHOOK-IDEMPOTENCY` | Raw-body verification, bounds, duplicate/collision/redelivery/reorder/restart cases, and payload-not-authority. |
| `T-ADR-0009-DIRECT-CHANGE-ACCEPT` | One exact actor/proof/delta passes current authorization and canonical-owner fencing; incomplete, mixed, historical, or provider-only authority cannot accept. |
| `T-ADR-0009-DIRECT-CHANGE-RESET` | Managed and invalid mapped state resets idempotently and verifies without ontology creation. |
| `T-ADR-0009-CONFLICT-QUARANTINE` | Concurrent, unknown, colliding, deleted/renamed, repair-failed, and ambiguous-create cases quarantine without leakage or destructive guessing. |
| `T-ADR-0009-PERMISSION-DRIFT` | Every supported API, Git, credential, artifact, runner, webhook, and raw-admin path fences, resets/verifies, or remains denied. |
| `T-ADR-0009-PROVIDER-OUTAGE` | Safe local reads remain provider-free; unsafe/effect paths deny; recovery preserves cursors and canonical state. |
| `T-ADR-0009-AMBIGUOUS-MUTATION` | Lost-response and ABA/create candidates never false-terminalize or blindly retry; every excluded effect retains its own permit. |
| `T-ADR-0009-FULL-RECONCILIATION` | Every scope binding and bound has negative coverage; an atomic one-holder claim blocks same-scope forks, stale holders, expiry, and post-terminal replay; inventory cannot widen scope; process loss starts fresh; eligible pages write nothing; total PostgreSQL writes remain constant as pages grow. |
| `T-ADR-0009-AUDIT-MINIMIZATION` | Closed audit/event/outbox/DLQ fields, opaque non-content-derived audit references, offline-guessing/cross-event provider-plan correlation checks, and the full forbidden-value-by-propagation-surface canary matrix prove that raw provider plans, paths, resources, cursors, payloads, headers, secrets, credentials, protected content, and exception text never propagate. |
| `T-ADR-0009-UPGRADE-ROLLBACK` | Exact-version support matrix, preflight/shadow/full-scan gates, compatible rollback or forward recovery, and nonterminal-effect preservation. |

`STEAD-P1-006` owns the scope issuance/read-only-validation and excluded-effect contract cases. `STEAD-P1-003` consumes those typed ports and owns provider fixtures and primary integration. WS-02 and WS-12 contribute their named boundary cases; WS-13 independently verifies the combined evidence.

## Reviews and approvals

Because this proposal narrowly supersedes accepted/locked call-granularity rules, every named review and explicit project-owner approval must name the same exact immutable decision SHA. Until the later mechanical acceptance record directly descends from that decision revision and changes only approval/gate/review records, ADR-0009 remains Proposed, `ADR-CAND-008` remains blocking, and no bounded-read exception is authorized.

| Role | Identity | Disposition | Evidence/date |
|---|---|---|---|
| Contract owner (WS-03) | pending non-author reviewer | pending | pending |
| Architecture and standards (WS-01) | pending | pending | pending |
| Canonical transaction owner (WS-02) | pending | pending | pending |
| Authorization/classification owner (WS-06) | pending | pending | pending |
| Event/audit owner (WS-07) | pending | pending | pending |
| Deployment/operations owner (WS-12) | pending | pending | pending |
| Independent QA and C-QA traceability owner (distinct WS-13 identity) | pending non-author reviewer | pending | pending |
| Independent security (distinct WS-13 identity) | pending non-author reviewer | pending | pending |
| Project owner | pending explicit approver | pending | must name exact immutable decision SHA |

[^gitea-webhooks]: Gitea, [Webhooks: delivery headers, HMAC validation, events, recent deliveries, and redelivery](https://docs.gitea.com/usage/repository/webhooks/).
[^gitea-issue-edit]: Gitea, [Edit an issue API: `content_version` optimistic locking for body edits](https://docs.gitea.com/api/operations/issue-edit-issue/).
