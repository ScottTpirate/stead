# ADR-0009: Gitea provider reconciliation precedence and conflict handling

- **Status:** Proposed
- **Date:** 2026-08-30
- **Decision owners:** WS-03, with WS-02 canonical-domain, WS-06 authorization/classification, and WS-07 event/audit integration
- **Project-owner approval required:** no; this selects a conforming reconciliation implementation inside the locked stock-Gitea, canonical-Stead, central-authorization, local-projection architecture and changes no owner-controlled public ontology or security decision
- **Requirement IDs:** `PRIN-002`, `ARCH-004`, `DOM-004`, `SCM-001`, `SCM-002`, `SCM-003`, `SCM-004`, `SCM-005`, `CLS-006`, `CLS-007`, `TEST-006`, `PERF-003`
- **Affected contracts/modules/directories:** `/modules/scm/`, `/providers/gitea/`, `/tests/contract/gitea/`, WS-02 canonical owner ports, WS-06 authorization and provider-enforcement ports, WS-07 audit/event ports, provider projections under the WS-03-owned PostgreSQL schema, and Gitea compatibility/operations evidence
- **Resolves:** `ADR-CAND-008`
- **Supersedes / superseded by:** supersedes no accepted decision; a changed precedence class, automatic ontology import, direct-provider authority, unmediated browser/provider path, or different ambiguity safety rule requires a superseding ADR

## Context and decision scope

The directive already fixes stock, upgradeable Gitea behind capability-specific Stead ports; the SCM-003 mapping; canonical Stead IDs and ontology; central authorization and classification; zero provider calls for ordinary UI reads; authenticated webhooks plus scheduled full reconciliation; and a local rebuildable PostgreSQL provider projection. Gitea is authoritative for provider-owned data but cannot become the user-facing model, an authorization authority, or a second canonical database.

The remaining implementation choice is how to decide a disagreement between canonical state, managed provider configuration, provider-owned mapped state, direct changes, a pending Stead mutation, and a stale local projection. This ADR selects a closed field-class precedence table, opaque provider snapshot tokens, a durable mutation/ambiguity state machine, and deterministic `accept`, `reset`, or `quarantine` outcomes. It does not implement the adapter, choose a Gitea release, add a dependency, or define later software-capability behavior beyond the already approved interfaces.

Gitea's documented webhooks provide an attempt-unique delivery UUID and HMAC-SHA256 over the raw request body, and may be redelivered.[^gitea-webhooks] Those deliveries are notification evidence, not an ordered change log. Gitea's APIs expose resource IDs, timestamps, Git object IDs, and capability-specific concurrency values; for example, the current issue-edit API documents `content_version` optimistic locking for body edits.[^gitea-issue-edit] It does not establish one universal strong version or idempotency key for every endpoint. Stead therefore cannot invent a global provider ETag, order changes by `updated_at` alone, or blindly retry every timed-out create.

## Decision drivers

- Preserve the fixed Stead ontology, canonical IDs, stable links, and module ownership
- Accept useful direct Gitea edits without allowing provider values or permissions to create authority
- Fail closed on permission, classification, mapping, identity, capability, or external-effect ambiguity
- Make webhook duplicates, redelivery, reordering, missed events, restarts, and partial failures harmless
- Keep ordinary reads projection-backed and provider-free while bounding synchronous mutation work
- Avoid holding a PostgreSQL transaction open across a provider call
- Use documented Gitea APIs, HMAC webhooks, and Git only, with explicit version capability profiles
- Make recovery, upgrade, rollback, and independent contract testing deterministic

## Considered options

1. **Treat Gitea as authoritative for every represented field and import direct changes.** This is operationally simple but lets provider configuration, permissions, labels, and unsupported values redefine Stead semantics and can create an authorization bypass. Rejected as nonconforming.
2. **Treat Stead as authoritative for every field and overwrite all direct changes.** This preserves a single writer but contradicts SCM-004, makes the supported raw administrative interface misleading, and loses valid provider-owned edits. Rejected.
3. **Use field-class precedence plus read-reconcile-write verification and a durable ambiguity state machine.** Provider-owned values may be accepted only inside the fixed mapping and after a current central decision; managed configuration and security state reset from Stead; uncertainty quarantines. Accepted.
4. **Use last-write-wins timestamps, a CRDT, or routine manual conflict resolution.** Gitea does not expose one cross-capability causal version, timestamps are not a safe total order, and provider values cannot be merged into a closed ontology. Manual review remains a recovery tool for genuinely ambiguous effects, not the normal correctness algorithm. Rejected.

## Decision

### Closed source-precedence classes

Every adapter field is registered in exactly one server-owned class. Unknown or multiply classified fields are unsupported and quarantine; callers, plugins, webhooks, and deployment profiles cannot select or change a class.

| Class | Examples | Authoritative source | Valid direct Gitea change | Disagreement outcome |
|---|---|---|---|---|
| `canonical_only` | Organization, Team, Project and Work UUIDs; capabilities; Team hierarchy; parent/dependency/estimate/relationship data; Agent assignment; effective label | Owning Stead module | Never imported from Gitea | Ignore an absent representation; quarantine any attempted provider representation or remap |
| `provider_content` | Work title/body, comments/reactions; repository/branch/commit/PR data when software capability is active | Gitea, constrained by the canonical resource and capability | Accept only after identity mapping, current central authorization/classification, supported shape, and concurrency checks | Accept through the owning module port; otherwise reset when exact prior state is safe, or quarantine |
| `mapped_value` | fixed Work type/priority/status, Cycle milestone, compatible active User assignee | Gitea stores the instance value; Stead owns the closed vocabulary and mapping | Accept only when exactly representable in the existing canonical vocabulary and currently authorized | Accept the mapped value, or reset to the last declared value; never create an ontology value |
| `managed_configuration` | hidden tracker, fixed board/columns, managed labels, repository purpose/visibility/settings, webhook registration, capability-required repository topology | Stead declared state | No | Reset and verify; failed or ambiguous repair quarantines the affected scope |
| `central_security` | relationships and permissions, security domain/container, classification and handling, branch/repository policy, provider-path eligibility, credential constraints | Stead authorization/classification and owning policy modules | No provider value can widen authority | Advance the provider-enforcement fence to pending, stop issuance/use, reset and verify; uncertainty remains denied/quarantined |
| `provider_identity` | installation/repository/issue/comment IDs, issue number, Git SHA, provider creation time and endpoint capability token | Gitea, stored only as opaque adapter state | Observe and map only to an already authorized canonical resource or explicit provisioning operation | Collision, reuse, rename/delete ambiguity, or cross-installation mapping quarantines; canonical IDs and links do not change |
| `derived_projection` | normalized local provider snapshot, search/activity/inbox inputs, reconciliation health | No authority; rebuildable from authoritative stores | Not applicable | Rebuild or suppress; a projection never settles a conflict or grants access |

Gitea repositories not created by or explicitly adopted through an authorized Stead provisioning operation never create a Project, Team, capability, repository resource, Work type, or navigation item. Inside a Stead-managed provider namespace they are inventory drift: the adapter ignores them when provably outside a managed scope, otherwise quarantines them for an authorized administrative recovery. A general Project never gains a code repository or software capability from provider discovery.

Provider-native User assignment may project an already mapped active canonical User. An unknown, ambiguous, suspended, Agent, service-account, or Directory-Group subject cannot be manufactured from a Gitea assignee. Agent assignment remains `canonical_only`; any provider limitation is adapter metadata, not an ontology or authorization change.

### Snapshot, delivery, and reconciliation identities

WS-03 persists no provider body as a public contract. Internal adapter records use these versioned identities:

- `ProviderResourceKey`: installation UUID, capability interface, provider resource kind, and opaque provider ID;
- `ProviderSnapshotToken`: compatibility-profile ID, resource key, the strongest endpoint-specific precondition when one exists, a SHA-256 digest of the adapter's canonical normalized snapshot, and provider timestamps as informational metadata only;
- `WebhookAttemptKey`: installation UUID, Stead hook-registration UUID and secret epoch, plus `X-Gitea-Delivery` UUID;
- `ProviderOperationID`: a Stead UUIDv7 bound to the caller idempotency key, canonical operation digest, resource/fence snapshot, and one authorization-effect permit;
- `ReconciliationGeneration`: a Stead-local monotonic generation and bounded page cursor for one scope scan.

The normalized snapshot includes only fields declared by that capability/version profile. It sorts unordered sets, preserves ordered data, distinguishes absent from explicit empty, and rejects unknown security- or mapping-relevant fields until that provider version is reviewed. A digest is a comparison token, not authority or proof that two external operations were one operation. `updated_at` is never a total-order key.

The webhook receiver accepts only the configured `POST` plus `application/json` profile and requires `X-Gitea-Signature` to be exactly 64 lowercase hexadecimal characters: the documented unprefixed HMAC-SHA256 of the exact bounded raw body. It rejects every other encoding or length and uses constant-time comparison before parsing. The v1 receiver ceiling is 4 MiB of raw body and JSON nesting depth 32; a compatibility profile may lower but not raise either limit. It checks installation/hook identity and active secret epoch, event and exact event type, content type, and the attempt UUID. Repeating the same attempt key and body digest is a no-op; the same key with another digest is a security incident and quarantines the hook. A redelivery with a different attempt UUID remains harmless because the receiver never applies the payload as a canonical delta: it durably marks the mapped provider resource dirty and schedules a fresh snapshot reconciliation. Unsupported, unsigned, malformed, unmapped, or over-limit deliveries cannot mutate a canonical owner; scheduled reconciliation remains the missed-event recovery path.

Webhook acknowledgment means only that the verified notification and dirty generation are durable. WS-07 event distribution may follow through the transactional outbox, but NATS availability and consumer completion are never on the receiver or product-request correctness path.

### Deterministic reconciliation algorithm

One resource reconciliation serializes through a WS-03-owned optimistic lease/generation; it does not hold a database transaction during Gitea I/O. Internal maintenance, webhook, full-scan, and recovery calls are not exempt from ADR-0005: every actual provider request has its own freshly authorized, one-use `AuthorizationEffectPermit`, complete provider/path check, final fence recheck, and immutable audit/outbox intent. A provider page or documented batch is one call and one permit; a loop, retry, follow-up page, or verification read consumes another permit. The worker performs:

1. Resolve the installation capability profile and opaque resource mapping from local state. Missing, colliding, reused, or cross-scope mappings quarantine without calling Gitea.
2. Load the current declared/last-confirmed Stead state, provider-enforcement fence, pending provider operation, prior snapshot token, and bounded webhook actor evidence through owned ports. Select the closed server-owned reconciliation action and exact container/resource set; an event payload, provider ID, cursor, or caller cannot widen it.
3. Authenticate the reconciliation service actor and run the complete current central authorization/classification and authoritative provider/path sequence for the exact snapshot-read action and bounded scope. Commit its one-use permit plus audit/outbox intent. Missing, stale, pending, mismatched, or denied context stops before network I/O.
4. Recheck the fence, atomically consume that permit, read one current provider snapshot or bounded page under the exact compatibility-profile deadline, and terminalize the permit only from the locked ADR-0005 outcomes. Normalize the verified response under that profile. Timeout, malformed response, or process loss follows the permit's terminal-proof rules; it never becomes an unaudited retry.
5. Classify every difference by the closed table. A webhook sender is only evidence until it maps uniquely to a current principal and action. Direct-change acceptance runs a separate fresh central decision for that acting principal and exact canonical mutation against the current post-read state; the service actor's read permit, historical permission, and provider-local permission cannot authorize acceptance.
6. Select exactly one outcome for the resource generation:
   - `in_sync`: persist the verified token and finish;
   - `accept`: call the canonical owning-module port with its optimistic precondition, then atomically persist the projection plus audit/outbox intent through owned transaction interfaces;
   - `reset`: create or resume one durable, fenced provider operation for the exact declared state, apply the minimum documented provider operation, read/verify the result, and atomically persist the confirmed projection plus audit/outbox intent;
   - `quarantine`: mark the affected provider path unusable, advance its enforcement revision, revoke or fence outstanding access as ADR-0005 requires, suppress provider-derived presentation that cannot be proven safe, and emit safe recovery evidence.
7. Re-read the local generation/fence before completion. A concurrent canonical change, security change, or newer dirty generation makes the result stale and schedules another bounded pass; it never overwrites newer state. Any new provider call required by that pass starts again at step 3 with a new permit.

`accept` is permitted only for `provider_content` or `mapped_value`; `reset` is mandatory for provably repairable `managed_configuration` or `central_security` drift. An unknown actor, unauthorized action, unsupported value, simultaneous Stead/provider edit, mapping collision, ambiguous external result, failed reset verification, or inability to revoke/fence an unsafe path selects `quarantine`. No automatic three-way text merge, last-write-wins rule, label invention, Project creation, canonical deletion, or privilege union exists.

Deletion or rename of a mapped tracker/repository is never accepted as deletion or rename of the canonical Project or Work Item. The mapping is quarantined. Authorized recovery may reattach or provision another supported provider resource through the canonical owner while preserving the Stead UUID, URI, human link, provenance, and audit trail.

### Stead mutation and ambiguous external effects

Every provider mutation is an ADR-0005 durable external effect. The API's idempotency key is unique within its canonical operation scope. Reuse with the same canonical input returns the existing operation/result; reuse with different input returns a non-disclosing conflict. The operation uses separate short transactions around, never across, network I/O:

1. **Prepare:** freshly authorize, bind the exact consistency vector and provider snapshot token, insert the WS-03 operation intent, issue the one-use `AuthorizationEffectPermit`, and append the audit intent through owned ports.
2. **Execute:** recheck the fence, atomically consume the permit, then make the documented provider call with the strongest supported conditional input. A strong-capability operation normally uses one mutation call and at most one verification read. A weak-capability operation may use one preflight read, one mutation, and one verification read. The compatibility profile fixes the bound.
3. **Confirm:** only an authoritative success representation or a verified read matching the exact intended normalized result confirms the effect. A transaction records provider identity/token, immediate local projection, operation terminal result, and outbox/audit evidence before returning success. The response never waits for NATS or a projection consumer.
4. **Resolve:** a proven rejection/no-effect becomes terminal without changing the projection. A timeout, connection loss after dispatch, malformed success, conflicting version, or unknown provider result becomes `ambiguous`/ADR-0005 `reconciling`; the caller receives the same safe operation reference and cannot cause an automatic duplicate.

For ambiguous update/delete operations, reconciliation compares the verified provider snapshot with the exact before and intended-after snapshots: after means confirm; before means proven no-effect only when the compatibility profile proves the read covers the complete authoritative state for that operation; any third or incomplete state quarantines as a concurrent conflict. For an ambiguous create, the adapter searches only the bounded operation window and expected parent using the service actor, resource kind, normalized content digest, and immutable provider fields. Exactly one exact candidate may be adopted; multiple or unverifiable candidates quarantine. Finding no live candidate after a visibility horizon is not proof that creation never occurred: the resource may have been deleted, renamed, moved, or hidden. `failed_without_effect` therefore requires affirmative capability-profile evidence that the request was not dispatched or that the provider durably rejected it without effect. Without that evidence the original permit remains `reconciling` until authorized recovery either proves a locked terminal outcome or irreversibly fences/removes every possible effect and verifies the corresponding terminal outcome. Non-idempotent creates are never blindly replayed.

Manual recovery may select among already observed exact candidates, attach affirmative provider/transport no-effect evidence, or verify that every possible effect was revoked or fenced. It cannot declare no-effect from elapsed time or absence alone, fabricate success, silently delete user content, reuse the original permit, or bypass the current authorization/fence check. A capability profile may use a documented provider idempotency facility or immutable uniqueness key only when its exact semantics and deletion/rename behavior are contract-tested; a digest or user-editable marker is not such a facility.

Only terminal proof changes an ADR-0005 permit from `reconciling` to `terminal`. A queued retry does not extend or reuse a permit. Every reconciliation read or page obtains its own permit, while the original mutation permit remains `reconciling`; a reset/repair is a new authorized operation with its own idempotency key and permit.

### Scheduling, outage, rate limiting, and degraded behavior

Three paths share the same reconciliation function and the per-provider-call permit sequence above:

- a verified webhook marks a resource dirty for prompt processing;
- a successful Stead mutation performs immediate confirmation/projection before success;
- a checkpointed full inventory scans bounded pages on a jittered schedule and resumes after restart without trusting page order as causality.

The Phase 1 default full scan interval is 15 minutes and its supported maximum is 60 minutes. Deployment configuration may lower, but not raise, that maximum. This is a missed-event/drift backstop, not the control that makes stale provider permission safe. Central security mutations mark the provider-enforcement fence pending and complete their required provider/credential reconciliation before acknowledgment under ADR-0005; gateways and scoped credentials enforce current central state independently of scheduled scans.

Ordinary composed reads continue from the last confirmed local projection during a provider outage only when current central authorization succeeds and the resource has no pending security, mapping, deletion, or unsafe-content ambiguity. They make zero Gitea calls and may expose only a non-resource-specific degraded-service indication to an already authorized user. Provider mutations, direct credentials, raw paths, and unsafe projection fields deny while their required provider state cannot be verified. A provider outage never causes a fail-open read, fabricated empty state, canonical delete, or cross-resource existence leak.

The adapter honors a documented provider retry hint when present and otherwise uses capped exponential backoff with full jitter in workers. It retries only a capability-profile-declared transient failure and only when no effect occurred or reconciliation makes the result safe. Authentication, authorization, validation, unsupported capability, precondition, and invariant failures are not transient. Interactive requests remain inside their endpoint deadline; deferred recovery keeps the durable operation reference.

Public errors use stable RFC 9457 problem types such as `provider-unavailable`, `provider-outcome-pending`, and non-disclosing `conflict`; they omit provider locator, raw status/body, hidden repository, actor, version, candidate count, and protected resource detail. Unauthorized and nonexistent probes retain the same concealment contract.

### Storage and ownership boundaries

ADR-0007's accepted physical PostgreSQL rules govern the actual schema and migration sequence. WS-03 owns provider mappings, snapshot/projection state, operation intents, webhook attempts, quarantine state, and reconciliation cursors under the `scm` module namespace. It writes canonical Work, Organization, Project, authorization, audit, activity, inbox, or search state only through typed owner ports or versioned events. Shared outbox and authorization-effect state are accessed only through their owning ports. No code reads or writes a Gitea table, imports an internal Gitea package, or treats a provider backup as Stead canonical storage.

Projection and reconciliation rows are versioned and rebuildable. Operation, mapping, quarantine, acceptance/reset, and audit evidence needed to explain an external effect is durable and is not discarded as a cache. Protected provider bodies and opaque locators remain access-controlled internal data; telemetry does not label them.

## Consequences

### Security, authorization, classification, and bypass paths

Provider permission is enforcement, never authority. A direct change is accepted only after current authentication mapping, OpenFGA, deterministic policy, profile-qualified ceiling, provider/path support, and final fence validation all allow. Permission or security drift first makes the affected enforcement revision pending; no new credential or provider operation may use it. If an already issued credential or raw path cannot be revoked, fenced, or gateway-constrained, the deployment cannot claim that path and the affected scope remains denied.

Hidden trackers and quarantined mappings remain absent from routine navigation, search, counts, errors, activity, inbox, and provider-specific browser code. Audit/recovery views require their own authorization and classification decision. A valid HMAC proves possession of the hook secret and body integrity, not sender authorization or canonical truth.

### Data model, migration, and backward compatibility

The first implementation seeds empty versioned mapping/projection/operation/webhook/cursor tables and provisions managed trackers only through canonical creation. Import of preexisting Gitea state is a separately authorized migration/adoption path that inventories and dry-runs the same closed mappings; it is not enabled by discovery. Provider locators may change during recovery or provider replacement while canonical IDs, URIs, issue links, capabilities, and history provenance remain stable.

Compatibility profiles are keyed by exact Gitea version and API/schema digest. They declare supported interfaces, fields, enum translations, conditional inputs, pagination, visibility horizon, rate/retry hints, and per-operation call bounds. Unknown versions or missing required capabilities make affected mutations unready; ordinary safe local reads may continue under the outage rules.

### Upgrade, rollback, backup, restore, and recovery

`steadctl upgrade` preflights the target pinned Gitea image/version/digest against the complete provider contract, current plus two prior supported minors, and next candidate where upstream exists. It drains or reconciles nonterminal operations, completes a full scan, backs up authoritative Stead data plus Gitea through supported mechanisms, verifies restore metadata, upgrades Gitea before enabling a compatible adapter profile, then runs shadow reads and full reconciliation before mutations resume.

Adapter rollback is allowed only when the predecessor profile supports the active Gitea version and persisted WS-03 schema. Otherwise mutations remain disabled for forward recovery or the operator restores the consistent pre-upgrade Gitea and Stead backup set. Restore resumes dirty generations and ambiguous operations idempotently; it never marks them successful from backup age. Webhook secrets and provider credentials are restored through the approved secret path, not logged or embedded in projection data.

### APIs, schemas, events, providers, and standards mappings

Public APIs expose canonical IDs, operation status, safe degraded state, ETags, and RFC 9457 problems only. Provider IDs, raw reconciliation class, provider version, and reset candidates remain internal or in separately authorized operator diagnostics. Events use canonical CloudEvents identities and causation; receipt of a provider event never authorizes delivery or a canonical mutation. Search, graph, activity, and inbox consume committed canonical/projection events and remain rebuildable.

The adapter uses documented REST APIs, HMAC webhooks, Git protocols, and supported authentication. Floating upstream documentation is evidence for implementation review, not the compatibility contract; each supported profile pins the exact upstream API schema or fixture digest used by its tests.

### Observability, audit, privacy, and evidence

Metrics report safe provider/version profile, operation class, outcome class, webhook verification result, reconciliation lag/age, dirty and quarantine counts, retries, rate limits, ambiguity age, page/call counts, and p50/p95/p99 provider/reconciliation latency. High-cardinality installation, Organization, repository, issue, principal, provider locator, body digest, and security-label values are not metric labels.

Audit records the acting/requesting principal when known, canonical containing scope, action, source class, safe prior/result token reference, accepted/reset/quarantined outcome, current authorization/model/policy/provider-enforcement revisions, operation/permit ID, provider-call count, compatibility profile, and correlation/causation. Raw provider bodies, webhook secrets/signatures, credentials, protected content, and broadly visible hidden-resource locators are excluded. Invalid signatures, attempt-ID/body mismatches, direct unauthorized changes, resets, quarantine, manual ambiguity resolution, permission drift, compatibility failure, and recovery are mandatory audit events.

Every performance-sensitive implementation PR reports the endpoint/scenario, p50/p95/p99, SQL queries/writes, OpenFGA calls, provider calls, response size, frontend chunk delta, and prior-baseline comparison. Ordinary reads assert zero provider calls and no result-size-dependent SQL/OpenFGA/audit work. Mutation tests assert the compatibility-profile call bound; full scans assert bounded pages and no unbounded memory growth.

### Dependencies, licenses, supply chain, and portability

This decision adds no dependency. A Gitea client, schema generator, retry library, or test container must receive exact dependency/license/security approval before import. The reconciliation algorithm works with the required PostgreSQL deployment and stock self-hosted Gitea, without a proprietary control plane, Gitea database access, or NATS request/reply.

### Documentation and accessibility

Operator documentation must explain safe degradation, quarantine, ambiguous-operation recovery, support profiles, full-scan health, webhook rotation, raw administrative boundaries, and upgrade/rollback. User-facing pending/conflict/degraded notices must be keyboard reachable, screen-reader announced, non-provider-specific, and preserve entered content and navigation context without implying success before confirmation.

## Verification

Decision acceptance names future implementation obligations; it does not claim they already pass.

| Test ID | Required evidence |
|---|---|
| `T-ADR-0009-PRECEDENCE` | Table-driven fixtures cover every field class and reject unknown/multiple classes, ontology creation, canonical-ID remap, and capability creation. |
| `T-ADR-0009-WEBHOOK-IDEMPOTENCY` | Exact raw-body HMAC, empty/wrong/mixed signatures, body bounds, duplicate attempt, attempt/digest collision, distinct redelivery, out-of-order delivery, missed event, restart, and payload-not-authority cases pass. |
| `T-ADR-0009-DIRECT-CHANGE-ACCEPT` | A supported mapped edit by a uniquely mapped currently authorized principal commits through the canonical owner, projection, outbox, and audit exactly once. Revoked/stale/historical/provider-only authority cannot accept. |
| `T-ADR-0009-DIRECT-CHANGE-RESET` | Managed configuration and invalid mapped values reset idempotently, verify the exact declared snapshot, and never create provider/ontology values. |
| `T-ADR-0009-CONFLICT-QUARANTINE` | Concurrent canonical/provider edits, unknown actors/fields, mapping collisions, deletes/renames, failed repairs, and multi-candidate ambiguous creates quarantine with no existence leak or automatic destructive choice. |
| `T-ADR-0009-PERMISSION-DRIFT` | API, Git SSH/HTTPS/LFS, token, package, artifact, runner, webhook, and raw-admin drift advances the fence, stops issuance/use, resets and verifies, or keeps the path denied; provider allow alone never authorizes. |
| `T-ADR-0009-PROVIDER-OUTAGE` | Safe authorized local reads remain zero-provider; unsafe/pending fields and all required provider effects deny; recovery resumes cursors without empty-state fabrication or canonical deletion. |
| `T-ADR-0009-AMBIGUOUS-MUTATION` | Lost responses for update/delete/create exercise before/after/third-state and zero/one/multiple-candidate rules; absence-after-horizon cannot produce `failed_without_effect`; no blind retry, duplicate, permit reuse, or false success occurs. |
| `T-ADR-0009-FULL-RECONCILIATION` | Bounded pagination, schedule jitter, duplicate/out-of-order pages, provider mutation during scan, cursor restart, webhook race, per-call fresh decision/permit/audit, denial-before-I/O, and final generation recheck converge to the same result with measured call/query/memory bounds. |
| `T-ADR-0009-UPGRADE-ROLLBACK` | Exact-version profiles cover pinned/current-2/next-candidate fixtures, unknown capability fails closed, preflight/shadow/full-scan gates work, and compatible rollback or forward recovery preserves canonical IDs and nonterminal operations. |

`T-STEAD-P1-003-CONTRACT`, the mapped SCM/architecture/classification/performance tests, `T-ADR-0005-PROVIDER-PATH`, and TEST-009/TEST-010 must consume these fixtures rather than create a second reconciliation rule. Failure injection covers database commit before/after provider dispatch, process death at every operation transition, webhook loss/redelivery, rate limiting, provider restart, pagination churn, permission removal, and projection rebuild.

## Rollout and supersession

Rollout is expand, shadow, activate, contract:

1. add versioned empty WS-03 storage and capability profiles;
2. inventory provider state and run shadow reconciliation with no accepts/resets;
3. resolve every mapping/security ambiguity and prove complete full-scan plus bypass evidence;
4. activate webhook dirtiness and projection writes, then canonical accepts, then managed resets/provider mutations;
5. contract obsolete provisional fields only after the compatibility window and one successful backup/restore/upgrade rehearsal.

Abort activation on an unknown Gitea version/capability, mapping collision, unexplained provider permission widening, unbounded call/query growth, nonterminal operation without recovery ownership, canonical/provider ID leak, or any unauthorized accept. Aborting disables mutations and retains evidence; it does not roll back a possibly completed external effect. Recovery reconciles forward until terminal proof.

A future ADR may add a provider or stronger native concurrency token by adding a reviewed compatibility profile behind the same classes and tests. It must supersede this ADR to change precedence, permit automatic ontology/capability import, make a webhook payload authoritative, use last-write-wins, relax quarantine, or grant provider-local authority.

## Reviews and approvals

| Role | Identity | Disposition | Evidence/date |
|---|---|---|---|
| Contract owner (WS-03) | pending non-author reviewer | pending | pending |
| Architecture and standards (WS-01) | pending | pending | pending |
| Canonical transaction owner (WS-02) | pending | pending | pending |
| Authorization/classification owner (WS-06) | pending | pending | pending |
| Event/audit owner (WS-07) | pending | pending | pending |
| Independent QA/security (WS-13) | pending distinct reviewer | pending | pending |
| Project owner | not required | conforming implementation decision | pending governance confirmation |

[^gitea-webhooks]: Gitea, [Webhooks: delivery headers, HMAC validation, events, recent deliveries, and redelivery](https://docs.gitea.com/usage/repository/webhooks/).
[^gitea-issue-edit]: Gitea, [Edit an issue API: `content_version` optimistic locking for body edits](https://docs.gitea.com/api/operations/issue-edit-issue/).
