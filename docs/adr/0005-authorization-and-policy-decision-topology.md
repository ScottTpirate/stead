# ADR-0005: Authorization and policy-decision topology

- **Status:** Proposed — decision selected; acceptance awaits the reviews below
- **Date:** 2026-08-29
- **Decision owners:** WS-06, with WS-02 application-composition integration and WS-01 public-contract review
- **Project-owner approval required:** no; this selects a conforming implementation inside the locked OpenFGA plus deterministic policy-decision architecture and does not weaken or replace that architecture
- **Requirement IDs:** `PRIN-007`, `PRIN-010`, `PRIN-011`, `PRIN-012`, `PRIN-015`, `ARCH-001`, `DOM-007`, `DOM-009`, `DOM-010`, `DOC-004`, `AUTH-001`, `AUTH-002`, `AUTH-003`, `AUTH-004`, `AUTH-005`, `AUTH-006`, `CLS-001`, `CLS-003`, `CLS-004`, `CLS-005`, `CLS-006`, `CLS-007`, `CLS-008`, `AGENT-001`, `AGENT-003`, `AGENT-004`, `AGENT-005`, `AGENT-006`, `AUD-001`, `AUD-002`, `OPS-001`, `OPS-002`, `SEC-002`, `SEC-004`, `SEC-006`, `TEST-001`, `TEST-002`, `TEST-003`, `TEST-004`, `TEST-006`, `TEST-008`
- **Affected contracts/modules/directories:** `/modules/authorization/`, `/modules/classification/`, `/modules/identity/`, `/apps/core/`, `/policies/openfga/`, `/policies/policy-decision/`, provider access gateways and credential issuers, audit/event consumers, and authorization/classification test fixtures
- **Resolves upon acceptance:** `ADR-CAND-003`
- **Supersedes / superseded by:** supersedes no accepted decision; a different evaluator, a separately addressable evaluator, nonzero decision caching, or a changed combining rule requires a superseding ADR

## Context and decision scope

The Master Build Directive already fixes the authorization architecture. Authentication and trusted context, stock OpenFGA, the implementation-neutral deterministic policy-decision layer, and provider/path enforcement are complementary checks. Every required check must allow, every explicit deny wins, and no module or administrator has an alternative path. OpenFGA cannot be removed or repurposed as the classification evaluator. The policy-decision boundary cannot be removed, expressed as provider-specific business logic, or made dependent on OPA/Rego without an approved decision.

`ADR-CAND-003` leaves only the evaluator and physical topology, call sequencing, failure deadlines, decision-cache behavior, provider credential issuance, and preservation of future Agent authorization seams unresolved. This ADR selects those implementation details. `ADR-CAND-002` still controls physical PostgreSQL namespaces and migration coordination for effect-permit/fence/outbox persistence, and `STEAD-P1-015` supplies the WS-02-owned core/outbox composition handoff before this implementation activates. This ADR does not revise the OpenFGA model, policy input/output schemas, decision table, security-label algebra, trusted-attribute normalization, Team relation semantics, or signed-bundle format selected separately by ADR-0006.

## Decision drivers

- Deny-by-default behavior with no network or process boundary between the core coordinator and classification evaluation
- Stock OpenFGA as the only relationship and need-to-know engine
- Exact conformance with the implementation-neutral policy input, output, and decision table
- No stale allow after a permission removal, label raise, explicit deny, delegation revocation, bundle activation, or provider restriction
- Full user, Agent, service-account, and non-acting Directory Group semantics without human-only assumptions
- Direct Git, package, artifact, runner, object-store, webhook, and provider API enforcement that cannot bypass the central result
- Identical security semantics in local, standard, HA, air-gap, and government profiles
- Simple Go operations, a small dependency and license surface, deterministic tests, and a credible exit path

## Considered options

1. **Native Go evaluator inside the authoritative authorization coordinator, with zero decision cache.** This removes an evaluator RPC and policy-language runtime, keeps the canonical contracts implementation-neutral, can use the required Go stack, and works offline. It requires strict bundle activation across HA instances and careful prevention of module-local forks. Accepted.
2. **OPA/Rego as a sidecar or separately addressable service.** This is capable and portable, but adds a network failure boundary, a second service lifecycle, evaluator-specific representation, bundle tooling, and a new dependency/license and vulnerability review. It is not required by the directive and provides no necessary benefit for the bounded initial decision table. Rejected for the initial implementation.
3. **Embedded OPA/Rego in the Go process.** This avoids the evaluator RPC but still couples the product and bundle representation to OPA/Rego, adds a large runtime dependency, and weakens the implementation-neutral exit boundary. Rejected.
4. **A standalone Stead policy microservice using native Go.** This preserves native rules but introduces avoidable network availability, authentication, deployment, and version-skew risks. Rejected.
5. **OpenFGA alone, provider-native authorization, or module-local checks.** These options cannot implement classification, contextual, handling, information-flow, infrastructure, explicit-deny, or full Agent intersection requirements and directly violate locked decisions. Rejected as nonconforming, not retained as fallback modes.

The accepted option is reversible only through a superseding ADR and differential conformance evidence. No alternative may be activated by configuration.

## Decision

### One authoritative coordinator and native evaluator

`stead-api` hosts the live authorization coordinator. WS-06 owns the coordinator implementation in Go under `/modules/authorization/`; WS-02 wires that module into `/apps/core/`. The coordinator calls the WS-06-owned policy rules under `/modules/classification/` through an internal typed interface. The evaluator is compiled into the `stead-api` process. It has no public policy endpoint, sidecar, subprocess, plugin loader, embedded OPA runtime, Rego input, or evaluator-specific public API.

All interactive Platform API and BFF operations invoke this coordinator. Provider access gateways and credential issuers either execute in the same trusted composition root or call a private, mutually authenticated Platform authorization operation that performs the complete coordinator sequence. `stead-worker`, `steadctl`, the browser, provider adapters, and domain modules do not evaluate or combine authorization independently. A worker that needs a fresh access-sensitive decision calls the Platform path; an event-carried prior decision never authorizes a new read, delivery, replay, or side effect.

HA may run multiple identical `stead-api` replicas. That is replication of one coordinator implementation, not multiple authorization systems. Every replica uses the same atomically selected OpenFGA model and signed policy-bundle activation set described by ADR-0006. A replica missing that exact activation set is not ready and denies protected operations.

### Required decision sequence

Every protected operation follows this sequence without a skip flag:

1. Authenticate an acting `user`, `agent`, or `service_account`; a `directory_group` cannot act.
2. Resolve trusted identity, attribute, authentication, session, runtime/workload, and delegation context. Missing, expired, revoked, conflicting, self-asserted, or unverifiable required context denies.
3. Resolve the canonical resource, containing security boundary, active capability, effective security label, and current resource/label revisions without disclosing existence.
4. Acquire one immutable activation snapshot containing the activation-set ID, activation-envelope and archive digests, release-attestation ID and release-attestation-envelope digest, policy-bundle ID, OpenFGA model ID/source digest, evaluator contract version, exact trust-set ID and trust-envelope digest, `activation_sequence`, trust epoch, and activation epoch. Separately atomically compare-and-max the normalized trusted time through ADR-0006's policy-time substate and bind its accepted `policy_time_high_water` and `policy_time_revision` to `policy_context.now` and decision evidence. At the same point acquire a closed consistency vector containing principal status, authority-configuration, selected assertion/coverage-result/synchronization, group and Team binding, Stead-local OpenFGA tuple/fence state, session, delegation, task, runtime-attestation, capability, resource, effective-label, explicit-deny, and provider-enforcement revisions applicable to the operation.
5. Ask stock OpenFGA for the required explicit relationship against the exact snapshot model ID using its supported `HIGHER_CONSISTENCY` preference; the protected Stead store also keeps OpenFGA query caches disabled. OpenFGA currently supplies no write revision/zookie that Stead can require “at or after.” Instead, every tuple write/delete first durably marks the applicable Stead-local fence pending, performs the supported OpenFGA API mutation, verifies the acknowledged tuple presence/absence with a cache-disabled/higher-consistency read, and only then advances the stable local tuple revision. Pending, ambiguous, failed, unverifiable, or mismatched tuple state denies and remains reconciliation-owned. A denied, malformed, timed-out, or unavailable Check response also denies.
6. Resolve the requested provider/path identity, enforcement capabilities, current enforcement revision, and the restrictions that would have to be enforced for the exact principal, resource/container, action, security domain, capability, and credential. This is non-authorizing context resolution only: it does not call a provider business API, issue a credential, produce the final provider allow, or satisfy the provider/path-specific enforcement check. The prospective result is encoded in the existing `authorization.provider_path` policy-input field; uncertainty or known inability is `allowed=false`, but `allowed=true` is only a candidate assertion that must be authoritatively rechecked after policy evaluation.
7. Build and validate the closed `POL-DECISION-IO-V0.1` input, including the OpenFGA result, prospective provider/path context, consistency fence, required context families, effective label, explicit denies, and Agent fields where applicable.
8. Evaluate the signed active policy bundle with the native Go evaluator. An OpenFGA or policy denial short-circuits safely: the coordinator records the required denial evidence but does not invoke the authoritative provider/path enforcement check, call the provider, or materialize a credential.
9. Invoke the authoritative provider/path-specific enforcement check against the exact principal, resource/container, action, security domain, capability, requested credential restrictions, policy result and obligations, activation snapshot, and complete consistency vector. It must explicitly allow, its result and revision must match the prospective `authorization.provider_path` input, and it must prove the path can enforce the decision-bound restrictions; unavailable, timed-out, false, stale, mismatched, or uncertain results deny. The final combining rule remains: relationship allow **and** policy allow **and** authoritative provider/path allow **and** no explicit deny; an Agent additionally requires every Agent-intersection term.
10. Reconfirm every activation and consistency-vector component acquired in step 4, including the authoritative provider-enforcement revision from step 9. A changed activation/vector component may trigger the one bounded fence restart below or deny. A routine increase in `policy_time_high_water`/`policy_time_revision` is deliberately not an activation/vector mismatch: the coordinator reads the latest value and denies if any temporal authority, permit, activation, trust, or provider bound is now expired; otherwise it continues without restart and never substitutes an earlier time to extend validity.
11. Cross the mandatory audit-before-effect and authorization linearization gate. Every authorization-relevant mutation first advances or marks pending the affected WS-06-owned authorization fence before its new state can be acknowledged; while a coordinated external-store mutation is pending, affected decisions deny. For a PostgreSQL domain mutation, the owning module compares and locks the complete fence, commits its owned domain change, and invokes the WS-02-owned transaction-scoped `core_outbox` insertion port with the immutable WS-07-owned audit/event intent in that same transaction. No module writes WS-07 audit tables or another module's tables directly. The commit is the protected mutation's linearization point.
12. A read, disclosure, provider credential, or non-transactional external effect instead commits a one-use, short-lived `AuthorizationEffectPermitV1` in state `issued` and the immutable audit/outbox intent through the same fence compare-and-use transaction. The permit binds the decision ID, acting/requesting principals, exact action/resource/container, complete activation and consistency vector, authoritative provider/path result, idempotency key where applicable, and `expires_at`. Its expiry is the earliest of the remaining request deadline and every applicable authentication/session, trusted-assertion/coverage/synchronization, delegation, task, runtime-attestation, activation-set, trust-key, and provider-enforcement expiry. A failed compare, audit/outbox write, missing temporal bound, or already expired permit denies. Permit commit is the operation's authorization linearization point: a later security mutation is ordered after it and must follow the drain protocol below. A permit is not renewable or a reusable authorization decision and cannot authorize a different action, resource, retry, replica, or request.
13. Before any protected byte, credential, provider call, or other effect begins, atomically compare the complete fence again, read the latest accepted policy-time high-water, prove the permit and every temporal authority remain unexpired at that value, and transition that exact permit from `issued` to `consumed`. A pending or advanced fence, expired temporal bound, canceled/terminal permit, failed transition, or enforcement failure denies without beginning the effect. Streaming disclosure and materialized credentials continue to enforce the latest high-water against their expiry and are suppressed/revoked when the bound is reached. Execute the Platform operation or materialize the scoped provider credential exactly once under the registered consumed-permit execution handle. The provider/gateway must enforce the decision-bound restrictions. A proven completion, cancellation before effect, suppression, revocation, or failure without effect transitions the permit to `terminal` with the corresponding closed outcome through the WS-06-owned authorization port/repository; that same transaction appends the immutable WS-07-owned terminal audit/event intent through the WS-02-owned `core_outbox` insertion port. An ambiguous external outcome instead transitions to nonterminal `reconciling` and remains owned by idempotent reconciliation from the durable attempt until a safe terminal outcome is proven. No component writes another owner's tables directly.
14. Emit non-authoritative decision telemetry. Telemetry failure never erases or substitutes for the durable audit evidence required by steps 11 through 13.

Parsing a token, hiding a UI action, resolving a URI, possessing a provider ID, receiving an event, or having an administrator role is never an allow decision.

### Security-mutation drain and visibility boundary

`AuthorizationEffectPermitV1.state` is the closed enum `issued`, `consumed`, `reconciling`, or `terminal`. Allowed transitions are `issued` → `consumed`; `issued` → `terminal`; `consumed` → `terminal` or `reconciling`; and `reconciling` → `terminal`. `terminal_outcome` is present only in `terminal` and is the closed enum `completed_before_boundary`, `canceled_before_effect`, `suppressed_before_disclosure`, `revoked_or_fenced`, or `failed_without_effect`. Every `consumed` permit is registered to an execution handle that can stop the provider call and suppress any not-yet-delivered protected output. `reconciling` means the effect is still ambiguous and is never treated as terminal or safe for a security-mutation drain. State transitions preserve the attempt and audit trail.

An authorization-relevant mutation first durably marks the affected fence `pending`, which denies affected decisions, prevents every `issued` → `consumed` transition, and cancels all unconsumed permits. Before the mutation may cross or acknowledge its externally observable committed security boundary, every permit already `consumed` under the prior fence must be `terminal`: a read/disclosure must have delivered all protected output before that boundary or be terminated with proof that later output is suppressed; an external effect must complete or be suppressed/reconciled to its safe terminal state; and a materialized credential must be revoked or fenced at the enforcing gateway/provider. A `reconciling` permit never satisfies this drain. Only then may the authoritative security mutation, advanced stable fence, and audit/outbox intent commit. If drain, suppression, reconciliation, or credential invalidation cannot be proven by the applicable permit/provider deadline, the security mutation is not acknowledged, the fence remains pending and affected operations remain denied until authorized reconciliation completes. A provider path that cannot implement this ordering is rejected by context resolution and cannot pass the authoritative post-policy enforcement check.

The pending marker is internal fail-closed coordination, not acknowledgment that the requested security mutation completed. The final authoritative commit/acknowledgment is the boundary used by `CBI-037` and `CBI-039`; no new protected content, credential use, or stale external effect may cross it. This ordering does not attempt to recall content fully delivered before the boundary.

### Deadlines, errors, and retry behavior

The coordinator uses the caller's remaining request deadline and an authorization hard ceiling of two seconds, whichever is shorter. Within that ceiling:

- one OpenFGA check receives at most 750 milliseconds;
- native policy evaluation receives at most 50 milliseconds and uses bounded rules with no unbounded loop, recursion, I/O, or dynamic code;
- provider/path context resolution and the authoritative provider/path enforcement check together receive at most 750 milliseconds and only the remaining overall authorization budget.

Scoped credential materialization occurs only after the audit precondition and fence recheck. It uses the caller's remaining request deadline and its provider adapter's separately reviewed timeout; expiration and revocation limits remain fixed by this ADR. A timed-out or ambiguous issuance is denied to the caller and reconciled by its durable idempotency key.

These are security ceilings, not availability targets. A deployment may lower them but cannot raise or disable them without a reviewed change. There is no hidden extended timeout for administrators, background workers, local mode, or bulk operations. Bulk/rebuild work evaluates each protected item and may control concurrency, but it does not relax a decision deadline.

The coordinator performs no dependency retry inside one decision. The sole internal reevaluation exception is a fence restart detected at step 10 before any effect permit, domain mutation, disclosure, provider call, or credential materialization exists. It restarts the complete sequence at most once, under the original request deadline, with a new decision ID and new snapshot/vector; the superseded decision is durably recorded as `superseded_before_effect` and cannot be executed. A second fence change denies. Timeout, cancellation, panic, schema error, unknown action/profile/obligation/reason, OpenFGA inconsistency, unavailable dependency, missing active bundle/model/trust set, provider context-resolution or authoritative enforcement failure, audit/CAS failure, or malformed output yields a deny with an internal reason-safe code and no retry. Public responses use the existing non-disclosing error contract and do not reveal which check, resource, tenant, relationship, label, or compartment caused the denial. A caller may retry the whole idempotent request under normal API rules and receives a new decision ID.

### Determinism and zero decision cache

The evaluator is a pure function of the validated input bytes' semantics and the exact active policy-bundle revision. It cannot read the ambient clock, environment, filesystem, network, DNS, database, random source, mutable global state, or provider response. Time is supplied only as `policy_context.now`; all authority, expiry, domain, profile, and revocation values are explicit input. Rule order cannot change the combining result. Reason codes and obligations are emitted in stable canonical order.

For identical validated input and bundle revision, `allow`, `policy_bundle_id`, reason codes, obligations, and cache fields are identical. The opaque per-evaluation `decision_id` is generated after semantic evaluation and is the only excluded field. An unsupported rule, field, obligation, profile, or bundle version denies rather than being ignored.

Version 1 has **no authorization decision cache**. Every protected operation performs a fresh OpenFGA check and native policy evaluation. Every output must therefore contain:

```text
cache.permitted = false
cache.max_age_seconds = 0
cache.invalidation_keys = []
```

No positive or negative decision may be stored in process memory, Valkey, PostgreSQL, CDN, browser state, event payloads, or a provider adapter for reuse. Holding the immutable active policy program, OpenFGA model identity, trusted public keys, or canonical resource data is not a decision cache; those values remain subject to their own version and consistency fences. HTTP responses containing protected results use the applicable private/no-store controls. A future nonzero decision cache requires a superseding ADR, proof that every fence and invalidation path is complete, and the full classification bypass matrix.

Any other accepted or candidate record that enumerates mandatory cache-key fields or maximum evidence expiry defines constraints that would apply **if** a future cache were separately approved. It does not activate a cache or override this v1 zero-cache decision.

### Agent, service-account, and Directory Group behavior

OpenFGA remains responsible for explicit Agent-specific authority, delegation, task/resource relations, and independent revocation. Assignment to Work grants no view, edit, execute, or provider credential. The policy input for an acting Agent must include `requested_by`, delegation, task scope, runtime identity, runtime security domain, classification ceiling, compartments, model provider, tool scope, execution environment, trusted attestation, expiry, and revocation state.

The final Agent allow is the intersection of:

1. current delegating-principal authority;
2. current Agent-specific authority;
3. the exact task resource and action scope;
4. runtime/workload identity and security-domain authorization;
5. session and execution-environment restrictions; and
6. resource classification and handling requirements.

The `authorization.agent_intersection` revocation term and every other term must be true. Removing the delegator's authority, Agent authority, task relation, enablement/revocation fence, runtime attestation, compartment, or applicable tool scope denies on the next operation. Requester authority is never copied to the Agent. External Agent runtimes use the same Platform API/MCP authorization path; the evaluator does not depend on a model, model provider, SDK, orchestrator, or runtime. A service account receives only its explicit OpenFGA and workload authority. A Directory Group may participate in relationship tuples but cannot authenticate, initiate, receive credentials, or appear as the acting principal.

### Provider and direct-path enforcement

The central allow does not make an unenforceable provider path safe. Before any direct Git, Git LFS, package, artifact, runner, object-store, webhook, or provider API access, the Platform must prove that the path can enforce the current container/security-domain restrictions. The adapter cannot translate a denied or unsupported contextual condition into a broader provider permission.

Credentials issued for direct Git or another approved direct protocol are bound to one acting principal, installation/Organization, resource or security container, permitted action set, security domain, activation-set/activation-envelope/archive/release-attestation and policy-bundle IDs/digests, OpenFGA model ID/source digest, exact trust-set/trust-envelope identity, activation/trust epochs, `activation_sequence`, accepted policy-time high-water/revision at issuance, and the complete consistency vector: principal, authority configuration, assertions/coverage/synchronization, group/Team bindings, tuple, session, delegation, task, runtime attestation, capability, resource/label/deny, and provider-enforcement revisions. The one-use effect permit must still be valid when it is consumed to materialize the credential, but its request-scoped expiry is not inherited by the credential after successful materialization. The credential expires no later than five minutes and no later than the earliest session, trusted-attribute/coverage, group synchronization, Agent attestation, delegation, task-scope, activation-set, trust-key, or provider-enforcement expiry; the enforcing gateway/provider compares the latest accepted high-water and revokes or rejects use at that bound. It is independently revocable, is never valid for provider business APIs, and is not reusable across resources or domains. Audit stores a credential identifier or hash, never the secret.

For an acting `agent`, direct Git over the configured SCM provider is the sole direct-provider/direct-protocol exception. An Agent can receive only a repository/domain/task/action-scoped Git credential; it cannot receive a package, artifact, runner, object-store, webhook, general provider API, or other provider-protocol credential. Those business operations must use the canonical Platform API/MCP path. Human users and service accounts still require an explicitly approved provider path and receive no authority from this sentence.

Permission or group removal, label raise, explicit deny, capability restriction, principal/session suspension or expiry, authority/assertion/synchronization/coverage change, task/delegation revocation, runtime-attestation change, provider-enforcement revision, trust-set/key change, or activation change stops new issuance and triggers the owned outstanding-permit, provider-reconciliation, credential, and gateway invalidation path. If the provider cannot revoke or constrain an already issued credential within the required fence, that security profile must place the path behind an enforcing gateway or deny it. Stock Gitea administrative/service tokens are never exposed as a substitute.

## Consequences

### Security, authorization, classification, and bypass paths

The accepted topology removes an evaluator network hop and its fail-open risks, but makes the Go coordinator and native rules security-critical code. A panic is recovered only at the coordinator boundary and becomes deny; it cannot return an incomplete allow. OpenFGA allow alone, policy allow alone, provider permission alone, Team hierarchy, Project accountability, Agent assignment, event receipt, search projection state, or administrator identity never grants access.

All list, count, facet, suggestion, navigation, activity, inbox, graph, notification, audit-view, export, and error paths call the same coordinator or consume a projection already filtered for the exact recipient and fence. Any uncertain projection state suppresses the result. Cross-domain/write-down transfer remains denied; the evaluator may produce an obligation for an external approved process but cannot automate the transfer.

### Contracts, ownership, and consumers

| Surface | Owner | Decision effect |
|---|---|---|
| OpenFGA model and model tests, `POL-FGA-V0.1` | WS-06 | Remain stock OpenFGA contracts; the evaluator cannot reinterpret relationship results. |
| Policy input/output, decision table, rule bundles, security-label profiles | WS-06 | Remain implementation-neutral and authoritative; no Go, OPA, or Rego representation enters public contracts. |
| Authorization coordinator and native evaluator | WS-06 | New Go implementation under owned modules; all other modules consume its typed interface. |
| `stead-api`/BFF composition root | WS-02 with WS-06 approval | Wire the coordinator through `/apps/core/`; expose no alternate evaluation path. |
| Public OpenAPI and error contracts | WS-01 with WS-06 approval | Expose no evaluator-specific endpoint and preserve non-disclosure. |
| Provider mapping, gateways, and scoped credentials | Owning provider workstream, with WS-06 approval | Must implement the common provider-path assertion and bypass suite; cannot decide policy locally. |
| Audit/events | WS-07 | Record the versioned decision context and activation metadata without protected bodies. |
| Search/graph/future MCP seam | WS-08 | Reuse the Platform path and never authorize from an index or provider business API. |
| CI, deployment, trust, and operations | WS-09/WS-12 | Exercise the same policy contract; no alternate infrastructure allow path. |
| Independent security and QA | distinct WS-13 identities | Approve the exact implementation, fixtures, dependency set, and release evidence. |

Changes to policy schemas, OpenFGA relations, label algebra, trusted-attribute precedence, Team roles, or bundle format remain with their existing owners and ADR gates. This ADR grants no cross-owner edit right.

### Data model, migration, and backward compatibility

This is the first executable evaluator, so there is no legacy policy engine or decision cache to migrate. `POL-DECISION-IO-V0.1`, the OpenFGA model, reason-safe output, and audit/event actor context remain compatible. Implementation adds only internal activation state, decision evidence, provider-credential metadata, and health state under the tables/interfaces of their owning modules.

The coordinator is introduced behind one typed interface before protected feature code. Existing Phase 1 probes contain no authorization behavior and are replaced rather than wrapped. A future policy input/output major coexists through the normal compatibility window; one request is evaluated against one declared contract version and activation set. Unsupported versions deny. Adding another evaluator requires the same fixtures to produce equivalent semantic output before it can be staged.

### Upgrade, rollback, backup, restore, and recovery

Evaluator binaries and signed bundle/model activation sets are versioned independently but declare compatibility. Upgrade stages the new binary and activation set, runs conformance and migration tests, and activates them only through ADR-0006's atomic pointer. A request never mixes a model, bundle, evaluator ABI, or contract version from different activation sets.

Rollback is allowed only as ADR-0006's forward-audited activation of a schema-compatible predecessor payload under current/higher trust, new accepted signing evidence, a higher `activation_sequence`, and nondecreasing policy-time substate. It repeats signature, continuous-validity, conformance, OpenFGA migration, provider-path, and non-disclosure checks. A revocation, label raise, explicit deny, trust-root revocation, `activation_sequence`, `policy_time_high_water`, or `policy_time_revision` is not undone as “rollback”; recovery is a new forward activation. If compatibility cannot be proven, remain denied and use forward recovery. Backup and restore preserve complete activation/trust/envelope/archive/release-attestation identities, model IDs/source digests, bundle bytes/digests, the separate current monotonic anchor and both substates, provider credential revocation state, effect permits, and decision/audit evidence.

### Observability, audit, privacy, and evidence

Metrics include decision allow/deny/error counts by safe reason category, stage latency, timeout counts, OpenFGA consistency failures, provider-context and authoritative-enforcement failures, activation epoch, and evaluator health. They must not use Organization, principal, resource, URI, label compartment, task, or provider credential as metric labels. Traces carry correlation and decision IDs plus model/bundle/activation versions; protected attributes, tuple contents, bodies, secrets, and policy input are excluded.

Audit records acting and requesting principals, authentication context, delegation/task context where present, action, protected resource reference under existing access rules, outcome, safe reason codes, exact activation-set/envelope/archive and release-attestation IDs/digests, policy-bundle ID, OpenFGA model ID/source digest, trust-set/envelope identity, activation/trust epochs, `activation_sequence`, accepted `policy_time_high_water`/`policy_time_revision`, every applicable consistency-vector revision, provider-enforcement result, effect-permit lifecycle and safe terminal outcome, correlation/causation, and cache status `not_permitted`. Policy changes, provider credential issuance/revocation, timeout denials, malformed inputs/results, clock rollback/recovery, drain/suppression/invalidation failures, and bypass attempts are mandatory audit events. Protected tuple/attribute values and credential material remain excluded. Public diagnostics expose health and version state without resource existence or policy content.

### Dependencies, licenses, supply chain, and portability

The evaluator uses the required Go implementation stack and Go standard library where sufficient. It introduces no OPA binary, Rego bundle, Wasm policy runtime, external policy service, proprietary component, cloud control plane, or outbound telemetry. Any additional parser, cryptographic, expression, or policy library needs an exact dependency/license/security approval before code import; a library cannot change the canonical input/output or rule semantics.

New Stead evaluator code is Apache-2.0. Release evidence includes source and binary provenance, SBOM, vulnerability/license/secret/SAST results, deterministic fixture results, and the exact model/bundle/evaluator digests. The same implementation must operate without network access after approved artifacts are installed.

### Documentation and accessibility

Contributor documentation must describe the single coordinator, rule-authoring constraints, reason-code discipline, no-cache invariant, and test corpus. Operator documentation must describe dependency health, deadlines, activation versions, credential revocation, failure symptoms, and recovery without suggesting a fail-open switch. User and accessibility documentation must ensure denial, reauthentication, and unavailable-state messages are useful, keyboard reachable, screen-reader announced, and non-disclosing.

## Verification

Decision-record acceptance approves the topology/evaluator choice and the named verification obligations below; it does not claim that the dependent implementation tests already exist or pass. The affected implementation, activation, and release must supply these automated tests and their traceability links:

- `T-ADR-0005-TOPOLOGY`: static and runtime checks prove the native evaluator is in-process, only the coordinator combines results, and no OPA/Rego, evaluator RPC, plugin loader, module-local policy, or alternate admin path exists.
- `T-ADR-0005-SEQUENCE`: spies and integration fixtures prove the exact authentication → context → resource/label → complete activation/vector snapshot → OpenFGA → non-authorizing provider/path context resolution → policy → authoritative provider/path enforcement → fence recheck → atomic compare-and-use audit/issued permit → fence-bound consume → effect enforcement → terminal audit sequence; the snapshot, permit, enforcement handle, and audit all bind the same activation-set/envelope/archive, release-attestation payload/envelope, policy/model, trust-set/envelope, epoch/anchor, and consistency-vector identities. OpenFGA or policy denial prevents the authoritative provider check and every prior denial prevents the protected operation; no external provider business call or credential materialization occurs before permit consumption. Permit expiry equals the earliest remaining request or applicable authentication/session/assertion/coverage/synchronization/delegation/task/attestation/activation/trust/provider temporal bound, and missing bounds deny. Domain mutation fixtures prove only the owning module writes domain state, audit/event intent enters only through the WS-02 `core_outbox` port, and WS-07 materializes through its owned ports.
- `T-ADR-0005-FAIL-CLOSED`: inject OpenFGA unavailable/malformed/stale responses, evaluator deadline/panic/malformed output, missing/unknown bundle, unsupported obligation, provider-context failure, authoritative provider-enforcement failure, audit-precondition failure, and cancellation; none produces content, metadata, credentials, or an external provider business call. OpenFGA or policy denial never invokes the authoritative provider/path checker. Exact two-second/750-millisecond/50-millisecond/750-millisecond upper bounds, remaining-budget propagation, and lower-only deployment configuration are enforced; attempts to raise or disable a bound fail contract validation. Ambiguous external outcomes retain a durable idempotent attempt for reconciliation.
- `T-ADR-0005-ZERO-CACHE`: repeated identical requests each call OpenFGA and the evaluator, output is exactly `false/0/[]`, protected HTTP results are not reusable, and no process, database, Valkey, CDN, browser, event, or adapter decision-cache code path exists.
- `T-ADR-0005-DETERMINISM`: identical input plus bundle yields identical semantic output excluding `decision_id`; clock, map/rule order, locale, process restart, replica, and offline execution do not change it.
- `T-ADR-0005-FENCE`: commit principal suspension, authority/assertion/sync/coverage change, group or Team binding removal, session revoke, tuple add/remove, label raise, explicit deny, bundle/trust activation, capability restriction, task/delegation revocation, runtime-attestation change, and provider-enforcement change at every boundary between steps 4 and 13 and while output is streaming. OpenFGA fixtures require the exact model ID, `HIGHER_CONSISTENCY`, disabled query caches, local pending/stable fence ordering, acknowledged mutation, and higher-consistency tuple presence/absence verification; they reject any invented provider revision/zookie parameter or claim. Each race linearizes before permit issue/consume and restarts or denies, or marks the fence pending, cancels unconsumed permits, drains/suppresses consumed effects, invalidates materialized credentials, and only then commits/acknowledges the security mutation. Concurrent compare-and-max policy-time advances do not restart or stale an activation pointer; they deny/suppress/revoke exactly when the latest high-water reaches an expiry and can never lower time or extend validity. Injected tuple-write/read, time-substate, drain, suppression, provider, and process failures leave affected protected operations denied; no protected byte or credential use occurs after the committed boundary, no stale allow crosses the compare-and-use gate, and a second activation/vector fence change never retries.
- `T-ADR-0005-AGENT-INTERSECTION`: separately mutate delegator authority, Agent authority, task action/resource, runtime identity/domain/attestation, session/environment, classification/compartment/handling, and revocation. Every missing or false term denies; assignment and requester authority alone never allow.
- `T-ADR-0005-PRINCIPALS`: user and service-account positive/negative paths pass; Directory Group may be an OpenFGA subject but cannot act or receive a credential.
- `T-ADR-0005-PROVIDER-PATH`: direct Git/HTTPS/SSH/LFS, package, artifact, runner, object-store, webhook, and provider API fixtures prove that pre-policy provider/path resolution is non-authorizing; OpenFGA and policy precede the authoritative provider/path result; the authoritative result matches the prospective input and exact activation/vector revision; and no provider business call or credential materialization occurs before a valid one-use permit is consumed. The materialized credential does not inherit the consumed permit's request deadline; it retains exact activation/trust/signing-evidence and complete consistency-vector binding, the five-minute maximum TTL and every applicable session/authority/activation/trust/provider earliest-expiry bound, independent revocation/invalidation triggers, no business-API token reuse, and denial where the provider cannot enforce context. Agent fixtures receive only repository/domain/task/action-scoped Git credentials; every package, artifact, runner, object-store, webhook, other direct-protocol, and provider-business credential request by an Agent denies.
- `T-ADR-0005-NONDISCLOSURE`: denials for resources, aliases, lists, counts, facets, suggestions, navigation, graphs, inbox/activity, notifications, audit views, exports, and errors reveal no protected existence or reason detail.
- `T-ADR-0005-MIGRATION-ROLLBACK`: compatible binary/contract/bundle/model staging and rollback pass; incompatible or revoked targets remain denied and require forward recovery.
- `T-ADR-0005-OBSERVABILITY`: required metrics, traces, and audit fields exist while protected bodies, secrets, attributes, tuples, credential values, and high-cardinality identifiers do not.

The implementation must also pass every row of `policies/policy-decision/decision-table.yaml`, all OpenFGA model/migration tests, the complete `TEST-004` classification matrix, provider contract/bypass tests, both golden scenarios where applicable, 100% policy decision-row coverage, and at least 90% mutation score for critical policy. A second evaluator is forbidden until differential conformance is added and passes.

## Rollout and supersession

1. Land the typed coordinator and pure evaluator behind deny-only probes.
2. Add every canonical decision row, Agent seam, non-authorizing provider-context resolution, authoritative post-policy provider enforcement, failure injection, and audit/telemetry assertion.
3. Stage the signed model/bundle activation set under ADR-0006 and run offline and HA conformance.
4. Enable one protected vertical-slice path, then the remaining paths only after bypass tests pass continuously.
5. Abort on a mixed activation pair, missing audit, stale fence, non-determinism, unexpected network call, unsupported rule, decision reuse, or disclosure.

A future ADR may select another native evaluator or OPA/Rego only after documenting the new dependency and license posture, bundle migration, topology, failure behavior, air-gap operation, performance, differential conformance, rollback, and removal of the old implementation. It may not change the locked combining rule, OpenFGA responsibility, provider enforcement, Agent intersection, default deny, or non-disclosure without explicit project-owner approval of the underlying architecture change.

## Reviews and approvals

Review here approves this decision record at one exact revision. Consumer reviews and executable failure-injection, migration, golden, and release evidence remain separate implementation gates.

| Role | Identity | Disposition | Evidence/date |
|---|---|---|---|
| Contract owner (WS-06) | pending non-author reviewer | PENDING | Required for policy semantics, OpenFGA boundary, and Agent intersection |
| Architecture and standards (WS-01) | pending reviewer | PENDING | Required for topology, module boundaries, and contract compatibility |
| Core composition owner (WS-02) | pending reviewer | PENDING | Decision-level `/apps/core` wiring boundary now; executable composition evidence before merge |
| Provider/event/search/operations reviewers (WS-03/07/08/09/12) | pending implementation reviewers | PENDING | Required before each owned consumer or bypass path activates |
| Independent QA (distinct WS-13 identity) | pending reviewer | PENDING | Decision/test-plan reciprocity now; exact failure-injection, migration, and golden evidence later |
| Independent security (distinct WS-13 identity) | pending reviewer | PENDING | Must not be the ADR author; decision-level security/dependency review now and executable evidence later |
| Project owner | not required for this conforming selection | N/A | Required only if a future change reopens a locked decision |
