# ADR-0003: Trusted principal and runtime attributes

- **Status:** Proposed; decision complete, dependent implementation remains blocked pending the approvals below
- **Date:** 2026-08-29
- **Decision owners:** WS-06
- **Project-owner approval required:** yes; the normalization is conforming, but its pre-consumer correction of the closed `POL-DECISION-IO-V0.1` schema requires project-owner approval under the contract ownership matrix
- **Requirement IDs:** `PRIN-007`, `PRIN-011`, `PRIN-012`, `DOM-010`, `AUTH-001`, `AUTH-002`, `AUTH-004`, `AUTH-005`, `AUTH-006`, `CLS-003`, `CLS-006`, `AGENT-001`, `AGENT-003`, `AGENT-006`, `SEC-006`, `TEST-004`
- **Affected contracts/modules/directories:** `/modules/identity/`, `/modules/authorization/`, `/packages/domain-schemas/identity/`, `/packages/provider-sdk/identity/`, `/providers/identity-oidc/`, `/providers/identity-scim/`, `TrustedAttributeProvider`, `/policies/policy-decision/`, identity portions of `/specs/openapi/`, identity/audit event schemas, deployment security-domain profiles, authorization consistency fences, and protected projections
- **Resolves upon acceptance:** `ADR-CAND-005`
- **Supersedes / superseded by:** none; a change to assertion identity, authority selection, conflict handling, or runtime-attestation binding requires a superseding ADR and compatibility plan

## Context and decision scope

Stead must normalize human, Agent, service-account, directory-membership, session, and future external-runtime evidence without trusting provider claim names or allowing a subject to assert its own authority. Authorization must distinguish an acting principal from a non-acting Directory Group, correlate OIDC and SCIM identities without email-based identity collisions, and evaluate short-lived Agent runtime evidence without turning a runtime or model provider into an authorization source.

The existing policy-decision contract already reserves trusted-attribute provenance, freshness, runtime identity, security domain, classification ceiling, compartments, model provider, tool scope, execution environment, revocation, and the six-way Agent authority intersection. This ADR fixes their normalization and conflict semantics before `STEAD-P1-006`. It does not select an OIDC/SCIM product, policy evaluator, agent runtime, attestation technology, signature format, model provider, or executable agent orchestration.

## Decision drivers

- Deny-by-default classification and information-flow decisions from verifiable, current evidence
- Stable canonical principal identity across provider rename, claim rename, and provider replacement
- Deterministic behavior when multiple authorities are configured or disagree
- Prompt revocation without serving a cached allow across a stale consistency fence
- External Agent runtime compatibility without model, SDK, cloud, or orchestrator coupling
- Protected-attribute minimization in APIs, logs, telemetry, search, and audit
- Versioned, portable contracts that work offline and in air-gapped deployments
- No configurable ontology, user-defined authorization attributes, or module-local claim interpretation

## Considered options

1. **Pass provider claims directly to policy.** This has little initial mapping work, but provider names, value types, freshness, and issuer semantics become part of the public authorization contract. It permits inconsistent module interpretation and unsafe self-assertion. Rejected.
2. **Copy selected claims onto the principal as mutable profile fields.** Reads are simple, but provenance, expiry, conflict, revocation, session specificity, and runtime binding are lost. A copied value can outlive its authority. Rejected.
3. **Normalize authority-bound, versioned assertions and separate short-lived runtime attestations.** This preserves source evidence and deterministic policy input while keeping providers replaceable. Accepted.
4. **Adopt a general claims/ontology or external policy-information-point framework.** It could model arbitrary attributes, but it introduces configurable authorization ontology, operational coupling, and dependencies before Stead needs them. Rejected.

The accepted representation is implementable with the approved Go, PostgreSQL, OIDC, SCIM, OpenFGA, and deterministic policy-decision boundaries. It adds no required third-party runtime or license.

## Decision

### Canonical assertion representation

Authorization-relevant principal evidence is represented as a versioned `TrustedAttributeAssertionV1`. It is an internal identity/authorization contract, not a new OWGP resource or configurable product concept. Every assertion contains:

- the canonical subject `PrincipalRef` and its acting/non-acting kind;
- a system-registered, namespaced `attribute_key`;
- an explicit value type (`string`, `boolean`, `integer`, or `string_set`) and canonicalized value;
- a configured `authority_id` and source kind (`oidc_claim`, `scim_attribute`, `platform_authority`, `workload_identity`, or `runtime_attestation`);
- the immutable external subject/object binding or a protected reference to it;
- `issued_at`, `last_synced_at`, and the earliest controlling `review_or_expires_at`;
- authority, assertion, and revocation revisions;
- provenance sufficient to reproduce verification without copying credentials or raw tokens;
- sensitivity (`public`, `internal`, or `protected`), last synchronization result, verification result, and revoked state.

The policy-decision input may omit the subject inside each assertion because the enclosing actor supplies it, but the identity store and resolver must bind every assertion to exactly one canonical subject. Authorization values may not be arbitrary JSON objects. External claim names and values are mapped through a versioned, system-owned attribute registry. A deployment profile configures authorities and required attributes; it cannot create a new attribute that grants authority or change a value's canonical meaning.

`not_applicable` is not an attribute value and cannot be encoded as a `TrustedAttributeAssertionV1`. It is a separate, non-authorizing `TrustedAttributeCoverageResultV1` issued by the configured primary authority for exactly one canonical subject and registered attribute key. The result contains status exactly `not_applicable`, authority ID and revision, immutable subject binding, source kind, provenance reference, issued/last-synchronized/expiry times, synchronization and verification results, coverage-result revision, revocation revision, and revoked state. It is usable only while current, verified, successfully synchronized, non-revoked, and cryptographically or transport-bound to that authority. It grants nothing, is never returned as a policy attribute value, and exists solely to prove that the primary authority has authoritatively disclaimed coverage so an explicitly configured fallback may be considered.

Directory Groups remain non-acting `PrincipalRef` values. Their membership supplies explicit authorization relationships and provisioning context, not an acting identity or a substitute for the actor's trusted attributes.

### Authority selection and conflict behavior

Each registered attribute key has exactly one configured primary authority for a deployment security domain and may name an ordered list of explicit coverage fallbacks. Authorities may be primary for different keys. Selection is deterministic:

1. use a current, verified, non-revoked primary assertion;
2. use a fallback only when the primary authority has issued a current `TrustedAttributeCoverageResultV1` with status `not_applicable` for that exact subject/key and the profile explicitly permits that fallback;
3. do not fall back because of timeout, network failure, stale synchronization, expiry, verification failure, or revocation;
4. if current candidate assertions conflict in subject binding, canonical value, authority revision, or revocation state, mark the attribute conflicted and deny every decision that requires it.

Stead never selects the most permissive value and never unions set-valued grants by default. A system profile may define a named deterministic reducer for a specific key; reducers that affect authority use intersection or the more restrictive result unless a separately approved downgrade/release workflow authorizes otherwise. Unknown keys, values, authorities, reducer versions, or provenance formats deny when the attribute is required.

### OIDC, SCIM, and canonical-principal correlation

OIDC identities bind by the configured OIDC Issuer Identifier plus immutable `sub`. The token `iss` value must exactly equal the configured issuer identifier under OIDC issuer comparison; generic URL normalization, case folding, trailing-slash insertion/removal, percent-decoding, host aliases, redirects, discovery aliases, or provider display names cannot collapse two issuer identifiers. Changing an issuer identifier is an explicit audited provider-identity migration with collision/quarantine checks, never an implicit normalization rule. SCIM resources bind by configured provisioning authority plus immutable SCIM resource ID; `externalId` may participate only when that authority guarantees its stability and uniqueness. Email address, user name, display name, group name, or provider URL is never a canonical identity key.

OIDC and SCIM records correlate to one canonical principal only through a configured immutable correlation identifier issued by a trusted authority or an authorized, audited administrative mapping. One external subject may map to only one active canonical principal. A collision, ambiguous remap, recycled external identifier, cross-Organization mismatch, or attempt to merge two canonical IDs is quarantined and cannot grant access until an authorized resolution records provenance. Rename and provider replacement preserve the canonical UUID. Suspension, deprovisioning, and credential revocation invalidate acting status and advance the consistency fence before success is reported.

### Freshness, synchronization, revocation, and caching

An assertion or coverage result is usable only when it is verified, not revoked, within both its authority-configured evidence age and synchronization age, before `review_or_expires_at`, and its last synchronization result is successful. Time is taken from the trusted policy-decision context, not a client field. For deterministic evaluation, the profile fixes `maximum_evidence_age`, `maximum_sync_age`, and `maximum_future_clock_skew`; validity requires all of `now <= issued_at + maximum_evidence_age`, `now <= last_synced_at + maximum_sync_age`, `now < review_or_expires_at`, `issued_at <= now + maximum_future_clock_skew`, and `last_synced_at <= now + maximum_future_clock_skew`. The earliest bound wins. A timestamp beyond the allowed future skew, negative interval, `partial`, `failed`, `unknown`, stale, missing, or unverifiable result denies.

`issued_at` is the authority's issuance/change time for the exact evidenced value or coverage result, or the profile-defined full-read observation time when that authority exposes no issuance time. `last_synced_at` is only the time Stead last completed verification and synchronization. A heartbeat, retry, partial sync, or re-read of the same authority revision may advance `last_synced_at` but cannot advance `issued_at`, change the value, or extend `review_or_expires_at`. Only a new authoritative revision or explicit authority reissuance/review with new provenance may create a later `issued_at`. Clock-skew handling never extends an expiry or maximum-age deadline.

Every decision input includes principal ID/type, selected assertion and authority revisions, authority-configuration revision, session revision/expiry, relevant group/tuple revision, policy bundle/model revision, resource and label revision, and—when present—delegation, task, runtime-attestation, and revocation revisions. ADR-0005 selects no authorization-decision cache for v1. If a future superseding ADR separately permits one, its key must include all of those revisions and it must expire no later than the earliest evidence expiry. Revocation, suspension, authority remap, conflict, failed synchronization, classification raise, group removal, or task/delegation change advances the affected consistency fence immediately. If the latest committed revision cannot be proven, the request denies and refreshes; rollback never resurrects an old allow.

### Agent and runtime evidence

Persistent Agent identity/authority assertions and per-execution runtime evidence are separate. `AgentRuntimeAttestationV1` is short-lived and binds all of the following:

- canonical Agent ID and Agent authority revision;
- external workload/runtime identity;
- exact delegation, task scope, and session/environment context;
- runtime security domain, classification ceiling, and compartments;
- model provider, tool scope, and execution environment;
- issuing authority, provenance/attestation reference, issue/expiry time, version, verification, and revocation revision.

An external runtime may present evidence, but only a configured `TrustedAttributeProvider` or workload-identity authority may verify and normalize it. The Agent, runtime, model provider, task payload, prompt, and requester cannot self-assert trusted values. Model-provider identity and tool scope may restrict a decision; neither grants authority. Runtime evidence is not copied into durable broad Agent permissions and is not reused across a different task, delegation, session, environment, or security domain.

An Agent allow still requires every term of the locked intersection: delegator authority, Agent-specific authority, task-scoped authority, runtime-domain authorization, session/environment restrictions, and resource classification/handling. Missing runtime evidence denies an Agent operation that requires it. This ADR preserves external runtime and MCP/A2A compatibility but authorizes no Agent execution, dispatch, memory, prompt, or model-hosting implementation.

### Contract and ownership boundaries

| Contract | Owner | Permitted responsibility | Prohibited boundary |
|---|---|---|---|
| Canonical principal, identity binding, assertion persistence and resolver | WS-06, `/modules/identity/` and `/packages/domain-schemas/identity/` | Normalize and version subject/attribute evidence | No provider claim or email becomes canonical identity |
| OIDC, SCIM, and trusted-attribute ports/adapters | WS-06, `/packages/provider-sdk/identity/` and identity providers | Authenticate, provision, resolve, verify, refresh, revoke | No self-asserted trusted value or provider-owned authorization decision |
| OpenFGA and deterministic policy-decision inputs | WS-06, `/modules/authorization/` and `/policies/` | Consume normalized evidence and revisions | No duplicate module policy, default allow, or administrator bypass |
| Resource/domain consumers | WS-02/03/04/07/08/09/10/11/12 | Request a central decision and enforce its obligations | No reading raw claims or deriving independent authority |
| API/UI | WS-01/05 | Expose authorized, minimized identity state and clear conflict/expiry status | No ordinary-client attribute enumeration or raw provenance/token display |
| Audit/events | WS-07 | Record lifecycle and decision metadata | No protected attribute values, credentials, or raw attestations in event bodies |

## Consequences

### Security, authorization, classification, and bypass paths

Required evidence that is absent, stale, expired, conflicted, revoked, unverifiable, from the wrong authority, or tied to the wrong subject/runtime/task denies. Authentication success alone supplies no clearance, compartment, release, Team, Agent, or runtime authority. Protected attribute existence and values are themselves authorization-filtered. Search, counts, directory views, explain/debug responses, activity, notifications, errors, and timing may not reveal a protected attribute, conflict, group, runtime, or target resource to an unauthorized caller.

### Data model, migration, and backward compatibility

The first implementation introduces versioned identity bindings, assertions, authority policies, conflicts/quarantine, synchronization state, and revocation revisions. Existing policy input field names such as `authority`, `provenance`, `issued_at`, `last_synced_at`, `review_or_expires_at`, `version`, and `verified` retain their meaning and are tightened rather than reinterpreted.

The checked-in `POL-DECISION-IO-V0.1` schema is closed with `additionalProperties: false`, so typed-value, authority/assertion/revocation revision, synchronization-result, and revoked-state fields are not falsely described as compatible additions to that exact schema. Acceptance authorizes a pre-consumer correction of v0.1 in one coordinated contract commit because no production policy consumer or persisted policy input exists. If a consumer is established before that correction lands, the change instead requires a new compatible schema/API major and coexistence; no reader may silently ignore the new fields.

Any prototype or imported claim is backfilled only when its immutable subject, authority, canonical key/value, provenance, and freshness can be verified. Otherwise it is stored as non-authoritative migration evidence or quarantined and cannot allow. Provider IDs remain opaque mappings. Export/import preserves canonical principal IDs, authority/assertion revisions, provenance references, conflicts, and revocations without exporting credentials or raw tokens.

### Upgrade, rollback, backup, restore, and recovery

Rollout is expand/verify/activate/contract: add v1 storage and resolver, import and verify bindings, run shadow decisions, compare deny/allow deltas, activate revision-fenced reads, then retire legacy claim reads. Abort on ambiguous identity, authority conflict, unexplained allow widening, missing expiry/provenance, stale-cache allow, or protected-attribute leakage.

Before activation, rollback removes the new read path while retaining evidence tables. After v1 assertions influence decisions, rollback may select only a previously compatible resolver/policy revision that understands every persisted assertion and revocation. Otherwise recovery is forward and fail-closed. Backup/restore preserves canonical identity bindings, authority configuration, assertion/revocation revisions, quarantine state, and audit evidence; restore cannot reset freshness or convert expired evidence into current evidence.

### APIs, schemas, events, providers, and standards mappings

The Phase 1 contract work updates the WS-06-owned identity schemas/provider SDK, the implementation-neutral policy input, minimized identity administration API, and identity/audit lifecycle events. OIDC Core provides human authentication identity, SCIM 2.0 provides provisioning identities/groups, and OpenFGA consumes explicit relationships; none replaces the canonical assertion contract. Runtime attestation stays provider-neutral. Public representations use stable canonical IDs and versioned enums and never expose provider claim names as canonical fields.

### Observability, audit, privacy, and evidence

Audit records assertion issue/refresh/revoke/conflict/quarantine, identity-link creation/change, authority configuration change, synchronization outcome, runtime verification, consistency-fence advancement, and allow/deny reason with actor/requester, subject, authority/assertion revisions, model/policy versions, correlation, causation, and source category. If a future ADR permits authorization-decision caching, its invalidations are audited as well. Records use hashes or protected references where values are unnecessary. Metrics use low-cardinality authority/profile/outcome categories, never principal IDs, external subjects, attribute values, compartments, or task contents. Traces carry decision and correlation identifiers, not tokens or raw attestations.

### Dependencies, licenses, supply chain, and portability

No new dependency is approved by this ADR. OIDC/SCIM adapters, signature/attestation libraries, or external authority connectors require exact dependency, license, vulnerability, provenance, upgrade, and rollback approval before use. The canonical representation and deterministic selection rules are implementable offline and do not require a SaaS identity graph, cloud attestation service, model provider, or Agent SDK.

### Documentation and accessibility

Operator documentation must explain authority mapping, correlation, freshness, quarantine, revocation, recovery, and protected-attribute access. Administrative UI must distinguish unavailable, stale, conflicted, revoked, and unauthorized without relying on color alone and without disclosing values to an unauthorized administrator. User-facing identity surfaces continue to present People, Agents, and Teams rather than provider claims.

## Verification

Decision-record acceptance approves the normalization choice and the named verification obligations below; it does not claim that the dependent implementation tests already exist or pass. Those tests and their traceability links are mandatory before the affected contract implementation, activation, or release can be approved.

| Test ID | Layer | Required evidence |
|---|---|---|
| `T-ADR-0003-NORMALIZATION` | schema/contract | Every supported source maps to the same typed `TrustedAttributeAssertionV1`; `not_applicable` is accepted only as a complete non-authorizing `TrustedAttributeCoverageResultV1`; unknown key/type/status/authority/provenance fails validation. |
| `T-ADR-0003-AUTHORITY-PRECEDENCE` | policy contract | Valid primary wins; only a current verified primary-authority coverage result for the exact subject/key enables a configured fallback; forged/value-encoded, wrong-subject/key, timeout/stale/revoked primary and conflicting values deny. |
| `T-ADR-0003-IDENTITY-CORRELATION` | integration | Exact configured OIDC issuer+subject and SCIM authority+resource ID map deterministically; issuer case/trailing-slash/encoding/alias variants remain distinct unless an explicit migration succeeds. Email/name collisions, recycled IDs, cross-Organization mappings, and ambiguous merges quarantine and deny. |
| `T-ADR-0003-FRESHNESS-REVOCATION` | integration/security | The exact evidence-age, sync-age, explicit-expiry, and future-skew calculations pass boundary fixtures; a heartbeat/retry/re-read cannot refresh `issued_at` or extend authority. Expiry, failed/partial sync, suspension, authority remap, and revocation advance the fence and prevent reused or direct-path allows; a future cache implementation must pass the same case. |
| `T-ADR-0003-AGENT-RUNTIME-BINDING` | policy/security | Runtime evidence is bound to the exact Agent/task/delegation/session/domain; replay to another context and any missing intersection term deny. |
| `T-ADR-0003-NO-SELF-ASSERTION` | API/provider/security | User, Agent, runtime, request payload, provider extension, and model-provider values cannot write or override trusted authority. |
| `T-ADR-0003-NONDISCLOSURE` | API/UI/search/audit | Ordinary and unauthorized administrative callers cannot enumerate values, conflicts, group bindings, raw provenance, or runtime evidence through any aggregate/error surface. |
| `T-ADR-0003-DETERMINISM` | policy conformance | Identical normalized evidence and revision set produces the same semantic decision; mutation tests kill permissive conflict/fallback/freshness changes. |
| `T-ADR-0003-MIGRATION-ROLLBACK` | upgrade/backup | Verified backfill, quarantine, shadow comparison, backup/restore, pre-activation rollback, and post-activation forward recovery preserve revocations and never widen access. |

These tests supply concrete evidence for `T-AUTH-001-ACCEPTANCE`, `T-AUTH-002-ACCEPTANCE`, `T-AUTH-004-ACCEPTANCE`, `T-AUTH-005-ACCEPTANCE`, `T-AUTH-006-ACCEPTANCE`, `T-CLS-003-ACCEPTANCE`, `T-CLS-006-ACCEPTANCE`, `T-AGENT-003-ACCEPTANCE`, `T-AGENT-006-ACCEPTANCE`, `T-SEC-006-ACCEPTANCE`, and applicable `SEC-BYP-036`, `SEC-BYP-038`, `SEC-BYP-039`, and `SEC-BYP-040` cases. The general and software golden scenarios use synthetic trusted human attributes; Agent seam tests prove denial without current runtime/task/delegation evidence and do not execute an Agent.

## Rollout and supersession

`STEAD-P1-006` remains blocked until this ADR and the independently required policy/topology and label decisions are accepted. WS-06 publishes the v1 schema, authority registry, mapping fixtures, and migration plan before any consumer reads claims. Consumers switch only through the central authorization contract. A future ADR may add a new evidence source or attestation profile, but it must preserve canonical principal identity, no self-assertion, conflict-as-deny, revision fencing, external-runtime neutrality, and the Agent authority intersection or explicitly obtain project-owner approval to change a locked decision.

## Reviews and approvals

Review here approves this decision record at one exact revision. Consumer reviews and executable migration/security evidence remain separate gates on the implementation.

| Role | Identity | Disposition | Evidence/date |
|---|---|---|---|
| Contract owner (WS-06 identity/authorization) | pending non-author reviewer | PENDING | Decision semantics and owned-contract boundary; implementation evidence remains separately gated |
| Architecture and standards (WS-01) | pending non-author reviewer | PENDING | Canonical identity, portability, and boundary review |
| Domain/search/operations consumers (WS-02/08/12) | pending reviewers | PENDING | Persistence, projection, deployment, backup, and runtime-seam review |
| Independent QA (WS-13) | pending non-author reviewer | PENDING | Decision/test-plan reciprocity now; executable contract, migration, negative-test, and reproducibility evidence before implementation approval |
| Independent security (distinct WS-13 identity) | pending non-author reviewer | PENDING | Decision-level authority, revocation, non-disclosure, Agent, and bypass review now; executable evidence later |
| Project owner | pending | PENDING | Required for the pre-consumer `POL-DECISION-IO-V0.1` correction |
