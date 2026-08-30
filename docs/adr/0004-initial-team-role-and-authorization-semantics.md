# ADR-0004: Initial Team role and authorization semantics

- **Status:** Proposed; decision complete, dependent implementation remains blocked pending the approvals below
- **Date:** 2026-08-29
- **Decision owners:** WS-06 with WS-02 Team-domain implementation
- **Project-owner approval required:** yes; this fixes a public Team-role and authorization contract used by the API and product UI
- **Requirement IDs:** `PRIN-015`, `DOM-009`, `AUTH-002`, `AUTH-003`, `AUTH-006`, `CLS-006`, `UX-006`, `UX-007`, `AGENT-003`, `SEC-006`, `TEST-004`
- **Affected contracts/modules/directories:** Team relationship storage in `/modules/organization/`, identity/provisioning in `/modules/identity/`, `/modules/authorization/`, `/policies/openfga/`, `/packages/domain-schemas/`, identity provider interfaces, Team portions of `/specs/openapi/`, Team/authorization/audit events, Team UI, provider permission projection, migration/export, and classification/non-disclosure tests
- **Resolves upon acceptance:** `ADR-CAND-021`
- **Supersedes / superseded by:** none; new roles, changed grant semantics, lead subject types/cardinality, or hierarchy/accountability inheritance require a superseding ADR and public compatibility plan

## Context and decision scope

Stead has stable hierarchical Teams, explicit Directory Group bindings, exactly one owning Team per Project, and optional contributing Teams. The directive deliberately separates those organizational/accountability relationships from authorization. It does not choose the initial executable Team role vocabulary or whether product labels map onto generic viewer/editor tuples.

This decision must make Team membership understandable to HR, finance, legal, operations, research, program management, administrative, and software organizations without introducing an arbitrary role engine. It must also preserve the rule that Team hierarchy, Project ownership, and Project contribution grant nothing by themselves; keep Directory Groups non-acting; and prevent a Team role from bypassing classification or future Agent runtime restrictions.

## Decision drivers

- Fixed, low-concept-count Team roles with stable API and UI meaning
- Explicit, reviewable OpenFGA relationships rather than hidden application mappings
- Least privilege for Team content, roster, role management, and hierarchy operations
- No accidental access from parent/child placement or Project accountability
- Prompt, revision-fenced direct and SCIM-derived revocation
- Human accountability for Team leadership without excluding explicit Agent/service participation
- Backward-compatible handling of the Phase 0 `member`, `viewer`, and `editor` relation seams
- Provider-neutral export/import and no directory-group-to-Team ontology leakage

## Considered options

1. **Persist configurable role labels and map them to generic viewer/editor relations.** This is flexible, but it creates a tenant-specific role/ontology engine, makes APIs and UX inconsistent, and risks mapping drift. Rejected.
2. **Expose only generic `viewer` and `editor`.** This is small, but it cannot express organizational leadership, membership, contribution, cardinality, provisioning, or accessible product language. Rejected.
3. **Use fixed `lead`, `member`, and `contributor` Platform roles as same-named explicit OpenFGA relations, then derive a small fixed permission set.** This makes the organizational relationship and authorization consequences visible and testable while retaining explicit direct grants. Accepted.
4. **Infer roles from Team hierarchy, owning/contributing Projects, or every external Directory Group.** This reduces tuple administration but violates locked non-inheritance and product-ontology boundaries. Rejected.

The accepted option adds no dependency. Its data and authorization changes are reversible through a versioned tuple/binding migration, but its public labels and semantics require compatibility discipline once released.

## Decision

### Fixed Team roles

The canonical, non-configurable `TeamRole` enum is exactly:

- `lead`: a human accountable for Team profile and role administration;
- `member`: a principal that belongs to the Team and receives only the fixed Team-container permissions below; membership alone grants no Project or Project-scoped Work Item access;
- `contributor`: a principal that collaborates with the Team with read-level Team-container access but is not a Team member.

These values are stable API values and same-named OpenFGA relations. Display labels may be localized, but their semantics and ordering are system-owned. Administrators cannot add, rename, reorder, script, or remap roles.

This ADR introduces no Team lifecycle/status value: every canonical Team that exists is subject to the normal lead invariant. In normal operation it has one or more active direct User leads, where “active” refers only to the linked User's canonical identity status. `lead` accepts only an active `user`; it cannot be supplied by a Directory Group and cannot be assigned to an Agent or service account. `member` and `contributor` accept explicit `user`, `agent`, and `service_account` subjects and `directory_group#member` usersets. Agents and service accounts therefore participate only through an explicit role and still require their independent authentication, delegation/runtime where applicable, classification, session, and provider-path checks.

### Fixed permission derivation

The Team authorization model retains explicit direct `viewer` and `editor` tuples for exceptional least-privilege grants and adds the three role relations. Computed permissions are fixed:

```text
viewer           = direct viewer OR lead OR member OR contributor
editor           = direct editor OR lead OR member
roster_viewer    = lead OR member OR organization editor from organization
profile_manager  = lead OR organization editor from organization
role_manager     = lead OR organization editor from organization
hierarchy_manager = organization editor from organization
```

`viewer` permits the authorized minimal Team surface and any Team-container read that another approved resource contract explicitly derives from `team.viewer`; a Team-scoped Document may use this derivation. `editor` permits Team-container write only where that resource contract explicitly derives from `team.editor`; a Work Item cannot use either derivation because canonical Work Items are always Project-scoped. Team permissions do not themselves rename/reparent the Team, manage roles, change classification, activate Project capabilities, or administer a Project. `contributor` receives no Team-container edit. Roster access and management are separate from generic Team visibility.

Team profile and role administration require the fixed `profile_manager` or `role_manager` relation shown above: an active direct User lead or an Organization `editor` may satisfy that relationship. Team hierarchy/reparenting and lead recovery are Organization-level interventions and require a current explicit Organization `editor` allow; a Team lead alone cannot satisfy them. The deterministic policy layer additionally requires the **acting principal** for every `profile_manager`, `role_manager`, `hierarchy_manager`, and lead-recovery action to be an active `user`. An Agent, service account, or Directory Group cannot exercise those Team-management permissions, even when it has or contributes to an Organization `editor` relationship; requester authority is not inherited. An acting User may satisfy the Organization-editor branch directly or through a current Directory-Group userset, but stale/failed group synchronization denies. These are restrictions of the named explicit/computed OpenFGA allows, never policy-created allows.

Organization membership or visibility alone grants nothing. Creating a Team requires the existing authorized Organization operation and atomically creates at least one direct active User lead. Adding or removing a lead requires `role_manager`, the policy-decision allow, and a postcondition that at least one active direct User lead remains. Self-removal of the last active lead and any Team-role transaction that would orphan the Team fail.

Identity suspension, deprovisioning, or identity merge must not be blocked merely to preserve Team administration. Before such an identity lifecycle operation is acknowledged, WS-06 invokes the WS-02-owned Team lifecycle port in the same ordered PostgreSQL transaction: it advances the principal and affected Team lead-invariant revisions, marks every Team that would have no other active direct User lead as `lead_recovery_required`, and appends the required audit/outbox intent through the WS-02 port. `lead_recovery_required` is an internal operational condition, not a canonical Team lifecycle state or user-configurable ontology. While it is set, the inactive lead grants nothing and every role/profile/hierarchy mutation is frozen except one audited recovery operation by an active acting User with a current Organization `editor` allow and policy allow that adds an active direct User lead. The successful recovery transaction clears the condition only after rechecking principal status, lead cardinality, relationship/group freshness, and the Team fence. If no eligible recovery User exists, the Team remains fail closed pending the separately governed Organization identity-recovery process; there is no Agent, service-account, local-mode, or administrator bypass.

Lead add/remove, User status change, group-backed Organization-editor revocation, and recovery serialize on the affected Team lead-invariant revision. A stale precondition or concurrent fence change restarts under the normal API rule or denies; no transaction may acknowledge a mutation based on an earlier active-lead count.

Team roles do not confer security officer, classification manager, release approver, repository maintainer, Project manager, runner, export, downgrade, or provider-administrator authority. Those remain separate explicit relationships and policy decisions.

### Role bindings and source precedence

`TeamRoleBinding` is a stable internal relationship type, not a new OWGP entity. Its persisted or serialized representation carries an explicit schema version. It records Team ID, subject `PrincipalRef`, role, source kind (`direct` or `directory_group`), source identifier, state, created/updated/revoked metadata, and binding/tuple revisions. WS-02 owns the Team transaction and lifecycle invariants; WS-06 owns subject resolution, provisioning, OpenFGA tuple semantics, and authorization projection. Neither owner writes the other's tables directly.

A principal may receive roles from multiple sources. Permissions are the union of current explicit relations, while the UI's single summary label uses fixed dominance `lead` then `member` then `contributor`. Source-specific bindings remain visible only to authorized roster administrators. Removing one source does not pretend to revoke another current source; the mutation response and audit identify any remaining effective role. Redundant direct lower-role bindings for a direct lead are rejected, while unavoidable direct/group overlap is retained with source provenance.

### Directory Group provisioning

SCIM creates and maintains Directory Groups and their members. A Directory Group affects a Team only after an authorized explicit binding to `member` or `contributor`; provisioning never creates a Team, parent relation, lead, Project role, or Organization-wide grant. The OpenFGA subject is the bounded `directory_group:<id>#member` userset. The group never acts, comments, approves, requests, or appears as the audit actor.

Group-derived access is usable only when the binding and group-membership synchronization revisions are current. Group removal, member removal, suspension, deprovisioning, stale/failed synchronization, or binding revocation advances the deny/consistency fence before the operation is acknowledged. A stale group-derived allow is not served while reconciliation catches up.

### Hierarchy, Project accountability, and classification

`parent` remains context only. No `viewer`, `editor`, role, roster, profile, or management permission is computed from parent or child. Reparenting preserves the Team UUID and every explicit role/direct grant and neither adds nor removes access except where a separately named restrictive classification policy recalculates a container ceiling and denies.

Project `owning_team` and `contributing_team` remain accountability/default-policy-target relationships only, and a Work Item's optional responsible-Team relation is likewise non-authorizing. Neither a Team role itself nor hierarchy, owning-Team, contributing-Team, or responsible-Team context creates Project or Project-scoped Work Item authorization. A Team lead, member, contributor, ancestor, or descendant receives no Project, Project-scoped Work Item/Document, repository, Code, Delivery, search, count, activity, notification, or navigation access merely from those links. Conversely, a Project role does not create a Team role.

Every computed OpenFGA allow remains necessary but insufficient. The deterministic policy layer may restrict it for effective label, compartment, releasability, security domain, session/device/network, explicit deny, group freshness, Agent runtime/task/delegation, or information flow; it may not manufacture an allow without an explicit relationship. Direct repository/provider paths must project only the final authorized permission.

### API and UX behavior

Authorized Team roster representations use canonical role values and show whether a binding is direct or directory-derived only to `roster_viewer`; ordinary Team views expose no hidden roster, group, count, source, or denial reason. Mutation APIs require idempotency and version preconditions and return the resulting binding/tuple revision. Role selection is a fixed accessible control with plain-language descriptions. `contributor` must not be presented as a contributing Team on a Project; the former is a principal-to-Team role, the latter a Team-to-Project accountability relationship.

Team pages, search, hierarchy navigation, rollups, mentions, activity, and notifications are filtered by the same central authorization and classification decision. The UI does not infer permission from a displayed role and does not show role actions a caller cannot execute.

### Contract and ownership boundaries

| Contract | Owner | Permitted responsibility | Prohibited boundary |
|---|---|---|---|
| Team lifecycle and `TeamRoleBinding` transaction | WS-02, `/modules/organization/` | Team identity, lead cardinality/recovery condition, binding version, rename/reparent transaction, and identity-lifecycle coordination port | No local authorization evaluation or direct OpenFGA-store mutation outside the WS-06 port |
| Principal/group resolution, OpenFGA model, role projection and revocation fence | WS-06 | Subject types, usersets, computed permissions, group freshness, tuple migration | No Team hierarchy/accountability inheritance or canonical Team writes |
| Team API schemas | WS-01 contract integration with WS-02/06 approval | Versioned role/binding representations and conditional mutations | No configurable role value or provider group locator as canonical ID |
| Team UI | WS-05 | Accessible fixed labels, source/status display, authorized actions | No client-side authorization or conflation of Team contributor and Project contributing Team |
| Events/audit | WS-07 | Binding, provisioning, reparenting, and decision evidence | No protected roster/group contents in broad event payloads |
| Provider enforcement | WS-03/04/09 as applicable | Apply final scoped repository/docs/runner permission | No provider role as canonical Team role or provider-side policy bypass |

## Consequences

### Security, authorization, classification, and bypass paths

The relation and permission matrix is closed and model-tested. Parent/child, owning/contributing Project, Organization membership, Directory Group existence, assignment, mention, and UI visibility alone grant nothing. Lead is human-only; Agents cannot obtain organizational administration through a human requester. An explicit Agent member/contributor relationship is still insufficient without all required Agent and classification checks. Denied Team/roster/group existence is suppressed across APIs, search, counts, facets, hierarchy, activity, notifications, audit viewers, and provider errors.

### Data model, migration, and backward compatibility

The first implementation adds versioned role-binding storage and OpenFGA relations without creating a first-class Role or Membership resource. Existing direct `viewer` and `editor` tuple semantics remain valid. Existing `member` tuples are not silently reinterpreted under the wider v1 computed permissions: before model activation, every non-test tuple is inventoried and linked to a verified `TeamRoleBinding`; ambiguous or provider-derived experimental tuples are quarantined and deny. The Phase 0 model has no production state, so clean installations seed only v1 bindings.

Exports preserve Team ID, fixed role, canonical subject, source category and canonical source ID where authorized, state, and revisions. They never export provider credentials. Imports validate Organization equality, subject kind, lead cardinality, group binding, and role enum and cannot extend the ontology through source role names.

### Upgrade, rollback, backup, restore, and recovery

Rollout uses a new OpenFGA model/version and expand/verify/activate/contract sequence: add binding storage and relations, inventory legacy tuples, materialize reviewed bindings, run old/new decision comparison and hierarchy/accountability negative suites, activate revision-fenced dual checks, then retire legacy writes. Any new allow unexplained by an approved v1 binding aborts activation.

Before activation, rollback removes v1 projections while retaining binding evidence. After v1 role mutations begin, rollback is allowed only to a model/API version that understands the v1 role relations, `lead_recovery_required`, and revocation revisions; otherwise recovery is forward. A rollback cannot restore removed roles, stale group membership, or a previous parent-derived allow. Backup/restore preserves bindings, OpenFGA model/tuple revisions, group synchronization checkpoints, lead-recovery conditions, revocations, and audit ordering, then verifies each Team's active-User lead invariant or keeps that Team mutation-frozen pending recovery.

### APIs, schemas, events, providers, and standards mappings

OpenFGA gains the fixed relations and computed permissions above. Team APIs gain versioned roster/list/mutate contracts with canonical principal references and opaque provider mappings. SCIM supplies Directory Group membership only through `ProvisioningProvider`; it does not expose SCIM groups as Teams. Events identify actor/requester, Team, canonical subject, fixed role, source category, revision, outcome, correlation, and causation with protected fields omitted. Permission-provider reconciliation consumes final permission decisions, not Team labels.

### Observability, audit, privacy, and evidence

Audit records Team creation, direct/group binding add/remove, role change, lead recovery, last-lead denial, group sync/revocation, rename/reparent, model migration, provider projection, and authorization decision metadata. It includes actor/requester, canonical IDs, before/after hashes or controlled fields, binding/tuple/model/policy revisions, source category, and correlation/causation, but no unnecessary Directory Group roster or protected content. Metrics use low-cardinality role/source/outcome labels and never Team/principal IDs. Reconciliation lag, stale-fence denial, orphan-prevention denial, and provider drift are observable.

### Dependencies, licenses, supply chain, and portability

No new dependency is selected. The decision uses the already locked OpenFGA, PostgreSQL, OIDC/SCIM provider interfaces, deterministic policy layer, and platform API/event stacks. Any library added for SCIM, OpenFGA clients, migrations, or UI controls requires ordinary exact dependency/license/security approval. No proprietary directory, cloud service, or provider-specific Team model is required.

### Documentation and accessibility

User documentation defines lead, member, and contributor in nontechnical language and distinguishes a Team contributor from a Project's contributing Team. Operator documentation covers group binding, stale sync, last-lead identity loss, the non-lifecycle `lead_recovery_required` condition, human-only recovery, migration, and rollback. Role badges and controls include text, status, and source cues; they do not rely only on color, hidden tooltips, or pointer interaction.

## Verification

Decision-record acceptance approves the fixed role/relationship choice and the named verification obligations below; it does not claim that the dependent schema, model, migration, UI, or golden tests already exist or pass. Those tests are mandatory before the affected implementation or release can be approved.

| Test ID | Layer | Required evidence |
|---|---|---|
| `T-ADR-0004-ROLE-ENUM` | schema/API | Only `lead`, `member`, and `contributor` round-trip; arbitrary/custom/provider roles fail. |
| `T-ADR-0004-PERMISSION-MATRIX` | OpenFGA/model mutation | Lead receives viewer/editor plus profile/role management without requiring Organization editor; member receives viewer/editor and contributor viewer only; an explicitly authorized Team-scoped Document may derive Team viewer/editor; Project-scoped Work Items and Documents may not; direct viewer/editor remain explicit; hierarchy/reparent and lead recovery require Organization editor and are denied to lead alone; every Team-management action additionally requires an active acting User; permissive matrix/type mutations fail. |
| `T-ADR-0004-SUBJECT-TYPES` | schema/OpenFGA/security | Lead accepts active User only; member/contributor accept the specified principals/userset; Directory Group cannot act; Agent/service-account Organization editors cannot administer or recover a Team; group-derived acting-User administration requires a current group fence; Agent action without its independent intersection denies. |
| `T-ADR-0004-LEAD-CARDINALITY` | domain/identity/integration/concurrency | Creation is atomic with a lead; concurrent lead removal, User suspension/deprovisioning, group revocation, and recovery serialize on the Team fence. Last-lead role removal denies; external last-lead identity loss wins, records `lead_recovery_required`, freezes mutations, and only an eligible active User recovery clears it with audit. |
| `T-ADR-0004-HIERARCHY-NON-GRANT` | OpenFGA/API/search | Parent, child, ancestor, descendant, and reparent-only fixtures grant no Team/resource/roster/navigation access. |
| `T-ADR-0004-ACCOUNTABILITY-NON-GRANT` | OpenFGA/golden | A Team member with no explicit Project/Work relationship can read an independently authorized Team-scoped Document but cannot infer Project/Work metadata, counts, navigation, or activity; owning/contributing Team and responsible-Team links grant no Project, Work, Project Docs, Code, or Delivery access. |
| `T-ADR-0004-GROUP-PROVISIONING` | SCIM/integration | No auto-Team/lead; only an explicit member/contributor binding grants; stale/failed sync, member removal, group deletion, and binding revocation deny at the current fence. |
| `T-ADR-0004-REVOCATION-AND-SOURCES` | integration/security | Direct/group overlap reports remaining sources; full revoke invalidates caches/provider grants before acknowledgement; no stale allow survives reconciliation. |
| `T-ADR-0004-NONDISCLOSURE` | API/UI/search/audit | Unauthorized callers cannot infer Team, role, roster, group, source, count, hierarchy, or denial reason; authorized UI remains keyboard/screen-reader operable. |
| `T-ADR-0004-MIGRATION-ROLLBACK` | migration/upgrade/backup | Legacy tuple inventory, quarantine, old/new comparison, model migration, backup/restore, pre-activation rollback, and forward recovery produce no unexplained allow or revoked-role resurrection. |

These tests supply evidence for `T-PRIN-015-ACCEPTANCE`, `T-DOM-009-ACCEPTANCE`, `T-AUTH-002-ACCEPTANCE`, `T-AUTH-003-ACCEPTANCE`, `T-AUTH-006-ACCEPTANCE`, `T-CLS-006-ACCEPTANCE`, `T-UX-006-ACCEPTANCE`, `T-UX-007-ACCEPTANCE`, `T-AGENT-003-ACCEPTANCE`, `T-SEC-006-ACCEPTANCE`, `T-TM-F029-CONTROL`, `SEC-BYP-036`, and `SEC-BYP-043`. Golden coverage must include allowed Team Knowledge alongside hidden Project Work absent an explicit Project/Work grant, a software Team/Project, Directory Group membership, direct contribution, a reparent, an owning/contributing Team link, an Agent member with missing runtime/task authority, and positive/negative role revocation. Neither scenario may expose a developer capability or resource solely because of a Team role.

## Rollout and supersession

`STEAD-P1-006`, and the Team-domain/UI work in `STEAD-P1-002` and `STEAD-P1-005`, remain blocked until this ADR receives the required approvals. WS-02 and WS-06 must land schema/model/migration changes together behind the new model revision; WS-05 may implement labels only from the accepted API contract. A future ADR may add a role only with project-owner approval, a public API/model major when required, migration and coexistence behavior, provider/export mappings, accessibility documentation, and the full no-hierarchy/no-accountability/non-disclosure matrix. It may not turn roles into configurable ontology or weaken central authorization/classification.

## Reviews and approvals

Review here approves this decision record at one exact revision. Owned contract changes, consumer reviews, and executable evidence remain separate implementation gates.

| Role | Identity | Disposition | Evidence/date |
|---|---|---|---|
| Contract owner (WS-06 identity/authorization) | pending non-author reviewer | PENDING | Decision-level OpenFGA/provisioning/revocation semantics now; model evidence later |
| Team domain owner (WS-02) | pending non-author reviewer | PENDING | Decision-level binding/cardinality/transaction boundary now; migration/recovery evidence later |
| Architecture and standards (WS-01) | pending non-author reviewer | PENDING | Fixed ontology, public contract, portability, and compatibility review |
| Product/frontend (WS-05) | pending implementation review | PENDING | Role language, progressive disclosure, accessibility, and context before UI merge |
| Independent QA (WS-13) | pending non-author reviewer | PENDING | Decision/test-plan reciprocity now; golden, migration, and reproducibility evidence later |
| Independent security (distinct WS-13 identity) | pending non-author reviewer | PENDING | Decision-level hierarchy/accountability/group/Agent review now; executable bypass/leakage evidence later |
| Project owner | pending | PENDING | Required public Team-role/authorization-contract approval |
