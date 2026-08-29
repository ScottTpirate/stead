# ADR-0002: Security-label algebra and profile identifiers

- **Status:** Proposed for approval
- **Date:** 2026-08-29
- **Decision owners:** WS-06
- **Project-owner approval required:** yes; `SCH-SECURITY-LABEL`, `POL-LABEL-LATTICE`, `POL-LABEL-COMMERCIAL`, and `POL-LABEL-USGOV` require project-owner approval under the contract ownership matrix
- **Requirement IDs:** `DOM-007`, `UX-003`, `AUTH-002`, `AUTH-004`, `AUTH-005`, `AUTH-006`, `CLS-001`, `CLS-002`, `CLS-003`, `CLS-004`, `CLS-005`, `CLS-006`, `CLS-007`, `CLS-008`, `STOR-003`, `TEST-002`, `TEST-003`, `TEST-004`, `TEST-008`, `AGENT-003`, `AGENT-006`
- **Affected contracts/modules/directories:** `SCH-SECURITY-LABEL`, `SCH-DEPLOYMENT-DOMAIN`, `PROFILE-OWGP`, `POL-DECISION-IO-V0.1`, `POL-DECISION-CLASSIFICATION`, `POL-DECISION-FLOW`, `POL-LABEL-LATTICE`, `POL-LABEL-COMMERCIAL`, `POL-LABEL-USGOV`; `/modules/classification/`, `/modules/authorization/`, `/packages/domain-schemas/security/`, `/policies/security-label-profiles/`, `/policies/policy-decision/`, `/policies/deployment-domains/`, `/specs/work-graph-profile/`, `/specs/openapi/`, event/audit contracts, and all protected-resource consumers
- **Resolves:** `ADR-CAND-004` upon acceptance
- **Supersedes / superseded by:** upon acceptance, this project-owner-approved pre-consumer correction supersedes the Phase 0 shorthand in `docs/architecture/security-label-lattice.md` that grouped releasability with union-composed restriction sets; releasability is an allowed-audience coordinate and therefore composes by intersection. An incompatible algebra, identifier, or profile-evolution rule requires a superseding ADR.

## Context and decision scope

The directive fixes the `SecurityLabel` fields, requires a defined least-upper-bound operation over container, explicit, source, and handling labels, and prohibits a derived resource from weakening any source. It also fixes two shipped profiles, treats CUI as handling rather than a classification level, requires signed/versioned policy bundles, denies resources above a deployment ceiling, and denies built-in cross-domain or write-down transfer. `ADR-CAND-004` left the algebra, incomparable-value behavior, profile/value identifiers, commercial vocabulary, and version compatibility open.

The current Phase 0 contracts establish useful seams but do not completely define those choices:

- OWGP `SecurityLabelValue` has the directive fields and an integer `version` but permits arbitrary strings.
- Profile sources have a stable `profile_id`, a separate semantic `version`, a sensitivity order, vocabulary lists, the named join rule, lowering behavior, and a Sigstore-compatible signing requirement.
- Policy input carries an effective label, label revision, and exact `policy_bundle_id`; policy output repeats the bundle ID.
- Deployment-domain profiles carry a ceiling and allowed profile IDs.

The approved Phase 0 architecture summary also described effective labels as a union including “releasability restrictions.” That shorthand is safe only if releasability is encoded as denied-recipient restrictions. The canonical field is instead `releasable_to`, an allowed audience: union would broaden disclosure. This ADR explicitly replaces that sentence with audience intersection before any production label or policy consumer exists. Because the document is project-owner-controlled and the semantic correction affects classification, the replacement is part of this ADR's required project-owner approval rather than a silent editorial interpretation.

This ADR gives those seams one deterministic meaning. It does not select the policy evaluator or topology reserved to `ADR-CAND-003`, trusted-attribute normalization reserved to `ADR-CAND-005`, bundle distribution and trust roots reserved to `ADR-CAND-007`, a cross-domain solution, a configurable ontology, or a compliance/accreditation claim.

The US-government profile must follow authoritative implementing guidance. The [NARA CUI program](https://www.archives.gov/cui/about) defines CUI as unclassified information requiring safeguarding or dissemination controls, while the [NARA CUI Registry](https://www.archives.gov/cui/registry/category-marking-list) is the source for category and marking data. [NIST SP 800-171 Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final) supplies applicable protection requirements for CUI in nonfederal systems. These references do not make Stead accredited or turn a profile token into an official marking without an exact, reviewed mapping.

## Decision drivers

- A derived label must be mathematically deterministic, conservative, and incapable of silently dropping a source restriction.
- Sensitivity, compartments, handling, dissemination, releasability, and export controls do not form one scalar order.
- Unknown, cross-profile, contradictory, or unrepresentable inputs must fail closed.
- Built-in identifiers must remain stable across display-label, policy-bundle, provider, and deployment changes.
- The OWGP label-value `version`, the effective-label consistency revision, profile `version`, and policy-bundle identity must not be conflated.
- The same result must be reproducible in local, Kubernetes, external-service, and air-gapped deployments without a cloud registry.
- CUI categories and controls require authoritative provenance and must remain distinct from national-security classification values.
- Policy evolution and rollback must never reinterpret an existing ID or turn an earlier deny into an accidental allow.

## Considered options

### Option 1 — One total scalar classification order

Map every label to a single rank and take the maximum. This is simple and cheap, with no new dependency, but it cannot safely express incomparable compartments, originator/dissemination rules, audience intersections, legal holds, export controls, or CUI handling. Encoding those dimensions into ever-larger scalar names would create a configurable ontology and still make composition opaque. Rejected.

### Option 2 — Product partial order with profile-defined normalization and compatibility rules

Use an ordered sensitivity coordinate, monotone restriction sets, a reverse-ordered permitted-audience coordinate, and signed profile rules for implication, incompatibility, and representability. Join takes the maximum sensitivity, conservative unions, and audience intersection, then validates the result. This is deterministic, implementation-neutral, offline-capable, and directly matches the directive. It requires property tests and explicit handling of unrepresentable combinations. Accepted.

### Option 3 — Treat all arrays as unordered unions

This extends the existing Phase 0 prose literally, but union is unsafe for `releasable_to`: adding audiences would broaden disclosure rather than restrict it. It also cannot resolve implied controls or contradictions such as mutually exclusive handling modes. Rejected.

### Option 4 — Store arbitrary policy expressions on each resource

Attach a Cedar/Rego/custom expression or tenant-defined rule graph to each label. This can model complex restrictions, but it leaks evaluator choice into the canonical contract, introduces unbounded policy languages and dependencies, weakens portability, and creates configurable ontology. Rejected.

### Dependency, license, and reversibility comparison

All four options can be represented without a new runtime dependency. The accepted option is implementable in the standard Go and TypeScript stacks and remains independent of OPA/Rego. Its data representation is durable, so identifier or order changes are not casually reversible; the explicit version, migration, and supersession rules below are therefore mandatory.

## Decision

### 1. Policy identity and normalization boundary

Every comparison or join occurs under one exact, verified policy bundle `B`. The bundle binds:

- one `profile_id` and its semantic profile version;
- the sensitivity order;
- stable vocabulary and scoped-identifier namespaces;
- implication, dominance, incompatibility, and representability rules;
- releasability audience containment/intersection rules;
- category/subcategory and external-registry mappings;
- lowering/two-person requirements; and
- the policy rules that consume the label.

The evaluator first normalizes a label against `B`. An unknown profile, unknown or deprecated-without-alias value, invalid qualified ID, unverifiable bundle, incompatible bundle/profile version, or unresolved external mapping has no permissive interpretation. Normalization fails and the protected operation denies. A migration tool may retain the source record in its existing protected quarantine flow, but no normal resource, search result, event, notification, export, or provider grant may expose it.

`SecurityLabelValue.version` remains the positive integer revision of the explicit label value. On a first-class `SecurityLabel` resource, it is the same field as the common resource-envelope `version`: one atomic mutation counter, not two independently moving revisions. It is not the profile version.

The policy input's opaque string `resource.label_revision` is the consistency-fence revision of the **effective** label used for that decision. It binds the explicit label revision plus every contributing container/source label and derivation generation. It therefore changes when the effective result changes even if the explicit label value's integer `version` does not. Its representation is internal and must not be parsed by consumers.

The profile document's `version` is semantic versioning for the profile. `policy_bundle_id` identifies the exact signed bundle used for normalization and decision replay. Implementations MUST preserve these four meanings in storage, consistency fences, audit, and migration evidence; they may correlate them but may not substitute one for another.

### 2. Stable identifier rules

Identifiers are semantic keys, not display labels:

- `profile_id` uses the canonical lowercase token grammar `[a-z][a-z0-9_]{0,63}`. The initial IDs are exactly `commercial` and `us_government`.
- Profile vocabulary definition IDs are case-sensitive ASCII tokens matching `[A-Za-z][A-Za-z0-9_]{0,127}`. Their case and spelling are immutable.
- A category value is either `<category_id>` or the qualified `<category_id>/<subcategory_id>`. A bare subcategory is invalid.
- A concrete compartment or other instance-valued restriction uses `<namespace_id>:<stable_instance_id>`. Display names, Team names, Project keys, provider IDs, and mutable paths are not stable instance IDs. The signed profile declares the allowed namespace and trusted registry; a UUIDv7 is preferred for locally issued instances.
- `releasable_to`, originator, and authority values use signed-profile registry IDs or canonical Stead resource URIs where the referenced authority is a Stead resource. They never use an unverified display string.
- Arrays are semantic sets: duplicates are invalid, input order has no meaning, and canonical output sorts by Unicode code point after normalization.

An ID is never reused or redefined. Removal reserves the ID permanently. A compatibility alias may map an old ID to a canonical ID only when the two are decision-equivalent for every applicable operation; the alias and proof are signed, versioned, tested, and audited. Presentation labels and official marking text are separate localized metadata and may change without changing the ID.

### 3. Formal label value

For algebra, a normalized label is:

```text
L = (p, s, H, C, K, D, R, E)
```

where:

- `p` is the compatible profile line;
- `s` is one member of the profile's ordered `sensitivity_order`;
- `H` is the normalized handling-regime restriction set;
- `C` is the normalized category/subcategory restriction set;
- `K` is the normalized concrete compartment/program restriction set;
- `D` is the normalized dissemination-control restriction set;
- `R` is the semantic set of permitted releasability audiences; and
- `E` is the normalized export-control restriction set.

`derivation_sources`, `originator`, `classification_authority`, `declassification_or_review_instructions`, and the integer label `version` are mandatory provenance/workflow inputs where applicable, but they are not order coordinates. Excluding them from the order does not permit their loss:

- `derivation_sources` is the identity-deduplicated union of all contributing protected sources;
- an automatically derived label may copy `originator`, `classification_authority`, or review instructions only when the applicable values are identical or one is absent under a profile rule that explicitly preserves the other;
- conflicting non-empty authority or review instructions make automatic derivation unrepresentable and require an authorized classification workflow; and
- that workflow may preserve or add restrictions, but it may not use metadata resolution to lower any algebra coordinate.

Within one compatible profile line, define `L1 ⊑_B L2` to mean that `L2` is at least as restrictive as `L1`. It holds exactly when:

```text
rank_B(s1) <= rank_B(s2)
H1 ⊆ H2
C1 ⊆ C2
K1 ⊆ K2
D1 ⊆ D2
audience_B(R2) ⊆ audience_B(R1)
E1 ⊆ E2
```

after profile implication and dominance normalization. The sensitivity coordinate is totally ordered for each shipped profile. The product is a partial order because compartments, controls, and audiences may be incomparable. Labels from different profile lines are incomparable unless a separately signed, versioned, non-weakening bridge maps both to one target profile. No such bridge ships in the initial release.

An empty `handling_regimes`, `categories`, `compartments`, `dissemination_controls`, or `export_controls` set means that dimension adds no restriction. An empty `releasable_to` means **no profile-specific audience restriction**, not “release to nobody.” It is the universal audience only for the releasability coordinate; OpenFGA, organization policy, security-domain policy, and all other authorization checks still apply.

### 4. Join and incomparable composition

For comparable profile inputs, the least upper bound is:

```text
join_B(L1...Ln) = normalize_B(
  p,
  max_B(s1...sn),
  union(H1...Hn),
  union(C1...Cn),
  union(K1...Kn),
  union(D1...Dn),
  intersection_B(R1...Rn),
  union(E1...En)
)
```

Profile normalization collapses an implication or dominated value only when the signed profile proves that the retained representation preserves every effect. `CUI_BASIC` and `CUI_SPECIFIED` are not globally ordered: category-specific Specified controls may differ, while Basic controls continue to apply where the governing authority does not specify a control. A join therefore retains and evaluates every applicable Basic and Specified obligation from the signed category mapping. The signed profile also validates combinations among handling, categories, dissemination, releasability, and export controls.

The join is defined only when the normalized result is representable. It is unrepresentable when, at minimum:

- inputs use different profile lines and no approved bridge exists;
- an input identifier or external mapping is unknown or unverifiable;
- audience intersection is empty;
- dissemination and releasability rules conflict;
- handling regimes/categories are mutually incompatible;
- originator, authority, or review metadata cannot be preserved by the automatic rule.

“Incomparable” never means “choose either.” An unrepresentable join fails the mutation atomically or enters an explicitly protected migration quarantine; it does not emit a partly labeled resource. Reads and downstream projections fail closed until resolution. No implementation may drop a compartment/control, broaden `releasable_to`, choose the lower sensitivity, or substitute a default profile to force a result.

A mathematically representable join may still be inadmissible to a particular container or deployment domain. Ceiling and provider-enforcement checks deny that placement without changing the join result or coercing it to a lower label.

The implementation MUST prove reflexivity, antisymmetry, and transitivity of `⊑_B`; commutativity, associativity, and idempotence of every defined join; that every result is an upper bound; and that no strictly lower upper bound exists. Property tests must include unrepresentable results rather than filtering them out.

### 5. Effective labels, containers, and ceilings

The effective label is the defined join of:

1. the Project/security-container default label;
2. the explicit resource label;
3. every source/derived-from label; and
4. applicable handling rules from the exact policy bundle.

A resource label may add display, export, retention, or handling obligations, but it cannot grant finer read access than its cloneable/provider container enforces. If the effective label requires different access, compartment, releasability, retention, or lifecycle enforcement, the resource moves to a separate authorized security container. A move or copy is itself a classified data-flow operation and re-evaluates the join and destination policy.

A deployment domain accepts a label only when the profile is allowed, the exact bundle is verified, sensitivity does not exceed the profile-compatible ceiling, all container/provider paths can enforce the result, and every policy-decision check allows. A ceiling string from another profile has no implicit mapping and denies. Raising a label is an authorized, audited mutation that commits the new label/policy fence before projections or provider grants can serve it.

Lowering sensitivity, removing a handling regime/category/compartment/control/export restriction, or broadening `releasable_to` is a lowering operation. It never occurs through ordinary join, migration, profile upgrade, or rollback. It is denied by default and requires the directive-mandated authority, source authority, written reason, audit, invalidation/reconciliation, and two distinct eligible approvers when the active profile requires two-person lowering. Approval contracts remain principal-typed and do not assume that every reviewer is human; the initial `us_government` policy nevertheless requires two independently authenticated `user` principals unless a later approved profile and accreditation policy explicitly permits another acting-principal type. One principal acting through two identities or an Agent delegated by the first approver does not satisfy separation of duty.

Core Stead provides no cross-domain or write-down allow. A higher-to-lower destination, incompatible profile/domain, or unverifiable destination denies even when a proposed lower label is supplied. An external accredited process may consume a separately authorized, audited interface in a later approved scope; this ADR creates no such route.

### 6. Initial profile vocabularies

The initial commercial profile has the following canonical v1 vocabulary:

| Dimension | Stable values / order |
|---|---|
| `profile_id` | `commercial` |
| sensitivity, low to high | `public`, `internal`, `confidential`, `restricted` |
| handling regimes | `privacy`, `legal_hold`, `export_control` |
| category/subcategory roots | `privacy/{personal_data,health_data,employee_data}`, `legal/{privileged,legal_hold}`, `financial/{material_nonpublic_information,payment_data}` |
| compartment namespaces | `need_to_know`, `deal_team`, `investigation` |
| dissemination controls | `no_external_share`, `named_recipients_only` |
| releasability groups | `employees`, `approved_contractors`, `named_partners` |
| export controls | `EAR`, `ITAR` |

These are fixed policy vocabulary, not user-created fields or product ontology. A named compartment, recipient group, or partner is an authorized registry instance under the declared namespace, not a new vocabulary definition.

The initial government profile preserves these current v1 identifiers:

| Dimension | Stable values / order |
|---|---|
| `profile_id` | `us_government` |
| sensitivity, low to high | `UNCLASSIFIED`, `CONFIDENTIAL`, `SECRET`, `TOP_SECRET` |
| handling regimes | `CUI_BASIC`, `CUI_SPECIFIED`, `export_control` |
| category roots | `CUI_CRITICAL_INFRASTRUCTURE`, `CUI_DEFENSE`, `CUI_EXPORT_CONTROL`, `CUI_PRIVACY`, `CUI_PROCUREMENT` and their checked-in subcategory IDs |
| compartment namespaces | `program`, `mission`, `contract`, `special_access_boundary` |
| dissemination controls | `NOFORN`, `FEDCON`, `FEDONLY`, `NOCON`, `DL_ONLY` |
| releasability groups | `USA`, `FVEY`, `named_foreign_governments` |
| export controls | `EAR`, `ITAR` |

`CUI_BASIC` and `CUI_SPECIFIED` are handling regimes, never sensitivity values. A label using either must have `UNCLASSIFIED` sensitivity, at least one exact category/subcategory mapping to the reviewed NARA registry snapshot, and the applicable authority/handling metadata. A CUI category may be Basic or Specified according to its governing authority; the profile cannot infer that status from the category display name. Neither regime globally dominates the other. Composition preserves the union of applicable category-specific controls and applies Basic requirements wherever the governing authority does not supply a different Specified control. A classified label may carry other applicable handling/export restrictions, but it cannot be labeled CUI.

The checked-in `CUI_*` grouping IDs are Stead profile IDs, not official banner markings. User-visible government markings must be generated only from exact external-registry mappings and agency policy in the signed bundle. Missing, stale, or ambiguous mappings deny the affected operation and block any government-readiness claim.

### 7. Profile and schema compatibility

`profile_id` identifies one semantic major line. Profile `version` uses `MAJOR.MINOR.PATCH`:

- a patch is decision-equivalent for every previously valid label and may correct prose, provenance, or implementation metadata only;
- a minor may add new IDs and rules that apply only to those new IDs, but cannot change the order, implication, compatibility, audience, or decision meaning of an existing ID;
- a change that removes/redefines an ID, reorders sensitivity, changes an existing combination from allow/representable to a weaker result, changes empty-set semantics, or changes the algebra is breaking.

Because the current label value does not embed a profile semantic version, a breaking profile change MUST use a new `profile_id`, coexist with the old profile, and migrate labels explicitly. It MUST NOT publish a new major under `commercial` or `us_government` and reinterpret stored labels. A future representation may add an explicit profile-version field only through the API/schema-major and coexistence process in ADR-0001.

Every decision and derived-label record binds the effective `label_revision` to the exact `policy_bundle_id`; that bundle in turn binds the profile version and content digest. Decision consistency fences include the effective-label and policy-bundle revisions. ADR-0005 selects no authorization-decision cache for v1; any future cache approved by a superseding ADR must include the same revisions. Semantic replay uses the recorded bundle, not whichever profile is currently active.

Profile parsers may accept a compatible successor minor, but writers emit only the active approved version. An older evaluator encountering a new identifier denies rather than ignoring it. A serializer never silently rewrites aliases, case, or deprecated IDs in persisted history; an explicit migration may canonicalize them with provenance and audit.

## Consequences

### Security, authorization, classification, and bypass paths

The algebra can only preserve or increase restrictions; it never supplies authority. OpenFGA relationship/need-to-know allow, deterministic policy allow, provider-path enforcement, and absence of explicit deny remain jointly mandatory. Administrator, classification-manager, Project owner, Team hierarchy, assignment, and possession of a label or URI confer no content bypass.

Unknown profiles/values, failed signatures, stale bundles, incomparable profiles, contradictory controls, empty audience intersections, missing trusted attributes, ceiling mismatches, and stale consistency fences deny. The same effective label and bundle fence applies to API/UI, Git/provider paths, search/counts/facets, activity, navigation, notifications, events, caches, objects, runners, backups, exports, and audit views. Non-disclosure errors reveal no protected label, title, identifier, category, compartment, or existence.

For an Agent, the label result is one term in the required intersection of delegator, Agent, task, runtime-domain, session/environment, and resource handling authority. An Agent's assignment, model provider, tool scope, or delegating human cannot override the label or ceiling.

### Data model, migration, and backward compatibility

The current OWGP field set remains sufficient; this ADR defines the explicit-label integer `version` and its relationship to the separate effective-label consistency token `label_revision`. Contract implementation must constrain identifiers, document qualified category/scoped-instance forms, and add profile-level implication, dominance, incompatibility, releasability-intersection, external-mapping, alias/deprecation, and compatibility metadata. Acceptance also updates `docs/architecture/security-label-lattice.md` so its normative summary distinguishes union-composed restrictions from intersection-composed allowed audiences. These additions are made in the owned policy/profile contracts after this ADR is accepted; this ADR does not authorize an unversioned in-place breaking schema edit.

Migration inventory records each label's explicit integer version, effective `label_revision`, source/container label versions, profile ID, exact source/target profile version and bundle ID/digest, normalized values, aliases, unknowns, and resulting disposition. Existing `commercial` and `us_government` labels validate against the signed v1 vocabulary. Ambiguous strings, unknown values, invalid CUI mappings, mixed profiles, and unprovable bundle provenance fail closed and enter the existing protected migration quarantine rather than receiving defaults.

After validation, migration canonicalizes set order, preserves stable IDs and derivation sources, recomputes every effective label, and invalidates/rebuilds provider grants, search, graph, activity, notifications, caches, attachments, exports, and other projections. It never lowers a label. A breaking profile migration uses a new profile ID, explicit mapping and provenance, coexistence, and the ordinary lowering workflow wherever any coordinate would become less restrictive.

### Upgrade, rollback, backup, restore, and recovery

Profile rollout is expand/verify/activate/reconcile/contract:

1. install the new signed bundle without activating it;
2. verify signature/trust, schema, IDs, algebra properties, compatibility, decision tables, migration, and full dry-run joins;
3. reject activation on any unknown, weaker, contradictory, unrepresentable, ceiling, or non-disclosure result;
4. atomically activate a new bundle revision and authorization consistency fence;
5. recompute labels and block affected projections/provider paths until they reach the fence; and
6. retire an old compatible bundle only after replay, backup/restore, and rollback evidence pass.

Rollback may reactivate only a previously approved signed bundle that can interpret every active label without weakening it. If labels use a newer identifier unknown to that bundle, the older binary/bundle denies those labels; it does not ignore the value. Once new IDs are written, forward recovery or continued bundle coexistence is preferred. Rollback never restores a stale allow, broadens an audience, removes a restriction, or undoes an audited lowering decision.

Backups preserve labels, derivation sources, classification workflow records, profile bundles and digests, trust evidence, bundle activation history, consistency revisions, aliases, external-registry provenance, and audit records. Restore verifies them before serving protected reads and rebuilds all derived projections from authoritative state.

### APIs, schemas, events, providers, and standards mappings

The following follow-up contract changes are required after acceptance:

| Contract | Required effect | Owner and required review |
|---|---|---|
| `SCH-SECURITY-LABEL` and `/packages/domain-schemas/security/security-label/` | Mirror the OWGP field set; constrain stable IDs; define label-revision semantics, normalization, qualified categories, scoped restrictions, and fail-closed validation | WS-06; WS-01 and all container owners review; WS-13 and project owner approve |
| `PROFILE-OWGP` and `/specs/work-graph-profile/` | Clarify embedded/effective label serialization and preserve provider-independent resource/provenance references without changing ontology | WS-01; all domains review; WS-06, WS-13, and project owner approve |
| `POL-LABEL-LATTICE` | Encode the partial order, join, representability, container/ceiling, raise/lower, and property/mutation fixtures | WS-06; all container owners review; WS-01, WS-13, and project owner approve |
| `POL-LABEL-COMMERCIAL` | Encode the exact commercial v1 vocabulary, stable registry namespaces, display mappings, compatibility rules, and signed-version metadata | WS-06; WS-01 reviews; WS-13 and project owner approve |
| `POL-LABEL-USGOV` | Encode government v1 vocabulary, exact NARA mapping provenance, CUI Basic/Specified rules, no-certification statement, and profile tests | WS-06; WS-12 and WS-13 review; WS-01 and project owner approve |
| `POL-DECISION-IO-V0.1`, classification, and data-flow policy | Bind decisions to bundle/label revisions; add safe reasons for invalid profile, unrepresentable join, ceiling, lowering, and cross-domain denial without selecting an evaluator | WS-06; affected policy-input owners review; WS-01, WS-13, and project owner approve |
| `SCH-DEPLOYMENT-DOMAIN` | Validate allowed profile IDs and profile-compatible ceilings against the exact activated bundle | WS-06; WS-12 and WS-01 review; WS-13 and project owner approve |
| OpenAPI, events, audit, search, provider, export, and migration contracts | Consume the shared effective-label result and bundle fence; do not reimplement algebra or expose protected metadata | Existing sole contract owner; WS-06 security review and WS-13 approval where required |

JSON Schema remains 2020-12, APIs remain provider-neutral, and the policy-decision interface remains implementation-neutral. CUI mappings may cite NARA registry identifiers and authoritative source metadata, but those mappings are profile data rather than new universal ontology.

### Observability, audit, privacy, and evidence

Every label create/change/join/raise/lower, profile activation, failed normalization, ceiling denial, compatibility migration, and external-mapping update records:

- acting and requesting principal plus delegation/task context when present;
- resource/container reference, label revision, source-label revisions, and derivation references;
- profile ID/version, policy-bundle ID/digest, and trust-verification result;
- normalized join outcome or safe failure reason;
- authority, written reason, and distinct approvers for lowering;
- correlation/causation and consistency-fence revisions; and
- reconciliation/invalidation outcome.

Audit and evidence omit protected content and minimize category, compartment, audience, and originator values. Ordinary logs and traces never contain full labels. Metrics may report coarse approved outcomes such as join success, unrepresentable, unknown profile, signature failure, ceiling denial, or reconciliation lag, but must not use resource IDs, category IDs, compartments, audiences, or label values as dimensions where counts could disclose protected activity.

Required operational signals include profile verification/activation failure, unknown-value denial, join failure rate, label-recompute backlog, stale-fence denial, provider/search/cache reconciliation lag, and rollback incompatibility. Alerts and dashboards remain authorization- and classification-filtered.

### Dependencies, licenses, supply chain, and portability

This ADR selects no evaluator, runtime library, SaaS registry, model provider, or cloud service. Algebra, normalization, and stable-ID validation are implementable with approved standard-library facilities. Any new parser, policy engine, signature library, registry snapshot, or generated data package requires exact version/digest, provenance, license, vulnerability, air-gap, SBOM, notice, and independent approval through the existing dependency workflow.

The profile contract retains its signed, versioned, offline-verifiable bundle requirement. The Phase 0 `bundle_signing.format: sigstore-bundle` value was a non-materialized placeholder while `ADR-CAND-007` remained open; accepted ADR-0006 replaces it with the Stead Policy Activation Set v1 DSSE profile and records the compatibility change before any production consumer exists. This label ADR does not select or alter that envelope. No network lookup is permitted during an authorization decision. External CUI registry material is imported only as an exact, provenance-recorded, reviewable snapshot; availability of that material does not itself authorize a government-readiness or compliance claim.

### Documentation and accessibility

Contributor documentation must explain the algebra, identifier grammar, profile/version/bundle distinction, canonical serialization, failure modes, and ownership. Operator documentation must cover profile installation, signature verification, ceiling configuration, dry-run upgrade, reconciliation, rollback, backup/restore, external-registry update, and incident response. Security documentation must map every classification bypass path and make the no-cross-domain boundary explicit.

User documentation and accessible UI markings use reviewed display labels rather than exposing opaque IDs alone. Banners, export/print markings, warnings, and screen-reader text remain calm but unmistakable under `UX-003`; color is never the sole signal. The US profile documentation must distinguish Stead internal IDs from official CUI markings and state that configuration is not accreditation, authorization to operate, or FIPS validation.

## Verification

Decision-record acceptance approves the algebra/profile choice and the named verification obligations below; it does not claim that the dependent implementation tests already exist or pass. The affected contract implementation, activation, and release must supply all existing mapped tests plus these exact ADR tests:

- `T-ADR-0002-ID-VERSION`: validates profile/value/qualified/scoped ID grammar, case sensitivity, immutable/deprecated IDs, set canonicalization, and the distinct meanings of explicit-label integer `version`, effective-label string `label_revision`, profile semantic `version`, and `policy_bundle_id`; it also proves that a first-class Security Label has one atomic resource/label mutation counter and that effective-label source changes advance `label_revision` without pretending to mutate the explicit label. Unknown, reused, redefined, or ambiguous IDs fail.
- `T-ADR-0002-PARTIAL-ORDER`: property-tests reflexivity, antisymmetry, and transitivity; proves shipped sensitivity orders and restriction/audience directions; cross-profile and unresolved values are incomparable rather than permissive.
- `T-ADR-0002-JOIN`: property-tests defined joins for commutativity, associativity, idempotence, upper-bound, leastness, deterministic replay, source union, sensitivity maximum, restriction union, audience intersection, and container/source/explicit/handling composition.
- `T-ADR-0002-INCOMPARABLE`: negative fixtures cover cross-profile inputs, empty audience intersection, unknown compartments/categories, conflicting dissemination/releasability, incompatible handling, conflicting authority/review metadata, invalid external mappings, and attempts to default/drop a restriction; every case fails closed without a partially visible resource.
- `T-ADR-0002-CUI-PROFILE`: proves exact US sensitivity values; CUI never appears as a sensitivity; Basic/Specified validation, non-dominance, and category-specific control preservation; required category/authority mapping; invalid classified-plus-CUI combinations; official-marking provenance; and no compliance/accreditation/FIPS claim.
- `T-ADR-0002-CONTAINER-CEILING-FLOW`: proves per-item labels cannot exceed provider/container enforcement, different access creates a separate container, unknown/incompatible ceilings deny, label raises fence every projection/path, lower runners/runtimes deny, and all core cross-domain/write-down paths deny.
- `T-ADR-0002-LOWERING`: proves every less-restrictive coordinate change is detected; authority/source/reason/audit/invalidation are mandatory; the generic contract remains principal-typed; the initial government profile requires two distinct eligible `user` approvers; and assignment, administration, self-approval, or delegated Agent identity cannot bypass separation of duty.
- `T-ADR-0002-COMPAT-MIGRATION`: proves compatible patch/minor behavior, breaking-new-profile-ID coexistence, alias equivalence, deterministic inventory/normalization, unknown-value quarantine, no-lowering migration, recomputation, backup/restore, safe old-bundle denial, and forward recovery.
- `T-ADR-0002-BUNDLE-AUDIT`: proves missing/invalid/stale/unapproved bundles deny; decisions bind exact profile/bundle/label revisions; audit has dual principal/correlation context; telemetry contains no full labels or protected high-cardinality values; and air-gapped verification performs no network lookup.

These ADR tests supplement, rather than replace, `T-DOM-007-ACCEPTANCE`, `T-AUTH-002-ACCEPTANCE`, `T-AUTH-004-ACCEPTANCE`, `T-AUTH-005-ACCEPTANCE`, `T-AUTH-006-ACCEPTANCE`, `T-CLS-001-ACCEPTANCE` through `T-CLS-008-ACCEPTANCE`, `T-TEST-002-ACCEPTANCE`, `T-TEST-003-ACCEPTANCE`, `T-TEST-004-ACCEPTANCE`, `T-TEST-008-ACCEPTANCE`, `T-AGENT-003-ACCEPTANCE`, and `T-AGENT-006-ACCEPTANCE`.

Authorization/classification implementation must reach 100% decision-row/policy-rule coverage and at least 90% mutation score for critical policies. Required mutations include reversing sensitivity order, replacing audience intersection with union, dropping each restriction dimension, treating unknown as empty, allowing a ceiling mismatch, weakening CUI Specified to Basic, bypassing the second approver, accepting an invalid bundle, and permitting a cross-domain result.

Golden-scenario evidence must include an ordinary commercial general-work Project, protected derived Work/Docs content, a label raise propagated across every projection/path, an Agent-context denial at the label intersection, direct-provider denial, restore/replay under the same bundle, and the mandatory cross-domain denial. Government-profile fixtures remain synthetic and do not create a readiness claim.

## Rollout and supersession

`ADR-CAND-004` remains blocking for `STEAD-P1-006` until this ADR is accepted and the candidate/index/issue/traceability references are updated by their owners. After acceptance, implementation proceeds in dependency order:

1. corrected security-label architecture summary, profile schema, and stable vocabularies;
2. lattice/normalization/property fixtures;
3. OWGP and security-label schema clarifications;
4. policy-decision and deployment-domain bindings;
5. classification module persistence and effective-label service;
6. API/event/audit/provider/projection consumers; and
7. migration, upgrade, backup/restore, golden, and independent bypass evidence.

No consumer may implement a private label comparison or join while the shared contract is unavailable. Any rollout aborts on a weakening result, unrepresentable active label, unknown ID, failed signature, replay difference, leakage, failed invalidation, or missing audit evidence.

A future ADR may supersede this decision only with a formal compatibility mapping, proof that no source restriction is weakened, schema/profile coexistence, migration and rollback plans, full property/mutation/classification evidence, WS-06 contract-owner approval, WS-01 architecture approval, independent WS-13 QA and security approvals, and project-owner approval. A change that enables cross-domain transfer, configurable ontology, an alternate authorization path, or removal of the deterministic policy boundary also changes locked architecture and requires explicit project-owner authorization beyond ordinary ADR acceptance.

## Reviews and approvals

This proposed ADR does not unblock implementation merely by existing in the repository. Decision-record approval applies to one immutable revision containing this exact choice, ownership, compatibility plan, and named test obligations. It authorizes the subsequent owned contract/test work but does not assert that its executable evidence already exists. The implementation author cannot provide an independent approval or approve a waiver for their own work.

| Role | Identity | Disposition | Evidence/date |
|---|---|---|---|
| Contract owner (WS-06) | pending independently identified reviewer | PENDING | Decision semantics and owned-contract boundary now; executable algebra/profile evidence gates implementation activation |
| Architecture and standards (WS-01) | pending independently identified reviewer | PENDING | Compatibility, ontology, ownership, and implementation-neutrality review required |
| Container/consumer reviewers (WS-04/08/09/10/12 and affected owners) | pending implementation review | PENDING | Required before each affected consumer implementation merges |
| Independent QA (WS-13) | pending distinct reviewer | PENDING | Decision/test-plan reciprocity now; reproducible schema/property/migration/golden evidence before implementation approval |
| Independent security (WS-13) | pending reviewer distinct from QA and implementation | PENDING | Decision-level classification and bypass review now; executable mutation/non-disclosure/direct-path/cross-domain evidence later |
| Project owner | pending | PENDING | Explicit approval required by the contract ownership matrix |
