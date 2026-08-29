# ADR-0001: Canonical URI and compatibility profile

- **Status:** Accepted
- **Date:** 2026-08-29
- **Decision owners:** WS-01
- **Project-owner approval required:** no; this selects a deferred implementation detail within the locked UUIDv7, provider-neutrality, portability, and compatibility boundaries
- **Requirement IDs:** `PRIN-002`, `PRIN-004`, `ARCH-005`, `STD-001`, `STD-002`, `DOM-001`, `EVT-003`, `MIG-003`, `MIG-005`, `TEST-001`, `TEST-002`, `TEST-005`
- **Affected contracts/modules/directories:** `/specs/work-graph-profile/`, `/specs/openapi/`, canonical resource persistence and lookup, events, search/graph projections, migration redirects, exports, and browser routing
- **Resolves:** `ADR-CAND-001`
- **Supersedes / superseded by:** none; a future incompatible identity grammar requires a superseding ADR and coexistence/migration plan

## Context and decision scope

Stead requires a provider- and host-independent identifier that survives rename, hierarchy change, provider replacement, path movement, and configured-origin changes. A human-facing link must remain dereferenceable without making its current host or route part of resource identity. The decision also has to make instance and Organization tenancy explicit, preserve the fixed OWGP ontology, and align API, schema, and event compatibility.

This ADR selects only the canonical identity and compatibility profile. It does not change authorization, add ontology, select persistence technology, define migration collision precedence reserved to `ADR-CAND-016`, or make a provider URL canonical.

## Decision drivers

- Stable identity through provider, hostname, route, display-key, and hierarchy changes
- Explicit instance and Organization scoping without using a mutable name
- Simple parsing and validation in offline, air-gapped, and multi-provider deployments
- Non-disclosing browser resolution through the normal authorization path
- One compatibility vocabulary across OWGP, HTTP APIs, events, exports, and migration
- No new runtime dependency, registry service, proprietary identifier, or license obligation

## Considered options

1. **Use the browser HTTPS URL as canonical identity.** Simple to dereference, but hostname, route, reverse-proxy, and deployment changes would mutate identity and make export/import host-dependent. Rejected.
2. **Use a registered `urn:uuid:<uuid>` identity with explicit scope-envelope fields.** Provider-independent, standardized, offline-validatable, and separates globally unique identity from authorization-sensitive tenancy and kind metadata. Accepted.
3. **Use a DID or externally registered HTTP namespace.** Extensible, but adds resolution, method, dependency, governance, and offline-operability costs that Stead does not need. Rejected.
4. **Use an unregistered product-specific Stead URN namespace.** The shape is compact, but the product name is not a registered URN namespace; treating it as globally interoperable would create standards ambiguity and a later registration or identity-migration burden. Rejected.

All options can be implemented without a third-party library. The accepted option is the least operationally coupled and is reversible only through an explicit identity migration, so it is fixed before persisted Phase 1 resources.

## Decision

### Canonical URI grammar

Every canonical resource has a lowercase URI with this grammar:

```abnf
canonical-uri = "urn:uuid:" uuidv7
```

In expanded form:

```text
urn:uuid:<resource_uuid>
```

The UUID uses the canonical lowercase UUIDv7 representation and MUST be globally unique across Stead instances. For an OWGP resource, the URN UUID MUST equal the resource `id`. The URI contains no instance, Organization, kind, alias, display label, provider name, path, fragment, query, or API/schema/event version. Identity is immutable; scope and kind are mandatory, separately validated envelope metadata rather than claims inferred from the URN.

Every complete resource envelope MUST carry `instance_id`, `scope_kind`, `scope_id`, `organization_id`, and `kind`, in addition to `id` and `uri`. The stable `instance_id` is generated once for an installation and restored with authoritative instance state. Scope rules are:

- the Instance resource uses `id=instance_id`, `scope_kind=instance`, and `scope_id=instance_id`;
- an Organization resource uses `scope_kind=instance`, `scope_id=instance_id`, and `organization_id=id`;
- every other Organization-owned resource uses `scope_kind=organization` and a `scope_id` equal to its canonical `organization_id`;
- an Organization UUID or instance UUID is never inferred from a display key, hostname, provider tenant, repository owner, or route.

Validation MUST compare the envelope `instance_id` with trusted configured instance state, then enforce the kind-specific scope rules. A `ResourceRef` carries `kind`, `id`, and `uri` (and optionally `browser_url`); its URN UUID MUST equal `id`, and any browser URL MUST agree with both `kind` and `id`. Nested references receive the same agreement checks as top-level resources.

`service_principal` remains the OWGP resource kind; `service_account` remains the acting-principal discriminator. `person` is a presentation of `user`, so Person search results use the canonical user's `urn:uuid` identity. Bounded projection kinds such as `code_file` and `code_symbol` may be URI-addressable by the search contract without becoming authoritative OWGP entities; their projection UUIDv7 identifiers remain globally unique, their records remain rebuildable, and their kind registry is not tenant-configurable.

### Browser URL and dereference behavior

The canonical browser locator is separate:

```text
https://<configured-origin>/r/<kind>/<uuid>
```

It is returned as `browser_url`. The server MUST derive it from the exact configured trusted origin plus the validated envelope `kind` and `id`; it MUST NOT accept or preserve a client-, import-, provider-, forwarded-host-, or request-host-derived value. The configured origin MUST be one canonically serialized HTTPS origin with no userinfo, path, query, or fragment. A browser URL with userinfo, a foreign authority, a mismatched kind/UUID, query, or fragment is invalid even when its route otherwise looks canonical. A configured-origin change regenerates `browser_url` but never changes `id` or `uri`. Compact `ResourceRef` values MAY omit `browser_url`; complete resource envelopes and public resource/search representations MUST include the server-derived value.

The `/r/` handler resolves the UUID through canonical state and then performs the same authentication, OpenFGA, policy-decision, classification, capability, and provider-path checks as any other read. It MUST NOT redirect, vary status/body materially, or disclose a title, kind, tenant, alias target, or existence before authorization. A URI parser is not an authorization decision and MUST NOT select a tenant connection solely from untrusted URI text.

Provider and historical source URLs remain namespaced external references or migration aliases. They never replace `uri` or `browser_url`.

### Aliases and redirects

Rename, Team reparenting within one Organization, Project ownership or container movement within one Organization, document path/container movement within one Organization, repository-provider migration, and configured-origin change do not change the canonical UUID or URI. A resource cannot be moved in place across Organizations. An authorized cross-Organization transfer creates a new destination UUIDv7 and `urn:uuid` identity, records the source URI and transfer provenance, links source and destination through an approved typed relationship or authorized legacy mapping, and re-evaluates authorization and classification in the destination. The compatibility map stores an alias string, alias type (`canonical_uri`, `browser_url`, or `legacy_url`), target canonical resource UUID, source/provenance, creation time, and state. Alias values are unique within an instance and are never recycled to another resource.

Resolution follows: current canonical URI or UUID, then active canonical alias, then authorized legacy redirect. Chains are flattened to one target and cycles are rejected. Historical HTTP URLs use `308 Permanent Redirect` only after authorization; API callers receive the current `uri` and `browser_url` in the authorized representation. Deleted, denied, cross-domain, and unknown targets use the same non-disclosing response contract. Redirect access is audited with the alias type and target ID but without protected content.

A cross-instance import likewise creates a new globally unique destination UUIDv7 and URI and preserves the source URI, source URL, and source instance/Organization context in provenance. Only backup/restore of the same logical instance may preserve its existing canonical UUIDs. This ADR does not define identity collision or merge precedence.

### API, schema, and event versions

The identity URI is version-neutral. Compatibility is negotiated at the representation boundary:

- the HTTP path selects the API major (`/api/v1`);
- `schema_version` selects the OWGP representation major/minor (`1.0`), with the API major serving only schema majors it declares compatible;
- CloudEvent `type` and subject suffixes select the event major (`stead.<domain>.<action>.v1`), while `dataschema` identifies the exact payload schema;
- exports record the exact API/profile, schema, and event versions used, in addition to stable resource URIs.

Patch changes clarify contracts without changing accepted instances. Minor schema changes are backward-compatible additions and cannot change a field's meaning, requiredness, cardinality, or URI interpretation. Breaking API, schema, or event changes use a new major. The current and successor majors MUST coexist for at least two consecutive stable releases and 180 days after successor general availability, whichever is longer. During coexistence, API readers/writers and event consumers accept both supported majors; events use explicit dual-publish/dual-read with idempotency preserved.

Deprecation is announced in contract documentation and API responses using `Deprecation`, `Sunset`, and a `Link` to the successor contract. Retirement requires usage evidence, migration tooling, export compatibility, consumer readiness, and release-gate approval. Earlier retirement is allowed only when continued support creates a known disclosure or integrity vulnerability and WS-06, WS-01, and the project owner approve the fail-closed migration response.

## Consequences

### Security, authorization, classification, and bypass paths

The URN exposes only a globally unique resource UUID. Envelope instance, Organization, scope, and kind fields remain protected metadata wherever resource existence or tenant membership is protected. Logs, errors, telemetry, redirects, search, events, and aliases follow the existing minimization and non-disclosure rules. Guessing or possessing a URI grants no authority. Configured-instance mismatch, cross-Organization scope mismatch, malformed URNs, resource/reference disagreement, foreign browser authority, userinfo, unknown kinds, and alias cycles fail closed and are audited safely.

### Data model, migration, and backward compatibility

New Phase 1 rows store globally unique UUIDv7 ID and canonical URI, explicit instance/scope/Organization/kind fields, and server-derived browser URL separately. The pre-implementation Phase 0 HTTPS examples have no persisted consumers; they are replaced in place by this accepted v1 profile. An upgrade from prototype data backfills `uri` deterministically as `urn:uuid:<preserved-id>`, populates and validates explicit envelope scope fields from trusted canonical state, records former browser or experimental URI values as provenance/aliases where safe, verifies global UUID uniqueness and reference agreement, then switches reads before writes. Provider IDs and URLs remain opaque external references.

### Upgrade, rollback, backup, restore, and recovery

Rollout uses expand/contract: add URI, explicit instance/scope fields, server-derived browser URL, and alias storage; backfill and verify; dual-read old locators; switch canonical writes; then retire old reads after the coexistence gate. Abort on duplicate UUID, configured-instance mismatch, invalid scope, reference disagreement, foreign browser authority, unknown kind, alias cycle, or an authorization/non-disclosure regression. Before contract, rollback restores the prior binary and schema while retaining added columns. After canonical writes begin, rollback must preserve the new URIs and use forward recovery; it MUST NOT regenerate IDs or revert canonical identity to an HTTPS/provider locator. Backup/restore preserves `instance_id`, canonical mappings, aliases, and audit evidence.

### APIs, schemas, events, providers, and standards mappings

OWGP defines `CanonicalResourceUri` and `CanonicalBrowserUrl`; resource envelopes require both. OpenAPI uses those definitions for canonical public URI fields. Events and PROV/OSLC/JSON-LD mappings carry the stable URN as resource identity and may carry the authorized browser URL only when payload minimization permits. Providers map their locators through adapters and never mint canonical identity.

### Observability, audit, privacy, and evidence

Metrics use kind and validation outcome, never tenant/resource UUID labels. Traces may carry a correlation-safe hash of canonical URI under existing telemetry policy. Audit records URI creation, alias creation/use, scope-validation failure, migration, deprecation-major selection, and redirect outcome with acting/requesting principal context. Evidence includes round-trip, host-change, provider-migration, non-disclosure, coexistence, backup/restore, and rollback results.

### Dependencies, licenses, supply chain, and portability

No runtime dependency is selected. UUIDv7, URN parsing, HTTPS routing, and validation are implementable with the standard Go/TypeScript stacks. The grammar is offline-validatable and has no DNS, registry, cloud, model-provider, or proprietary dependency.

### Documentation and accessibility

User interfaces display titles/keys and copy browser URLs by default; diagnostic/admin views may copy canonical URNs. Accessible link text describes the resource rather than reading the URN. API, migration, export, operator-origin-change, backup/restore, and contributor contract documentation must explain the distinction.

## Verification

The contract is accepted when automated evidence proves:

- `T-ADR-0001-URI-GRAMMAR`: valid lowercase UUIDv7 URNs pass; hostname/provider URLs, wrong versions, malformed tokens, and non-v7 UUIDs fail;
- `T-ADR-0001-SCOPE`: configured-instance matching, Instance self-scope, Organization instance scope and `organization_id` equality, and Organization-owned resource scope hold, including negative cross-Organization fixtures;
- `T-ADR-0001-KIND-ID`: each URN UUID equals the resource ID, each browser URL kind/UUID agrees with its envelope or nested `ResourceRef`, and mismatches fail;
- `T-ADR-0001-HOST-INDEPENDENCE`: the server derives the exact browser URL from the configured trusted origin; changing that configuration changes only `browser_url`, while userinfo, foreign authority, and request/provider supplied origins fail;
- `T-ADR-0001-ALIAS`: rename, reparent, provider move, legacy link, flattened redirect, cycle, deletion, and non-disclosure behavior pass;
- `T-ADR-0001-COMPAT`: API/schema/event v1 compatibility, successor-major dual-read/write, deprecation headers, replay, and retirement gates pass;
- `T-ADR-0001-MIGRATION`: deterministic backfill, collision stop, export/import provenance, backup/restore, rollback-before-cutover, and forward recovery pass.

The checked-in OWGP examples and validator provide the first four contract-level assertions now. Alias persistence, HTTP dereference, migration, and multi-major runtime tests land with their owning dependent issues before release.

## Rollout and supersession

`STEAD-P1-001` may implement only this v1 grammar and its separate mandatory envelope scope fields. Downstream persistence, API, events, search, exports, and migration consume the shared URI contract rather than reimplementing parsers. Any change to URI grammar, scope semantics, browser derivation, or identity immutability requires a superseding ADR, compatibility analysis, a new parser profile where needed, and the full coexistence/migration/rollback process above.

## Reviews and approvals

| Role | Identity | Disposition | Evidence/date |
|---|---|---|---|
| Contract owner | `/root/directive_audit` (WS-01 architecture) | ACCEPT | 2026-08-29; ADR and OWGP/OpenAPI contract tests |
| Architecture and standards (WS-01) | `/root/directive_audit` (WS-01 architecture) | ACCEPT | 2026-08-29; preserves locked architecture and resolves `ADR-CAND-001` |
| Domain/provider/search/migration reviewers (WS-02/03/08/11) | pending implementation review | PENDING | Required before affected consumer implementation merges |
| Security-contract review (WS-06) | pending reviewer | PENDING | Required before affected contract implementation merges |
| Independent QA/security review (distinct WS-13 identities) | pending reviewers | PENDING | Required before affected contract implementation merges |
| Project owner | not required for this conforming choice | N/A | No locked decision changes |
