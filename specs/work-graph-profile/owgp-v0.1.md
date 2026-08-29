# Open Work Graph Profile 0.1

Status: **Phase 0 approval candidate**
Requirements: `STD-001`, `STD-002`, `DOM-001`–`DOM-011`, `PRIN-013`–`PRIN-015`

OWGP 0.1 is Stead's fixed, provider-neutral interchange profile. Its normative JSON Schema is `owgp-v0.1.schema.json` and covers every `DOM-002` canonical entity; `examples.yaml` supplies representative examples for the Phase 0 vertical-slice resources and principal/event seams. Canonical API values never change with display labels or provider mappings.

## Invariants

- Every resource uses a stable UUIDv7 identifier and canonical URI, version, Organization context, effective `SecurityLabel`, provenance, and explicit typed relationships.
- `PrincipalRef` is `user`, `agent`, `service_account`, or `directory_group`; only the first three may be an acting principal.
- A Team has at most one parent in its Organization, is at most twelve levels deep, and cannot form a cycle. Hierarchy grants no authorization relation.
- Every Project has one owning Team, zero or more contributing Teams, one fixed preset, universal `work` and `docs`, and only fixed optional capabilities. Repository and delivery resources are optional.
- A Work Item belongs to exactly one Project and uses `deliverable`, `task`, or `problem`.
- A Document belongs to exactly one Organization, Team, or Project and uses `page`, `specification`, `decision`, `procedure`, or `policy`.
- Project lifecycle is separate from reversible archive metadata.
- Agent and Agent Run are representable and auditable without coupling to a model, SDK, runtime, orchestrator, prompt format, or provider.
- Exports contain canonical values and opaque external references; a provider locator never replaces a canonical ID.

## Compatibility

Patch versions may clarify prose. Minor versions may add optional fields or enum values only after contract review and compatibility tests. Removing a field/value, changing cardinality, changing relationship direction, changing canonical meaning, or weakening policy requires a major version, migration/coexistence window, approved ADR where locked, and rollback plan.

Importers preserve unknown source data only under namespaced `source_metadata`. Unknown source concepts do not extend this ontology. Export/import conformance requires schema validation, stable-ID round trip, relationship preservation, effective-label non-lowering, and explicit unsupported-construct reporting.
