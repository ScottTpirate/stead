# Open Work Graph Profile 0.1

Status: **Phase 1 foundation contract**
Requirements: `STD-001`, `STD-002`, `DOM-001`–`DOM-011`, `PRIN-013`–`PRIN-015`, `ARCH-005`, `MIG-003`, `MIG-005`

OWGP 0.1 is Stead's fixed, provider-neutral interchange profile. Its normative JSON Schema is `owgp-v0.1.schema.json` and covers every `DOM-002` canonical entity; `examples.yaml` supplies representative examples for the Phase 0 vertical-slice resources and principal/event seams. Canonical API values never change with display labels or provider mappings.

## Invariants

- Every resource uses a stable UUIDv7 identifier, provider/host-independent canonical URI, separate canonical browser URL, version, Organization context, effective `SecurityLabel`, provenance, and explicit typed relationships.
- `PrincipalRef` is `user`, `agent`, `service_account`, or `directory_group`; only the first three may be an acting principal.
- A Team has at most one parent in its Organization, is at most twelve levels deep, and cannot form a cycle. Hierarchy grants no authorization relation.
- Every Project has one owning Team, zero or more contributing Teams, one fixed preset, universal `work` and `docs`, and only fixed optional capabilities. Repository and delivery resources are optional.
- A Work Item belongs to exactly one Project and uses `deliverable`, `task`, or `problem`.
- A Document belongs to exactly one Organization, Team, or Project and uses `page`, `specification`, `decision`, `procedure`, or `policy`.
- Project lifecycle is separate from reversible archive metadata.
- Agent and Agent Run are representable and auditable without coupling to a model, SDK, runtime, orchestrator, prompt format, or provider.
- Exports contain canonical values and opaque external references; a provider locator never replaces a canonical ID.

## Canonical identity and browser links

[ADR-0001](../../docs/adr/0001-canonical-uri-and-compatibility-profile.md) defines the normative v1 identity profile:

```text
urn:uuid:<resource_uuid>
```

The UUID is lowercase UUIDv7, globally unique across Stead instances, and equal to the resource envelope's `id`. Every complete envelope separately requires `instance_id`, `scope_kind`, `scope_id`, `organization_id`, and `kind`: an Instance is self-scoped; an Organization is instance-scoped and has `organization_id=id`; every other Organization-owned resource has `scope_kind=organization` and `scope_id=organization_id`. The envelope `instance_id` must match trusted configured instance state. Neither provider nor hostname is identity, and scope/kind are validated fields rather than claims inferred from the URN.

Complete resource envelopes also carry:

```text
https://<configured-origin>/r/<kind>/<uuid>
```

as `browser_url`. The server derives this exact value from a canonically serialized configured trusted HTTPS origin with no userinfo, path, query, or fragment and the validated `kind`/`id`; client, provider, import, request-host, userinfo, and foreign-authority values are rejected. Changing configured origin changes only the derived browser URL. Compact resource references may omit `browser_url`, but their `kind`, `id`, and `uri` must agree, including in nested references. Dereference and redirect handling must authorize before disclosing existence; URI parsing never grants access or selects a tenant by itself.

Renames, hierarchy or container changes within the same Organization, provider moves, and origin changes preserve UUID/URI. An in-place cross-Organization move is prohibited: an authorized transfer creates a new destination UUIDv7/URN, preserves the source identity and transfer context in provenance, links the two through an approved typed relationship or authorized legacy mapping, and re-evaluates authorization and classification. Cross-instance imports reidentify the resource similarly, except restoration of the same logical instance.

## Compatibility

The identity URI is version-neutral. HTTP API major is selected by `/api/v<major>`, each resource declares exact OWGP `schema_version`, and event major is selected by `stead.<domain>.<action>.v<major>` plus its exact `dataschema`. Patch versions may clarify prose. Minor versions may add optional fields or enum values only after contract review and compatibility tests. Removing a field/value, changing cardinality, changing relationship direction, changing canonical meaning, or weakening policy requires a major version, migration/coexistence window, approved ADR where locked, and rollback plan.

Breaking majors coexist for at least two consecutive stable releases and 180 days after successor general availability, whichever is longer. API deprecation uses `Deprecation`, `Sunset`, and successor `Link` metadata; event evolution uses dual-publish/dual-read and replay tests. Canonical URI aliases and historical URLs resolve through the authorized, audited redirect map and never recycle to another resource.

Importers preserve unknown source data only under namespaced `source_metadata`. Unknown source concepts do not extend this ontology. Export/import conformance requires schema validation, stable-ID round trip, relationship preservation, effective-label non-lowering, and explicit unsupported-construct reporting.
