# Core PostgreSQL catalog-conformance harness

Status: first bounded `STEAD-P1-015` implementation slice. This document does not claim completion of `STEAD-P1-015`, ADR-0007, or any aggregate ADR verification suite.

## Boundary

`apps/core/internal/postgres` owns a dependency-free PostgreSQL 16+ catalog reader and exact manifest comparator for the core composition root. It does not render effective configuration, create roles or schemas, repair drift, implement migrations, select a database driver, or expose raw SQL facilities to modules. WS-12 remains the owner of installation-specific effective-configuration rendering. Later issue owners extend one complete rendered manifest with their own namespace cases; this slice contributes only the `core_outbox` fixture.

The manifest registers:

- the non-secret sixteen-character deployment key and full installation UUID binding;
- every deployment-qualified role's semantic ID, deterministic rendered name, versioned installation/semantic-ID binding, and complete non-secret PostgreSQL role properties;
- controlled external or built-in principals that can occur in owner, grantor, or grantee catalog fields but are not release-owned deployment roles;
- exact membership tuples, including role, member, grantor, and explicit `ADMIN`, `INHERIT`, and `SET` options;
- exact database, schema, and object identities/owners;
- exact database, schema, object, owner-global default, and schema-scoped default ACL tuples; and
- an invariant that the actual persistent column-ACL tuple set is empty.

Before typed decoding, the manifest reader performs a bounded canonical JSON pass. It rejects invalid UTF-8, duplicate decoded object keys at every manifest depth, case variants of known keys, unknown or missing fields, null-for-container ambiguity, non-integral number spellings, invalid types, and trailing values. The comparator then rejects invalid deployment identities; role bindings not exactly encoded as `stead-role:v1:<installation-uuid>:<semantic-id>`; unqualified or overlength registered role names; unknown semantic references; duplicate expected tuples; any `SUPERUSER`, `CREATEROLE`, `CREATEDB`, replication, or `BYPASSRLS` role capability; any `ADMIN TRUE` membership; any ACL/default-ACL grant to `PUBLIC`; and any ACL/default-ACL grant option. Legitimate registered `LOGIN` and `INHERIT` properties remain exact manifest fields. It then rejects PostgreSQL versions older than 16 and compares every registered set in both directions. Unknown principals, duplicate catalog rows, missing/extra tuples, owner/property/binding drift, option reversal or inversion, unexpected grants, and every `pg_attribute.attacl` entry fail closed. Role properties are compared field-by-field and configuration arrays element-by-element; no concatenated equality key is authoritative.

## Catalog read contract

`CatalogQueryContracts` is the stable adapter contract and `SQLCollector` is its standard-library `database/sql` implementation. The collector opens one repeatable-read, read-only transaction against the target database, sets `SET LOCAL search_path = pg_catalog, pg_temp`, verifies that exact effective value, and only then executes these ordered projections:

1. `server_version` from `server_version_num`;
2. release-owned roles from `pg_roles` and `shobj_description`, including all registered properties but never password bytes; `rolconfig` is emitted as a JSON array ordered bytewise with explicit `COLLATE "C"` and decoded strictly without delimiter packing;
3. all `pg_auth_members` rows where either endpoint has the deployment prefix, including grantor and all three PostgreSQL 16 membership options;
4. the connected database and its effective ACL from `pg_database` plus `acldefault`/`aclexplode`;
5. every non-system schema and its effective ACL from `pg_namespace`;
6. the selected ACL-bearing non-system relation kinds (ordinary/partitioned tables, sequences, views, materialized views, and foreign tables), plus routines and owner-created types/domains, with effective `relacl`, `proacl`, and `typacl` tuples;
7. every owner-global and schema-scoped row from `pg_default_acl`; and
8. every persistent user-column ACL from `pg_attribute.attacl`, including unregistered schemas and relations.

Queries accept the deployment prefix as a bound parameter. Identifiers remain result data and are never interpolated into SQL. An approved PostgreSQL driver is supplied by the eventual composition/deployment adapter; this slice adds no dependency and changes neither `go.mod` nor `go.sum`.

## Safe failure surface

`ConformanceError.Error()` emits only a normalized error code and violation count. Structured violations contain a code, non-sensitive section/field label, and deterministic input ordinals; they do not carry deployment keys, installation UUIDs, role names, semantic role IDs, schema/object/column names, or ACL principals. A privileged diagnostic path may correlate ordinals with its protected manifest and snapshot, but those values must not be copied into ordinary readiness or API errors.

## Core fixture and evidence limit

`packages/test-fixtures/core/core_outbox_catalog_manifest.json` is a deterministic, non-production `core_outbox` namespace fixture. `tests/integration/core/postgres_catalog_cases.json` registers an exact unique inventory of `INHERIT` inversion, `SET` inversion, reversed edge, `ADMIN TRUE`, and unknown-grantor mutations for every expected membership edge, plus extra-schema-grant and persistent-column-ACL mutations. Package tests generate the required per-edge inventory, require the checked-in inventory to match it exactly, and execute every case. They also cover missing, duplicate, extra and property/owner drift; lockstep prohibited manifest/catalog mutations; configuration delimiter-collision regression; strict JSON decoding; and search-path setup/verification failure.

The later live-PostgreSQL 16 suite must include a sequence with `relacl IS NULL` and no owner-global sequence row in `pg_default_acl`, then prove that fallback expansion yields the owner's `SELECT`, `UPDATE`, and `USAGE` privileges.

The current tests prove manifest decoding, query-contract coverage, exact comparison semantics, safe error rendering, and mutation rejection without a running database. Live PostgreSQL execution, privilege operations, unauthorized re-grant/reconfiguration probes, other owners' namespaces, bootstrap/repair, migration ordering, transaction/outbox atomicity, backup/restore, performance, and independent WS-13 evidence remain later bounded work. Therefore this contribution must not be reported as `T-ADR-0007-NAMESPACE-ROLES`, `T-ADR-0007-FOREIGN-WRITE-DENIAL`, or ADR-0007 aggregate completion.
