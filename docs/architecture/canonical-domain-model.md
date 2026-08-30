# Canonical open-work domain contract

Status: **Phase 0 approval candidate**
Requirements: `DOM-001`–`DOM-011`

The normative machine contract is [OWGP 0.1](../../specs/work-graph-profile/owgp-v0.1.md). This document records its cardinalities and the separations most likely to be accidentally collapsed.

| Relationship | Cardinality | Invariant |
|---|---:|---|
| Instance → Organization | `1:N` | Organization has stable identity. |
| Organization → Team | `1:N` | Team belongs to exactly one Organization. |
| Team → parent Team | `0..1:1` | Same Organization; acyclic; maximum twelve levels; no access inheritance. |
| Team → owned Project | `1:N` | Each Project has exactly one owning Team. |
| Team → contributing Project | `N:M` | Accountability only; no implicit access. |
| Project → Work Item | `1:N` | Work Item is always Project-scoped. |
| Organization/Team/Project → Document | exactly one container per Document | Container controls authorization, classification, retention, and Git boundary. |
| Project → Repository | `0..N` | A Project is never a Repository; general Projects require no user-facing or code repository. A Gitea tracker repository, when used as opaque Work backing, is an adapter concern rather than a canonical Project cardinality. |
| Work Item → assignee | `N:M` User or Agent | Assignment is not execution authority. |
| Directory Group → Team membership source | `N:M` explicit binding | Directory Groups and Teams remain distinct. |

`ProjectCapabilitySet` is fixed and versioned. `work` and `docs` are mandatory. `code_review` and `ci` require `scm`; other delivery capabilities follow their provider contract. Presets are `general`, `software`, and `controlled_knowledge` and seed only capabilities/content/views—not ontology, workflow, authorization, or navigation order.

Work Item canonical values are general-purpose. Software display aliases do not alter serialized values. Project lifecycle is `planned`, `active`, `paused`, `completed`, or `canceled`; `archived_at` and `archived_by` are reversible visibility/retention metadata.

Every mutation uses optimistic concurrency, a module-owned transaction, and an atomic outbox entry. Stable IDs/URIs survive rename, hierarchy change, provider migration, export/import, and path moves. Breaking cardinality or canonical-value changes require a major contract version and migration/coexistence plan.
