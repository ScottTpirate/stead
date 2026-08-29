# Stead

Stead is a new, open-source, self-hostable unified work platform. Its normative product and architecture specification is the [Master Build Directive](unified_open_work_platform_master_build_directive.md).

The repository is currently in **Phase 0: architecture constitution and contracts**. It contains planning, governance, ownership, test, and security baselines only. Phase 1–3 feature implementation is blocked until the project owner approves the complete Phase 0 contract set against an immutable commit or tag.

## Phase 0 package

- [Architecture constitution](docs/architecture/constitution.md)
- [Requirements traceability register](specs/traceability/requirements.yaml)
- [Dependency-ordered epic and issue hierarchy](docs/planning/epic-issue-hierarchy.md)
- [Machine-readable implementation issue catalog](docs/planning/implementation-issue-catalog.yaml)
- [Thirteen-workstream ownership map](docs/architecture/workstream-ownership.md)
- [Contract ownership matrix](docs/architecture/contract-ownership-matrix.md)
- [Repository layout and boundaries](docs/architecture/repository-layout-and-boundaries.md)
- [Agent-ready compatibility overlay](docs/architecture/agent-ready-compatibility.md)
- [Phase 0 artifact backlog](docs/planning/phase-0-artifact-backlog.md)
- [Golden vertical-slice test plan](docs/testing/golden-vertical-slice.md)
- [Threat model](docs/security/threat-model.md) and [classification bypass inventory](docs/security/classification-bypass-inventory.md)
- [Machine-readable threat and bypass traceability](specs/traceability/security-findings.yaml)
- [License and dependency approval workflow](docs/governance/license-and-dependency-approval.md)
- [Release gates and independent approvals](docs/governance/release-gates.md)
- [Unresolved ADR candidates](docs/adr/unresolved-implementation-choices.md)

## Current gate

`GATE-P0-APPROVED` is **pending**. Repository publication, document merge, or elapsed time does not imply architecture approval. See the [Phase 0 backlog](docs/planning/phase-0-artifact-backlog.md) for the required evidence and approval record.

Validate the machine-readable Phase 0 planning package with:

```bash
ruby scripts/validate_phase0.rb
```

## Naming

**Stead** is the project and repository name. Directive-defined component contract names (`platform-web`, `platform-core`, `platform-worker`, and `platformctl`) remain in force unless an approved ADR supplies a compatibility and migration plan.

## License

New original core code is licensed under the [Apache License 2.0](LICENSE), subject to the directive's dependency and retained-notice rules. No dependency is approved merely because it appears in a draft plan.
