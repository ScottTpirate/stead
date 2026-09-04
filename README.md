# Stead

Stead is an open-source, self-hostable, organization-wide open work and knowledge platform. Its single normative product and architecture specification is the [canonical Master Build Directive](docs/architecture/MASTER_BUILD_DIRECTIVE.md).

Phase 0 is approved and baselined at tag `phase0`, commit `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31`. Phase 1 implementation is active: ADR-0001 through ADR-0008 are accepted; `STEAD-P1-001` and `STEAD-P1-016` are complete; and the original Stead frontend foundation is merged. `STEAD-P1-015` has merged PostgreSQL catalog-conformance and dependency-free transaction-port slices, but remains incomplete and blocked on an approved database dependency path plus live PostgreSQL integration. ADR-0009 remains proposed and unapproved, and the merged frontend foundation does not complete `STEAD-P1-005`. `STEAD-P1-017` is deferred until the first Phase 2 migration implementation actually needs its namespace; Phase 2–3 otherwise remain phase-gated.

## Phase 0 package

- [Reconciliation report](docs/architecture/PHASE0_RECONCILIATION_REPORT.md)
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
- [Phase 0 validation evidence](docs/phase0/VALIDATION_EVIDENCE.md)

## Current gate

`GATE-P0-APPROVED` is **approved** against tag `phase0` and immutable commit `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31`. The five required dispositions are recorded in the [Phase 0 Closeout Packet](docs/phase0/PHASE0_CLOSEOUT_PACKET.md). Approval opens dependency-ready work only; it does not waive ADR deadlines, issue acceptance criteria, independent review, or later release gates.

Validate the machine-readable Phase 0 planning package with:

```bash
ruby scripts/validate_phase0.rb
scripts/validate_json_schemas.sh
```

## Naming

**Stead** is the project and repository name. Directive-defined component contract names (`stead-web`, `stead-api`, `stead-worker`, and `steadctl`) remain in force unless an approved ADR supplies a compatibility and migration plan.

## License

New original core code is licensed under the [Apache License 2.0](LICENSE), subject to the directive's dependency and retained-notice rules. No dependency is approved merely because it appears in a draft plan.
