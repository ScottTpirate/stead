# Stead

Stead is an open-source, self-hostable, organization-wide open work and knowledge platform. Its single normative product and architecture specification is the [canonical Master Build Directive](docs/architecture/MASTER_BUILD_DIRECTIVE.md).

Phase 0 is approved at tag `phase0`, commit `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31`. Phase 1 is active: ADR-0001 through ADR-0009 are accepted, `STEAD-P1-001` and `STEAD-P1-016` are complete, and the frontend foundation is merged. ADR-0009's accepted decision is `b64384249a82f6f744ec07a002f70de6e24e15e6`; the local bootstrap amendment is accepted in [PR #46](https://github.com/ScottTpirate/stead/pull/46).

The persistent [Phase 1 integration PR](https://github.com/ScottTpirate/stead/pull/45) contains the approved PostgreSQL runtime driver, real transactions, central authorization, and connected Organization/Team/Project API and UI. The retained older synthetic installation completed actual browser creation and independent reads of an Organization, parent/child Teams and a general Project, including five full reloads and manual Refresh. Independent PostgreSQL checks confirm matching domain, audit, idempotency and outbox transactions. A separate authenticated no-grant User received matching generic responses for known/nonexistent resources; a denied Team mutation left protected database and OpenFGA state unchanged. This is bounded response/state evidence, not browser-denial coverage or timing-side-channel resistance. Live OpenFGA tests separately confirmed that Team hierarchy and ownership do not grant access. That demo is now stopped with its original state intact and an independently verified private stopped-state snapshot; preservation is not an application restore test or activation of current source.

The reviewed signed bootstrap has passed real per-installation policy, mutation, dependency and offline verification checks. Development services have [distinct scoped approval](deploy/compose/dev-service-review.md), limited to synthetic use; the local Gitea service's approved use remains startup/health-only. A separately isolated, unmodified upstream successor has passed [real repository, issue and Markdown API checks](docs/governance/dependency-evidence/gitea-successor-functional-proof-20260905.json), including denied and stale-write behavior, with independent QA. Stead's private adapter has also passed its [actual isolated provider contract](docs/governance/dependency-evidence/gitea-adapter-functional-proof-20260905.json), including stale issue-version rejection and 24 bounded calls; it has no application dispatcher or live provider activation yet. Outbox intents are durable but asynchronous delivery, Gitea-backed Work/Docs, browser bypass/accessibility/performance coverage, full audit correlation and Phase 1 release gates remain unfinished. Neither `STEAD-P1-015` nor `STEAD-P1-005` is complete. `STEAD-P1-017` remains deferred until actual Phase 2 migration work requires its namespace; Phase 2–3 remain gated.

The inactive provider-effect store has also passed a [fresh real PostgreSQL storage test](docs/governance/dependency-evidence/postgresql-effect-storage-proof-20260905.json): atomic effect/audit/outbox rollback, competing updates, and fail-closed revocation fences under malformed records and inspection timeout. This is storage evidence, not provider activation or successful sealed provider authorization.

The patched browser, Playwright and axe have passed an [isolated tool-compatibility test](docs/governance/dependency-evidence/browser-tool-compatibility-proof-20260905.json), including real renderer sandbox checks, verified TLS with negative controls, keyboard/reload and positive/negative axe checks. Independent QA/security verified the result and cleanup; this synthetic fixture is not Stead browser-journey or accessibility-release evidence.

Fresh product testing at exact application/harness `daea3d49280dbc2b72c8271f010d6d744d864d88` has passed supported startup, service smoke and four fresh instance-bound signed checks. Its real HTTPS browser run completed login, Organization creation/read, parent and child Team creation/read, general Project creation/read, and reload/Refresh reads. It then failed the command-palette keyboard stage; the distinct no-grant principal was not exercised. Five reached axe surfaces reported no violations, but contrast and palette ARIA checks remain incomplete. Independent QA/security verified the partial result, unchanged inputs/runtime and observable cleanup. This is not Checkpoint A acceptance, independent SQL/audit correlation or a performance-gate pass. The current application, four created objects, established primary session and first failure are retained while a bounded keyboard diagnostic is prepared.

Earlier fresh-installation TLS and workspace-transition failures remain preserved separately, together with their stopped installations and verified private snapshots. Their peer-trust, selector, contrast and main-landmark corrections are included in the new tested application; no historical failure is rewritten as a pass. TEST-009, TEST-010 and the complete Phase 1 release gate have not passed.

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

Phase 1 remains in progress. Browser tooling and isolated component checks do not pass Checkpoint A, TEST-009, TEST-010 or the complete [STEAD-P1-012 release gate](https://github.com/ScottTpirate/stead/issues/17). PR #45 remains draft; Phase 2 must not begin without the complete gate and explicit release approval of its tested immutable revision.

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
