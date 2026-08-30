# Phase 0 artifact backlog

**Status:** Phase 0 artifacts approved and baselined at tag `phase0`; only dependency-ready Phase 1 work is authorized.<br>
**Gate:** `GATE-P0-APPROVED` passed against immutable commit `e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31` with all five required dispositions.

The detailed issue records and mandatory implementation fields live in [`implementation-issue-catalog.yaml`](implementation-issue-catalog.yaml). Enforceable pre-implementation ADR deadlines live in the [ADR candidate implementation-gate index](../governance/adr-candidate-index.md) and the catalog's `adr_decision_gates`. This backlog is the dependency and review view for the architecture-constitution milestone.

## Dependency order

```mermaid
flowchart TD
  P000[P0-00 Source inventory] --> P001[P0-01 Constitution]
  P000 --> P002[P0-02 Traceability and issue contract]
  P001 --> P003[P0-03 Repository and module boundaries]
  P001 --> P004[P0-04 OWGP v0.1]
  P004 --> P005[P0-05 Canonical schemas]
  P005 --> P006[P0-06 Security-label lattice]
  P005 --> P007[P0-07 Provider interfaces]
  P005 --> P008[P0-08 OpenAPI skeleton]
  P005 --> P009[P0-09 Event and AsyncAPI contracts]
  P003 --> P010[P0-10 Database ownership map]
  P006 --> P011[P0-11 OpenFGA model v0.1]
  P006 --> P012[P0-12 Policy-decision contract]
  P007 --> P013[P0-13 Threat and bypass baseline]
  P009 --> P013
  P010 --> P013
  P011 --> P013
  P012 --> P013
  P001 --> P014[P0-14 License and dependency policy]
  P003 --> P015[P0-15 Golden-slice test plan]
  P007 --> P015
  P008 --> P015
  P009 --> P015
  P011 --> P015
  P012 --> P015
  P013 --> P015
  P002 --> P016[P0-16 Release and independent-review gates]
  P013 --> P016
  P014 --> P016
  P015 --> P016
  P004 --> P017[P0-17 ADR disposition]
  P006 --> P017
  P007 --> P017
  P010 --> P017
  P016 --> P019[P0-19 v0.2 reconciliation]
  P017 --> P019
  P019 --> P020[P0-20 Product and UX contracts]
  P019 --> P018[P0-18 Coherence and completeness audit]
  P020 --> P018
  P018 --> P021[P0-21 Closeout packet]
  P021 --> P0G[GATE-P0-APPROVED Project-owner approval]
```

Dependencies are finish-to-start unless an issue explicitly limits the dependency to a reviewed draft. Parallel drafting is allowed only across non-overlapping owned files. A downstream artifact cannot be approved against a dependency that is still materially changing.

The compact `P0-00`…`P0-21` labels in this document are artifact work packages, not a second issue registry. Canonical tracked issue IDs are the `STEAD-*` records in [`implementation-issue-catalog.yaml`](implementation-issue-catalog.yaml). Their crosswalk is:

| Artifact work package(s) | Canonical tracked issue(s) |
|---|---|
| `P0-00`, `P0-02`, `P0-13`, `P0-14`, `P0-15`, `P0-16`, `P0-18` | `STEAD-P0-014`; `P0-14` receives WS-01 guardrail review, and `P0-15` also consumes `STEAD-P0-015` plus component-owner seam evidence |
| `P0-01`, `P0-03`, `P0-17` | `STEAD-P0-001`; `P0-03` also uses `STEAD-P0-003` |
| `P0-04`, `P0-05`, `P0-08` | `STEAD-P0-002`; OpenAPI governance also uses `STEAD-P0-001` |
| `P0-06`, `P0-11`, `P0-12` | `STEAD-P0-007` |
| `P0-07` | Capability owners `STEAD-P0-004`, `005`, `007`, `008`, `009`, `010`, `011`, `012`; `STEAD-P0-001` integrates provider conventions |
| `P0-09` | `STEAD-P0-008` for events/publishing/consumption and `STEAD-P0-003` for the `EVT-002` transactional-outbox boundary |
| `P0-10` | `STEAD-P0-003` plus each namespace-owning `STEAD-P0-*` contract issue |
| Agent-ready seam work across `P0-05`–`P0-13`, `P0-15`, `P0-18` | `STEAD-P0-015`, which integrates but does not co-edit owner contracts |
| `P0-19` | `STEAD-P0-001` canonical integration, `STEAD-P0-014` independent reconciliation/traceability verification, and affected contract issues only where their artifact changed |
| `P0-20` | `STEAD-P0-006` with WS-01/06/13 review |
| `P0-21` | `STEAD-P0-014` closeout integration; all owners attest to their artifacts without becoming independent approvers |
| `GATE-P0-APPROVED` | The canonical gate record of the same ID |

## Artifact issues

| Order | Issue | Owner | Requirement focus | Deliverable and acceptance evidence | Depends on | State |
|---:|---|---|---|---|---|---|
| 0 | `P0-00` Source inventory | WS-13; WS-01 and WS-06 review normative and security extraction | All 128 named IDs; canonical directive sections 0–24 | Immutable directive checksum; extracted unique-ID list; no missing/extra/duplicate IDs | — | Baselined |
| 1 | `P0-01` Architecture constitution | WS-01 | PRIN-001–015; locked decisions 1–30 | Precedence, open-work/agent invariants, phase freeze, change control, and approval record match the directive | P0-00 | Baselined |
| 2 | `P0-02` Traceability and issue contract | WS-13 | TEST-001; §0; §20; §22 | Machine-readable 128-ID requirement-to-issue/test/doc/release register; every issue has all mandatory fields; validator passes | P0-00 | Baselined |
| 3 | `P0-03` Repository/module boundaries | WS-01 repository/architecture editor; WS-02 runtime/database-boundary integrator | ARCH-001–004; PRIN-002,005,013 | Required logical tree, runtime boundaries, database ownership rules, capability-neutral modules, and prohibited imports/writes are explicit | P0-01 | Baselined |
| 4 | `P0-04` OWGP v0.1 | WS-01 | STD-001–002; PRIN-004,006,013; DOM-001–011 | Canonical schemas/examples, generic containers, Team hierarchy, Project capabilities/lifecycle, universal values, relationships, compatibility and export/import conformance | P0-01 | Baselined |
| 5 | `P0-05` Canonical schemas | WS-01 common/resource integration; WS-06 identity leaf; WS-02 assignment leaf | ARCH-005; DOM-001–011; AGENT-001–002 | JSON Schema 2020-12 definitions include all closeout resources, PrincipalRef, Agent/AgentRun, capability/preset, provider-neutral assignment, and negative ontology/human-assumption tests | P0-04 | Baselined |
| 6 | `P0-06` Security-label schema and lattice | WS-06 | DOM-007; CLS-001–005,008; AGENT-003,006 | Versioned label/profile schemas, join semantics, container ceilings, raise/downgrade rules, propagation, cross-domain denies, and future delegator/agent/task/runtime/session/resource intersection seams; decision tables | P0-05 | Baselined |
| 7 | `P0-07` Provider interfaces | Capability-specific sole editors WS-03/04/06/07/08/09/10/11; WS-01 integration; WS-12 operational reviewer | SCM-001; SRCH-002; STOR-001; CICD-005; NOTIF-002 | Narrow capability contracts, invariants, versioning, test fixtures, error/idempotency semantics; no unbounded provider interface | P0-05 | Baselined |
| 8 | `P0-08` OpenAPI skeleton | WS-01 | ARCH-003,005; AUTH-002; STD-001 | OpenAPI 3.1.1 skeleton with auth/security schemes, ETags, RFC 9457, UUIDv7, canonical resources, multi-resource search, version policy | P0-05 | Baselined |
| 9 | `P0-09` Event/AsyncAPI contracts | WS-07 sole event-schema/publisher/consumer editor; WS-02 owns `EVT-002` transactional outbox; WS-01/06/13 and producers/consumers review | EVT-001,003–004; EVT-002; ACT-001; NOTIF-001; AUD-002; AGENT-004 | CloudEvents/AsyncAPI, container/capability/classification and actor/requester/delegation-task/correlation fields, replay/DLQ/idempotency | P0-05 | Baselined |
| 10 | `P0-10` Database ownership map | WS-02 boundary integrator; each namespace owner is sole migration/write editor; WS-01 architecture reviewer | ARCH-003–004; EVT-002; GRAPH-001 | Every module/table/migration namespace has one owner; cross-module write/read policy and projection rebuild contract are explicit | P0-03 | Baselined |
| 11 | `P0-11` OpenFGA model v0.1 | WS-06 | AUTH-002–003,006; DOM-003,006,009–010; AGENT-001–003,006 | Model separates Team hierarchy/accountability from access and covers groups, agents, assignment, explicit task scope and no broad inheritance; complete matrix | P0-06 | Baselined |
| 12 | `P0-12` Policy-decision input/output contract | WS-06 | AUTH-002,004–006; CLS-001–008; AGENT-003,006 | Trusted input provenance, principal/runtime/task/delegation/classification seams, fail-closed output/cache/version contract and complete decision table | P0-06 | Baselined |
| 13 | `P0-13` Threat model and bypass inventory | WS-13 (independent); all technical owners consulted | SEC-003–006; CLS-006–008; TEST-004,008; AGENT-003–006 | 33 threats and 47 bypass paths, including hierarchy, capabilities, knowledge scopes, general Work/provider leakage, and Phase 0 agent scope | P0-07,09–12 | Baselined |
| 14 | `P0-14` License/dependency workflow | WS-13; project owner/legal for exceptions | SEC-001–002; CICD-002,004 | Default allow/reject rules, evidence, quarantine, ADR/legal exception, CI gates, notices/SBOM, upgrade/rollback handling | P0-01 | Baselined |
| 15 | `P0-15` Golden scenarios | WS-13 owns assertions; component owners supply contracts and fixtures | TEST-002–010; AGENT-001–007; §23 | TEST-009 general Project without code plus TEST-010 software extension; hierarchy/capability/non-disclosure, install/recovery/event/provider coverage | P0-03,07–09,11–13 | Baselined |
| 16 | `P0-16` Release and independent-review gates | WS-13 | PRIN-010; TEST-001–010; §22 | Entry/exit gates, immutable evidence manifest, waiver constraints, segregation of duties, veto and revocation rules | P0-02,13–15 | Baselined |
| 17 | `P0-17` ADR disposition | WS-01; project owner approves | §0; §21 | Twenty-one genuine implementation choices, including the initial Team relation model, with exact issue activation deadlines; reconciliation introduces no unresolved conflict; locked decisions not reopened | P0-04,06,07,10 | Baselined |
| 18 | `P0-19` v0.2 reconciliation | WS-01; WS-13 verifies | PRIN-013–015; DOM-008–011; UX-006–009; AUTH-006; TEST-010 | Canonical directive and report preserve agent-ready work, map semantic replacements, classify all affected artifacts, and remove superseded sources | P0-02–17 | Baselined |
| 19 | `P0-20` Product and UX exit contract | WS-05; WS-01/06/13 review | PRIN-013–015; UX-001–009 | IA, presets, object surface, design constitution, component ownership, six low-fidelity persona flows, no Devlane ontology contract | P0-19 | Baselined |
| 20 | `P0-18` Coherence/completeness audit | WS-13 independent of artifact authors | All | Automated ID/YAML/JSON/field/link validation plus contradiction, ownership, boundary, security, and testability review; zero blocking artifact findings | P0-02–17, P0-19–20 | Baselined |
| 21 | `P0-21` Phase 0 Closeout Packet | WS-13 integration; all owners attest | All | Eight required closeout sections, validation evidence, ADR list, Phase 1 dependency plan, approval record; no Phase 1 authorization | P0-18 | Baselined |
| Gate | `GATE-P0-APPROVED` Phase 0 approval | Project owner; WS-01 architecture and WS-06 security-contract approval; distinct independent WS-13 QA and security approvals | §20 Phase 0 | Approval record names exact commit/tag and every artifact version; no unresolved Critical/High Phase 0 artifact defect; future executable risks retain owned controls/tests/gates; future issues unblock only after recorded approval | P0-21 | **Approved** (`phase0`) |

## Required review evidence

Each issue must attach or link:

- the exact requirement IDs and directive version used;
- a diff or immutable artifact version;
- automated schema/model/lint/coverage output where applicable;
- authorization/classification decision tables and negative cases;
- migration, compatibility, upgrade, rollback, and recovery analysis;
- observability/audit and sensitive-data analysis;
- dependency/license evidence;
- documentation updates;
- WS-01 architecture disposition;
- WS-06 security-contract disposition;
- separate independent WS-13 QA and security dispositions from distinct reviewer identities;
- project-owner disposition where the gate, an ADR, a license exception, or a locked decision requires it.

Phase 0 contracts may use executable schemas and tests, but they must not include broad domain/provider/UI feature implementation.

## Approval outcome

`GATE-P0-APPROVED` has three valid outcomes:

- **Approved:** exact artifact versions recorded; dependency-ready Phase 1 issues may activate in dependency order. This is the recorded outcome for tag `phase0`.
- **Changes requested:** findings are assigned and all affected approvals remain pending.
- **Rejected/superseded:** reasons and replacement direction are recorded; no implementation is unblocked.

There is no implicit or partial approval by merge, elapsed time, or repository publication.
