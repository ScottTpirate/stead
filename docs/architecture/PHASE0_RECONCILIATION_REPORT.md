# Phase 0 reconciliation report

Status: **Complete; ready for owner and independent approval**
Canonical source: [MASTER_BUILD_DIRECTIVE.md](./MASTER_BUILD_DIRECTIVE.md)
Reconciled: 2026-08-28

The v0.2 open-work direction was merged with the previously approved agent-ready architecture and compatible Phase 0 work. No completed compatible work was restarted. Existing IDs were preserved when their core purpose survived; semantic replacements are explicit below.

Before the Phase 0 baseline was frozen, a bounded naming and contract normalization applied the approved Stead product name and corrected the classification-policy implementation boundary:

| Area | Existing state | Required change | Impact | Requirement IDs |
|---|---|---|---|---|
| Deployable and CLI names | Placeholder `platform-*` component names | Use `stead-web`, `stead-api`, `stead-worker`, and `steadctl` for concrete interfaces | MINOR UPDATE REQUIRED | PRIN-005, ARCH-002–003, DEP-001–005, OPS-001–004 |
| Event namespace | Placeholder `platform.<domain>.<action>.v<major>` with no production consumers | Use `stead.<domain>.<action>.v<major>`; no migration or compatibility alias | MINOR UPDATE REQUIRED | EVT-003 |
| Classification policy implementation | OPA/Rego was prescribed in addition to OpenFGA | Keep OpenFGA mandatory and require a separate deterministic, implementation-neutral classification/context/information-flow policy layer; an evaluator such as OPA/Rego requires an ADR | MATERIAL UPDATE REQUIRED | ARCH-001, AUTH-002, AUTH-004, TEST-002 |

| Area | Existing state | Required change | Impact | Requirement IDs |
|---|---|---|---|---|
| OWGP schemas | Project/software-centered planned profile | Add generic containers, general Work/Docs, Team hierarchy, capabilities/presets/lifecycle, groups, Agent/AgentRun | MATERIAL UPDATE REQUIRED | DOM-001–011, PRIN-013–015 |
| Canonical entity model | Fixed entities with agent only as compatibility seam | Agent/AgentRun and Directory Group are canonical; software resources remain conditional | MATERIAL UPDATE REQUIRED | DOM-002–003, DOM-010 |
| OpenAPI | Planned canonical API skeleton | Add multi-scope Docs, capabilities, typed search, PrincipalRef and agent schemas; no provider/Devlane ontology | MATERIAL UPDATE REQUIRED | ARCH-005, DOM-008–011, AUTH-006 |
| AsyncAPI | Planned CloudEvents envelope | Add container/capability, acting/requesting principals, delegation/task, correlation/causation | MATERIAL UPDATE REQUIRED | EVT-001–004, AGENT-004 |
| OpenFGA | Agent-ready but flat Team model | Add groups/Agents and explicit Team/Project relations with no hierarchy/accountability inheritance | MATERIAL UPDATE REQUIRED | DOM-009–010, AUTH-002–003, AUTH-006 |
| Policy-decision input/decision | Future agent attributes reserved | Add explicit principal/requester/task/delegation/runtime intersection and capability/hierarchy leak cases | MATERIAL UPDATE REQUIRED | AUTH-004–006, CLS-006 |
| Security-label model | Generic label/lattice already approved in principle | Clarify Organization/Team/Project containers and capability metadata protection | MINOR UPDATE REQUIRED | CLS-001–008, DOM-003 |
| Provider interfaces | Gitea/software capability focus | Keep Gitea preferred, make Work/provider contract general, capability-gate software, add contract-only A2A provider | MATERIAL UPDATE REQUIRED | PRIN-013, SCM-001–006, GRAPH-002 |
| Search resource model | Work/Docs/Code projection planned | Use typed multi-resource envelope; filter Team/Project rollups, capabilities, agents, counts and suggestions | MATERIAL UPDATE REQUIRED | SRCH-001–003, CLS-006, UX-006–008 |
| Event schemas | Principal-safe overlay planned | Publish actor-context and canonical data schemas including container/capabilities | MATERIAL UPDATE REQUIRED | EVT-001–004, AGENT-004 |
| Audit schemas | Separate actor/requester seam approved | Retain seam and add canonical AgentRun/task context and multi-container subject support | MINOR UPDATE REQUIRED | AUD-001–002, DOM-010, AGENT-004 |
| Migration canonical model | Fixed ontology mapping planned | Map to universal types/presets/containers/hierarchy; software records only for active capabilities | MATERIAL UPDATE REQUIRED | MIG-001–005, DOM-004–005, DOM-008–011 |
| Golden scenarios | One software-heavy path | Replace with TEST-009 general no-code path and TEST-010 additive software extension | SUPERSEDED | TEST-009, TEST-010 |
| Requirement/test traceability | 115 IDs | Canonical 128-ID inventory; add 13 v0.2 IDs and update issue/test reciprocity | MATERIAL UPDATE REQUIRED | all; new IDs below |
| Threat model | 28 findings and 42 bypass controls | Add hierarchy, capability, knowledge-container, general-provider and agent-scope threats/controls | MATERIAL UPDATE REQUIRED | TM-F029–033, CBI-043–047 |
| License/dependency workflow | Agent-portable and fail-closed workflow complete | No semantic change; status/readiness wording only | UNCHANGED | SEC-001–002, AGENT-007 |
| Repository/database ownership | 13 workstreams and modular boundaries complete | Add contract-only agent/A2A/MCP paths; clarify Agent schemas versus runtime | MINOR UPDATE REQUIRED | ARCH-002–004, DOM-010, GRAPH-002 |
| Product/UX contract | Single shell and Devlane fork | Add universal/capability nav, object surface, six journeys, design constitution; reject Devlane ontology/routes | MATERIAL UPDATE REQUIRED | PRIN-014, UX-001–009 |
| Agent-ready overlay | Agent principal/seams; no canonical Agent entity | Preserve all AGENT requirements; reconcile Agent/AgentRun canonical schemas while retaining external runtime/non-execution boundary | MATERIAL UPDATE REQUIRED | DOM-002, DOM-010, AUTH-006, AGENT-001–007 |

## Requirement-ID mapping

New stable IDs from v0.2 are `PRIN-013`–`PRIN-015`, `DOM-008`–`DOM-011`, `UX-006`–`UX-009`, `AUTH-006`, and `TEST-010`.

| Previous requirement | Reconciled disposition |
|---|---|
| `DOM-001`, `DOM-002`, `DOM-003`, `DOM-006` | IDs preserved; expanded to open-work containers, groups, Agents/runs, hierarchy and relationships. |
| `DOM-004` | ID preserved; Feature/Task/Bug canonical values replaced by `deliverable`/`task`/`problem`; Feature/Bug are software display labels. |
| `DOM-005` | ID preserved; software-specific document values replaced by `page`/`specification`/`decision`/`procedure`/`policy`; aliases are display-only. |
| `DOC-001` | ID preserved; Project-only/default docs backing expanded to Organization-, Team-, and Project-scoped knowledge repositories and unified authorized browsing. |
| `UX-001` | ID preserved; navigation replaced by universal Home/Inbox/My Work/Projects/Knowledge/Teams and capability-driven Project areas. |
| `GRAPH-002` | ID preserved and expanded from MCP access to MCP/A2A/agent interoperability. |
| `TEST-009` | ID preserved for the general-work no-code scenario; former software assertions moved to new `TEST-010`. |
| Agent-ready addendum | Preserved as `AGENT-001`–`AGENT-007`; DOM-002/010 now require Agent/AgentRun schemas, but AGENT-007 still forbids execution/orchestration in Phase 0. |
| `service_principal` source term | Canonical API discriminator remains `service_account`, referencing the one Service Principal entity. This preserves the approved agent-ready schema and is not a second identity type. |

No existing requirement was silently deleted. Historical v0.1 and review-diff content was either incorporated above or intentionally superseded by the canonical directive.

## Required explicit checks

| Check | Result and evidence |
|---|---|
| Code/repository/build/release not mandatory | PASS — OWGP Project requires Work+Docs only; general golden forbids code repository and Code/Delivery UI. |
| Work/Document not software-specific | PASS — universal enums in OWGP; software labels are display-only. |
| Team hierarchy without inherited permissions | PASS — `parent` exists in schema/OpenFGA, with no `viewer/member/editor from parent`; the 80-assertion OpenFGA matrix covers parent/child and owning/contributing non-grants. |
| Organization/Team Docs | PASS — `ContainerRef` and Document schema permit exactly Organization/Team/Project; examples and golden cover all. |
| Principal user/agent/service account | PASS — `PrincipalRef` includes those acting kinds plus non-acting Directory Group. |
| No human-only assignee/actor | PASS — assignment, actor context, events, audit, API and policy-decision layer use typed principal references. |
| Multi-resource Search | PASS — typed SearchResult and search resource model cover universal and applicable optional resources. |
| Capability-driven navigation | PASS — fixed capability schema and UX contract suppress inactive/unauthorized surfaces. |
| General and software goldens | PASS — executable plans for TEST-009 and TEST-010 are separate. |
| No Devlane route/ontology contract | PASS — UX constitution and threat/bypass tests explicitly prohibit it. |

## ADR conflicts

No reconciliation conflict requires an ADR. The current genuine implementation choices remain deferred in [the ADR index](../adr/INDEX.md) and must be decided before their named dependent implementation. The reconciliation does not reopen a locked decision.

## Cleanup disposition

`MASTER_BUILD_DIRECTIVE.md` is the sole normative directive. The v0.1 historical copy, v0.2 input copy, review diff, Phase 0 handoff input, and prior top-level working directive become superseded after their applicable content and references are incorporated. They should be removed rather than archived; Git history retains the prior tracked directive.
