# Agent-ready compatibility overlay

**Status:** Reconciled Phase 0 compatibility contract; ready for approval<br>
**Requirements:** AGENT-001–007<br>
**Scope:** Contract seams only; no executable agent capability

This overlay records where Phase 0 contracts must remain extensible for later agent functionality. The canonical ontology now includes Agent and Agent Run schemas under DOM-002 and DOM-010; this overlay does not authorize an agent runtime, orchestration, dispatch, or an executable implementation epic in Phase 0.

The `service_account` Principal discriminator refers to the DOM-002 **Service Principal** entity. `PrincipalRef` also supports `directory_group` for membership and authorization relationships, but Directory Groups cannot act. `user`, `agent`, and `service_account` are the acting principal kinds. Agent and Agent Run representations remain runtime-neutral.

## Required seams

| Contract surface | Phase 0 compatibility requirement | Sole editing owner | Required Phase 0 proof |
|---|---|---|---|
| Canonical Principal schema | Discriminated reference with `user`, `agent`, `service_account`, `directory_group`; human identity, acting principal, and non-acting group subject are distinct | WS-06 sole editor; WS-01 architecture reviewer | Schema accepts all reference kinds, restricts actors to three acting kinds, and rejects human-only assumptions |
| Agent and Agent Run schemas | Runtime-neutral identity, registration, task/delegation, state, attribution, and external-runtime references without prompt/model/framework internals | WS-06 sole editor; WS-01/07/08 reviewers | Schema fixtures validate future run attribution and lifecycle representation while repository inventory proves no executor exists |
| Work assignment | Canonical assignee references a Principal and accepts `agent`; Gitea native-user limitations stay inside its adapter/projection | WS-02; WS-01 owns public schema | Contract fixture accepts an agent; provider fixture documents supported mapping/degraded behavior without changing canonical type |
| OpenFGA v0.1 | Reserve `agent` principal and seams for explicit delegation, task/resource scope, independent revocation, and agent-specific permissions | WS-06 | Model and migration fixtures prove no implicit broad inheritance from a user |
| OPA decision input | Carry principal type and extensible, namespaced trusted attributes for runtime, domain, ceiling, compartments, model provider, tool scope, and execution environment | WS-06 | Input-schema fixtures validate presence/absence/fail-closed behavior; no policy grants execution in Phase 0 |
| Audit and CloudEvents | Represent actor, actor principal type, different `requested_by`, optional delegation/task context, correlation, and causation without a future schema break | WS-07 owns event/actor-context schemas; WS-01 owns the public canonical Audit Record resource schema | Round-trip fixture with `requested_by = user:alice` and `actor = agent:backend-agent` |
| Platform API | Principal-safe resource and assignment representations; provider-specific business resources do not become the future agent contract | WS-01 public contract; WS-02 domain consumer | OpenAPI/schema review and negative provider-leak test |
| Platform-wide MCP | Reserve WS-08 ownership and the same API/authorization/audit path; do not define the full tool catalog now | WS-08; WS-01/06/13 reviewers | Boundary and ownership review only; executable catalog absence test |
| Direct Git interoperability exception | Future agent business access remains API/MCP-first; only scoped direct Git protocol access is exempt | WS-08 owns the interoperability-boundary document; WS-03 and WS-06 review | Boundary test proves provider business APIs and unrestricted provider access remain prohibited |
| Scoped Git credential mechanics | Git credentials are repository/domain/task/action scoped, short-lived, independently revocable, and provider enforced | WS-03 owns GitProvider/credential mechanics; WS-06 owns policy | Threat/bypass tests cover SSH/HTTPS/LFS scope, expiry, revocation, non-enumeration, and attribution |
| External runtime interoperability | No canonical contract requires a particular model, provider, agent SDK, runtime, or orchestrator | WS-08 architecture; WS-13 independent test | Dependency and schema lint/review; future MCP profile and A2A/Agent Card decision point documented |
| Classification intersection | Preserve inputs/relations for delegator ∩ agent ∩ task ∩ runtime domain ∩ session/environment ∩ resource label/handling | WS-06 | Reserved decision inputs and negative cases are complete; no broad inherited allow |

## Contract-neutral conceptual shape

The approved JSON Schema will choose exact field names and URI forms. It must be able to express this meaning without a version-breaking redesign:

```text
request_context
├── actor: agent:backend-agent
├── actor_type: agent
├── requested_by: user:alice
├── delegation: optional explicit reference
├── task_scope: optional explicit reference
├── correlation_id
└── causation_id
```

This sketch is explanatory, not a public schema. Canonical field names remain a P0-05/P0-08/P0-09 contract decision owned under the contract matrix.

## Explicit negative scope

Phase 0 must contain no implementation of:

- agent orchestration or scheduling;
- prompting or prompt templates as a product subsystem;
- model hosting or model-provider integration;
- agent memory;
- `AgentRun` execution (the canonical Agent Run schema is permitted and required);
- A2A dispatch;
- an executable full MCP tool catalog.

Phase 0 may contain schemas, model fixtures, decision tables, interface ownership, threat cases, and non-execution tests needed to prove compatibility. A future executable agent integration requires its own approved issue set, contracts, threat review, and `ADR-CAND-017` disposition.

## Review checklist

- No field is typed or named as `user` when it semantically means Principal.
- Assignment and review/subscription contracts do not assume a human.
- Provider-native user IDs are confined to provider adapter state/references.
- OpenFGA and OPA seams deny missing, expired, revoked, or unverifiable agent/delegation/runtime data.
- Audit/event attribution cannot collapse requester and actor.
- Platform API/MCP paths use the same authorization, classification, observability, and audit controls as human clients.
- Direct Git is the only provider-direct exception and is scoped, short-lived, revocable, and bypass-tested.
- No dependency or schema couples Stead to one AI vendor or runtime.
- No Phase 0 artifact accidentally authorizes or implements agent execution.
