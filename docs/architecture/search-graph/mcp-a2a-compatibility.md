# MCP and A2A compatibility boundary

The machine-readable Phase 0 seams are `specs/mcp/compatibility-v0.1.yaml` and `specs/a2a/compatibility-v0.1.yaml`. MCP operations reuse canonical Platform APIs and policy/audit context. A2A/Agent Card fields identify external, replaceable runtimes without importing their internal model, prompt, memory, or orchestration semantics.

No executable MCP catalog, registry behavior, dispatch, or AgentRun execution is authorized in Phase 0. Direct scoped Git remains the sole provider-direct exception.
