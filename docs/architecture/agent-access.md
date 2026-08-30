# Agent access boundary

Future external agents use canonical Platform APIs through a platform-wide MCP surface and the same authorization, classification, observability, and audit path as other principals. Direct provider business APIs are prohibited; scoped, short-lived, task/repository/action-bound Git protocol credentials are the only approved exception. A2A/Agent Card semantics preserve runtime interoperability.

Phase 0 defines schemas and compatibility seams only. It contains no registry behavior, AgentRun executor, dispatch, prompting, model hosting/provider, agent SDK requirement, memory, orchestration, or full MCP tool catalog.
