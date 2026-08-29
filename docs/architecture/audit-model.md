# Audit model

Audit uses OWGP `AuditRecord` plus the shared actor context. It records action, canonical subject/container, actor, actor type, requester when different, delegation/task, authorization relationship/action/reason context, decision, policy/model versions, request ID, source IP/network/device context, originating service/provider, outcome, correlation/causation, timestamp, and controlled before/after hashes. This supports `requested_by=user:alice` with `actor=agent:backend-agent` without schema change.

Records are append-only and access-controlled. Security-policy administrators do not gain content access by role. Query/export, retention, checkpoint, restore, and failed/denied bypass operations are themselves audited. Bodies, secrets, credentials, prompts, and agent memory are excluded.

Phase 0 defines the contract; Phase 1 implements the first append-only path and later releases add tamper-evident checkpoints. Export versions preserve old record readability; rollback cannot erase or reinterpret already committed audit evidence.
