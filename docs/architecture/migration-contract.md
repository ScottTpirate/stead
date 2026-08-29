# Migration canonical model

Status: **Phase 0 approval candidate**
Requirements: `MIG-001`–`MIG-005`

The normative machine contract is [migration job schema](../../specs/migration/migration-job-v0.1.schema.json) with a [canonical Phase 0 profile](../../specs/migration/canonical-model-v0.1.yaml).

Every connector implements `discover → analyze → map → dry_run → import → validate → delta_sync → cutover → finalize`. Stages are resumable, idempotent, versioned, audited, and checkpointed without source credentials in state.

The checkpoint stage uses the same closed stage enum as the job. Validation records expected/actual counts, content hashes, label non-lowering, relationship completeness, provenance completeness, and authorization non-regression before cutover can become ready.

Mapping targets only OWGP. Jira/Gitea/source issue types map to `deliverable`, `task`, or `problem`; document types map to the five universal values; provider-only data remains namespaced `source_metadata`. Repositories and delivery records are created only when the target Project capabilities permit them. Organization/Team/Project document containers and Team ownership/hierarchy are explicit. Unknown concepts are reported or quarantined, never made into new ontology.

Migration preserves source IDs/URLs, authors, timestamps, bodies, comments, attachments, relationships, Git history where available, labels without lowering, and provenance. Identity and label mapping must succeed before protected writes. Permanent redirects use canonical IDs.

Pre-cutover rollback discards only connector-owned staging and reverses canonical writes through owner APIs. Post-cutover recovery is forward reconciliation from checkpoints and preserved source/provenance. Provider swaps never change canonical IDs, URIs, capability semantics, or public links.
