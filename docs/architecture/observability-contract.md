# Observability, backup, and reliability contract

Every boundary propagates OpenTelemetry trace/correlation/causation context and emits service/version/operation/error/latency plus outbox, replay, DLQ, projection, reconciliation, policy, provider, and migration health. Attributes never include protected bodies, secrets, credentials, prompts, or cardinalities that leak denied resources.

Backup coordinates PostgreSQL module stores, Gitea/Git, OpenFGA, object data/manifests, policy/profile revisions, configuration, and audit/checkpoints. NATS and search are rebuildable and not sole recovery sources. Restore verifies stable IDs, Git hashes/history, labels, permissions, audit, canonical URLs, and replay parity.

SLO datasets are reproducible and classification-safe. Health/doctor exposes dependencies and version compatibility without sensitive detail. Upgrade, restore, chaos, and rollback tests are release gates.
