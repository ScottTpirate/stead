# CI, runner, action, and secret contract

CI is optional and requires SCM. Workflows use internally approved, mirrored, immutable action/image digests. Runner pools are ephemeral and partitioned by Organization/security domain/label/trust; lower-domain pools cannot receive higher data. Caches and credentials never cross pools. Privileged runners require explicit policy exception and dedicated pool.

SecretProvider issues short-lived job/action scoped values; secrets never persist in Git, events, logs, search, frontend, artifacts, or caches. Every run records image/action digest, policy decisions, credentials used by identifier, cleanup, build, SBOM, artifact, provenance, and release links. Upgrade/rollback uses a signed known-good catalog and cleanup/isolation tests.
