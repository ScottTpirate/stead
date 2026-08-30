# Stock Gitea provider contract

Gitea is a replaceable upstream engine behind the capability ports in `specs/provider-interfaces.yaml`. Integration uses documented REST APIs, HMAC webhooks, Git SSH/HTTPS/LFS, supported authentication, and documented configuration—never a fork, internal Go import, database query/write, or user-facing canonical ontology.

Every Project receives one hidden tracker repository for Work Item issue content and fixed board state. A general Project receives no code repository. Canonical Work types/statuses/priorities, parentage, estimates, graph relations, Team ownership, capabilities, and agent assignment remain Platform semantics; provider-only native-user assignment limitations remain adapter metadata.

Direct provider changes are reconciled when valid or reset/rejected and audited. PermissionSync reconciles central policy across API, Git, token, package, release, webhook, runner, and raw-admin paths. Images are version/digest pinned. Current, two prior minor, and next candidate versions pass one contract/golden suite before support or upgrade.

Ordinary Stead UI reads use a local rebuildable Gitea provider projection in PostgreSQL. Gitea webhooks update it asynchronously, scheduled reconciliation detects missed events and drift, and projection rows retain the provider revision and reconciliation evidence needed for audit. A normal Work, Project, inbox, search, or relationship surface MUST NOT call Gitea synchronously per issue, repository, comment, property, or row. Provider-call-count tests assert zero Gitea calls for ordinary reads and fail any result-size-dependent waterfall.

Gitea remains authoritative for provider-owned data. A mutation calls the documented adapter with idempotency/concurrency controls, returns only after authoritative success plus the required Stead transaction, and immediately updates or reconciles the local projection. The transactional outbox then distributes the committed result; neither NATS publication nor a projection consumer is awaited in the synchronous response chain. Provider drift remains visible, measurable, reconcilable, and auditable without exposing Gitea ontology to the browser.
