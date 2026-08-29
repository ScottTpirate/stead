# Stock Gitea provider contract

Gitea is a replaceable upstream engine behind the capability ports in `specs/provider-interfaces.yaml`. Integration uses documented REST APIs, HMAC webhooks, Git SSH/HTTPS/LFS, supported authentication, and documented configuration—never a fork, internal Go import, database query/write, or user-facing canonical ontology.

Every Project receives one hidden tracker repository for Work Item issue content and fixed board state. A general Project receives no code repository. Canonical Work types/statuses/priorities, parentage, estimates, graph relations, Team ownership, capabilities, and agent assignment remain Platform semantics; provider-only native-user assignment limitations remain adapter metadata.

Direct provider changes are reconciled when valid or reset/rejected and audited. PermissionSync reconciles central policy across API, Git, token, package, release, webhook, runner, and raw-admin paths. Images are version/digest pinned. Current, two prior minor, and next candidate versions pass one contract/golden suite before support or upgrade.
