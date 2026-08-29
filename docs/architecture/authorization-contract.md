# Authorization and classification decision contract

Status: **Phase 0 approval candidate**
Requirements: `AUTH-001`–`AUTH-006`, `CLS-001`–`CLS-008`, `AGENT-003`, `AGENT-006`

An operation is allowed only when authentication/trusted context is valid, OpenFGA allows the explicit relationship, OPA allows classification/ABAC/context, the provider or direct path can enforce the result, and no explicit deny applies. Missing, expired, revoked, unsupported, or unverifiable input denies. Responses conceal denied existence.

The OPA input declares which additional context families an action requires. Data-flow context carries the destination domain/ceiling/profiles/organizations/releasability/channel, proposed label, and any reasoned/authorized lowering request. CI context carries runner pool/domain, approved image digest, network/egress, secret scope, artifact label, and deployment environment. Infrastructure context carries admission/storage/backup/restore/integration target, provider, ceiling, encryption, network, and applicable backup/integration identity. A required context family that is absent or unverifiable denies.

The authoritative contracts are [OpenFGA model](../../policies/openfga/model.fga), [model tests](../../policies/openfga/model-tests.yaml), [OPA input](../../policies/opa/input-v0.1.schema.json), [OPA output](../../policies/opa/output-v0.1.schema.json), and [decision table](../../policies/opa/decision-table.yaml).

Team `parent` is organizational context only; the model intentionally defines no viewer/member/editor relation through a parent. Project owning/contributing Teams also grant nothing without explicit authorization tuples. Restrictive OPA policy may cascade only through a named, tested policy rule.

For an Agent, allow is the intersection of delegator authority, agent-specific authority, task scope, runtime/workload identity and security domain, session/environment restrictions, and resource label/handling. Agent assignment is not permission. Revocation is independent of the requester. Directory Groups may be authorization subjects but cannot act.

Every decision carries a consistency fence over the resource version, effective-label revision, OpenFGA tuple revision, and delegation/revocation revision. A protected read or mutation MUST evaluate at or after the latest committed raise, compartment addition, explicit deny, permission removal, or delegation revocation. If that ordering cannot be proven, the operation denies and refreshes policy state; a previously cached allow is never served across the fence. Label raises and revocations commit before invalidation events are released, and consumers stop serving affected projections until they reach the new fence. Rollback never restores a stale allow: it is a forward, authorized policy change with a new revision and audit record.

Decision telemetry records decision ID, model/bundle versions, reason codes, latency, correlation, and cache behavior—never protected bodies or secrets. Audit records actor/requester/task/delegation and the decision metadata. Policy/model upgrades require signed/versioned bundles, migration tests, cache/projection invalidation, staged activation, and rollback to a compatible previously signed revision.
