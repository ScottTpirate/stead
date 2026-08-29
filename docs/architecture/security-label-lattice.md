# Security-label lattice and container contract

Status: **Phase 0 approval candidate**
Requirements: `CLS-001`–`CLS-008`

The `SecurityLabel` fields are fixed in OWGP. Profile sources are versioned and validated by [the profile schema](../../policies/security-label-profiles/profile.schema.json); the release pipeline MUST materialize and verify a Sigstore-compatible signed bundle at `RG-08-SECURITY`. Commercial and US-government-oriented profile sources enumerate their categories/subcategories, compartments, dissemination controls, releasability groups, and export-control rules. Phase 0 records this signing contract and does not fabricate a key ID, digest, or signature before a release candidate exists.

Effective label is the least upper bound of sensitivity plus the union of source, explicit, container, handling, compartment, dissemination, releasability, and export restrictions. No derivation can lower a source. Unknown/incomparable values deny until policy resolves them.

Repositories, tracker repositories, docs repositories, package namespaces, runner pools, caches, artifact stores, backup sets, and deployment domains are enforcement containers. Per-item markings cannot grant finer read access than a cloneable/provider container. Different access, classification, compartment, retention, or lifecycle requires a separate container.

Deployment security domains use [a machine-readable profile](../../policies/deployment-domains/domain-profile.schema.json) to bind a classification ceiling to allowed label profiles, integrations, notification channels, storage/residency, backup domains, runner pools/images, and network egress policy. Inputs outside that declared domain deny.

Lowering/declassification/decontrol is denied by default, requires authority and written reason, is audited, invalidates caches/search/notifications/exports, triggers reconciliation, and uses two-person approval under the government profile. Core Stead performs no cross-domain/write-down transfer.

Profile upgrades run lattice property tests, full decision tables, signature verification, derived-resource recalculation, non-disclosure checks, and rollback rehearsal. A profile cannot claim compliance, accreditation, or FIPS validation merely because the deployment can select validated cryptographic modules.
