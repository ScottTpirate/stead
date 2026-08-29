# Deployment and lifecycle profiles

Profiles are `local`, `standard`, `ha`, `air_gap`, and `government`. Docker/Compose and Helm/Kubernetes are first class; no public cloud or SaaS control plane is required. Effective config fixes security domain/ceiling, integrations, storage, notification channels, runner pools, network zones, identity, policy bundles, versions/digests, and backup destinations without exposing secret values. The normative security-domain shape and representative commercial/government values are [machine-readable](../../policies/deployment-domains/domain-profile.schema.json).

Upgrade order is detect → compatibility preflight → consistent backup → expand migrations → safe component order → smoke/golden/security tests → report → contract when safe. Rollback is permitted while schemas remain backward compatible; otherwise an explicit tested forward-recovery plan is required. Air-gap inventory is signed and no-network tested.
