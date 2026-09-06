# Checkpoint A local service decision

Status: **ACCEPTED for the bounded non-distributed use only**.

- Candidate: `432e89f4cd37075137951d891d822cd8b2524ac9`.
- Author/requester: `/root/local_inventory`.
- Architecture/license-steward: `/root/adr_inspection`, ACCEPT, 2026-09-05.
- Independent security: `/root`, ACCEPT, 2026-09-05.
- Evidence archive SHA256: `459b44b88181fe1822152549482f640cd52b6df4d85d2b36b068aa721bdcfd51`.
- Category: `REVIEW-NONRUNTIME`; no production approval, exception or residual-risk waiver.

These are distinct accountable agent reviews, not GitHub human reviews. The
[candidate intake](dev-service-intake.md) retains the exact versions, binary and
source identities, 371-module inventory, license notices, scan dates, actual
execution restrictions and rollback. Its historical pending status describes
the candidate before these reviews; this decision supplies the disposition.

Architecture/license review independently recomputed the archive and 405 retained
license/notice hashes and checked all 371 module checksums and the 71-package
Gitea APK inventory. The exact Couchbase BUSL-1.1 grant permits this non-production
use; the complete notice must accompany each local Gitea cache and data copy.
The exact xi2/xz dedication is retained as a custom public-domain license, not
silently reclassified as a general permissive production dependency.

Security review independently inspected the actual scanner JSON, pinned Gitea
source, configuration, launcher credential separation and read-only mounts:

- Rebuilt OpenFGA has zero govulncheck findings; NATS's three findings are
  module-only, with affected SSH/OpenPGP packages absent from the binary.
- Gitea's **two Critical and thirteen High** package findings remain recorded.
  The scoped startup/health path disables SSH, registration, uploads, imports,
  mirrors, actions, packages, remote avatars and mail. Stock SSH initialization
  returns before key/server setup when disabled. The inspected health handler
  only pings the synthetic PostgreSQL/cache and serializes fixed response data.
  No Gitea accounts, repositories, content or provider operations are approved.
- The upstream bwrap advisory GHSA-pxhw-h44j-8pfx requires attacker-controlled
  filesystem content during setup; it is not a runtime escape. This launcher
  only mounts the fixed digest-acquired stock files read-only, creates private
  synthetic state, uses fixed mount destinations and drops capabilities. It
  neither accepts untrusted images/arguments nor claims protection from a
  malicious same-user developer. That specific setup prerequisite is absent
  from the accepted use. This is not general acceptance of vulnerable bwrap.
- Exact root-owned, non-setuid bwrap/tar/Git executables are checked. No host
  package, Docker permission, global TLS trust or production system is changed.

Approval is void on a source/version/configuration change, new applicable
advisory, untrusted input, nonlocal listener or expanded Gitea route. Reassess
before the first P1-003 provider object. All acquired binaries, source trees,
state and associated inventories remain outside product/release/SBOM/installer/
air-gap artifacts. Startup remains separately gated by the reviewed signed
bootstrap implementation. Shutdown preserves local state; there is no approved
older stack to downgrade to.
