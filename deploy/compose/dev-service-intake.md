# Checkpoint A non-distributed development service intake

Status: **pending distinct architecture/license and security review**. Requester:
`/root/local_inventory`. This record is not self-approval, a production exception,
a scanner suppression, or permission to activate a policy. The service manifest
remains fail-closed. Reviewer decisions bind the exact candidate commit.

## Scope and review units

One combined development-infrastructure slice under `REVIEW-NONRUNTIME`:

1. OpenFGA 1.19.0 rebuilt from unchanged upstream source with approved Go 1.27.0;
   stock NATS 2.14.6 scratch image; existing rootless host prerequisites.
2. Stock Gitea 1.27.3-rootless, **startup/migration and health only**. No Gitea
   account, repository, provider mutation/read, SSH, Git protocol, upload, import,
   mirror, action, package, extension or production input is approved here.

All service state is fresh local synthetic data with disposable per-install
credentials. PostgreSQL uses separate databases/roles; OpenFGA requires a private
service token; NATS has one application account and separate scoped roles.
The browser receives no infrastructure credential or direct infrastructure API.
Every listener is literal loopback. Namespaces, read-only image mounts, explicit
data/config mounts and dropped capabilities reduce accidental access; shared host
networking is **not** an egress or hostile-local-user security boundary.

These images, source trees, prerequisite binaries, internal inventories and
notices are excluded from every Stead product/release/SBOM/installer/air-gap
artifact. They are acquired locally, not bundled. No production, commercial
hosting, customer data, deployment, CI handling of untrusted changes, or release
use is covered. The strict runtime/release gate is unchanged. Stop and reopen
review before any expanded use, dependency/configuration change or nonlocal bind.

## Exact identity and provenance

| Component | Immutable candidate |
|---|---|
| PostgreSQL | Already independently approved `DEP-APP-OCI-CHAINGUARD-POSTGRES-18-6-R2-99982050`; linux/amd64 manifest `f9fe3c8946c2f696d9835598a46bc584350acb925028ea1a47977ad9b93bd7c4`. Also supplies the identical read-only base filesystem for the static OpenFGA binary; this bounded additional use is included in this request. |
| OpenFGA | Upstream `130c30aea5e73543e63b173dadfbd1ee519aa97a`, v1.19.0, unchanged `go.mod`/`go.sum`, `CGO_ENABLED=0`, `-mod=readonly -trimpath`, upstream version/commit/date linker values. Result SHA256 `2f90d6f9a1b3a5c92fb114006f41dbe48edd59877cf068bae648a232b4342dec`; independent clean source builds reproduced identical bytes. Apache-2.0 main source; 141 linked module identities. |
| NATS | Official registry scratch manifest `190ba625ec25f1eab47e4215f064067a924e548a3428ae226ec23d32a122b03f`, index `d4a8980c1ee558257f196f86693ec919c7a8b8095dd678e2cb5ff1adcfe03ecb`, source `1aa10f9fe4e7a27b7d877af004a9c0022fdc4910`, binary `2d0dc83e0547185a6820377114215d6a7c645f607aeb31728fffaf3d84e77c10`. Go 1.26.7/CGO0; Apache-2.0 main; 9 linked modules. Official BuildKit provenance identifies docker-library builder, exact nats-docker `e55a3d1604e9fcd5b5b988b1ab68948d033a4708` scratch recipe and pinned staging input. This is registry provenance evidence, not a claimed verified Sigstore signature. |
| Gitea | Official rootless manifest `95b0ae18fb99b4a579b3dd383ea5ad8d8f77534c030c1fe554e6378ac8a5c496`, index `1c17ecaead42eb3b5391553d8708103a4beb0e86edf5b9ebc1eb269c318845f2`, source `146cc3eec57174711eac0e0a0c7b38670c6e3922`, binary `b99d2dc94c4d2ea489c9b62da108a9923222505c0d4f54340e064beef51c6fe6`. Go1.26.7/CGO0/jsonv2; binary reports upstream generated-tree `vcs.modified=true`, not a Stead source patch. Main MIT license SHA256 `ed2f10a9d78b8c6c9ef33f1420d0eb266981891caf2f15d630553f02dc60d3ae`; 249 linked modules and 71 APK packages. No independently verified image signing claim. |

All platform manifest/config/layer digests were recomputed on acquisition. The
371 distinct Go module identities across these binaries matched Go proxy/sumdb
module checksums with zero mismatches. The retained inventory includes exact
versions, origin commits, license and NOTICE file bytes and hashes; it is not
just top-level project metadata. Gitea APK inventory retains exact package
versions and 26 distinct license expressions, including copyleft OS utilities.

## License findings and obligations

The ordinary permissive and MPL components remain wholly non-distributed. Source
license heuristics are evidence, not approvals. The supplement resolves missed
filename/punctuation cases: `davecgh/go-spew` ISC; `mikelolasagasti/xz` 0BSD;
`mrjones/oauth` MIT; `sorairolake/lzip-go` Apache-2.0 OR MIT; `zeebo/blake3` CC0-1.0.
`opencontainers/go-digest` code is Apache-2.0; its CC-BY-SA-4.0 documentation is
not linked into a service. `xi2/xz` has an explicit custom public-domain dedication
by Michael Cross, Lasse Collin and Igor Pavlov; independent legal/policy review
must interpret that declaration, not mark it permissive by scanner fiat.

Gitea actually links `github.com/couchbase/goutils v0.3.0` BUSL-1.1 logging source
(upstream `7185fbe6a4c3d46bb034f0e244cd8d98d0194b31`; module sum
`h1:rsv72B6BDjW9jmwlfiDUrdu3EpNvPuo5WLULHzQ0DLE=`). The exact license explicitly
grants non-production use. This request relies only on that grant, **not** the
restricted Additional Use Grant and not the future Apache change date. The full
[unaltered Couchbase license](notices/goutils-v0.3.0-BUSL-1.1.txt) is conspicuous
beside this launcher and must accompany each local Gitea cache/data copy. No
Gitea source is forked or copied into Stead modules. If the distinct legal/policy
review finds this use needs an exception, hold it for the required owner/ADR
path; this record cannot grant one.

## Vulnerability assessment for the exact use

Trivy 0.74.0 database updated 2026-09-04T13:08:55Z, next update
2026-09-05T13:08Z. Govulncheck 1.7.0 uses database modified
2026-09-02T19:12:04Z. Recheck freshness before activation; JSON exit status alone
is not a clean result.

| Candidate/findings | Actual context, proposed disposition for independent review |
|---|---|
| OpenFGA official image High findings | Not reused: Go1.26.5 standard-library/optional grpc-health-probe findings prompted the exact unmodified Go1.27 rebuild. Actual rebuilt binary has zero module/package/symbol findings; PostgreSQL base retains its separately reviewed Medium-only finding. |
| NATS three Unknown x/crypto findings | GO-2026-5932/OpenPGP, GO-2026-6354 and GO-2026-6355/SSH are module-only: affected packages and symbols are absent from the actual binary. No SSH/OpenPGP feature is invoked. Trivy has zero Critical/High. |
| Gitea Critical CVE-2026-60002 openssh-keygen and CVE-2026-56854 x/crypto/ssh | Inapplicable to this path: stock rootless entrypoint launches no sshd; `DISABLE_SSH=true` forces builtin false (`modules/setting/ssh.go`) and `modules/ssh/init.go` exits before server/key setup. Outbound Git SSH is blocked with `GIT_SSH_COMMAND=/bin/false`; imports/mirrors are disabled and no repository/account is created. No keygen, SSH client, forwarding, SFTP, SCP or server authentication executes. Related SSH High/Medium/Unknown findings have the same disabled path. |
| Gitea OpenSSL QUIC/CMP/CMS/DTLS findings and curl/libcurl Unknowns | Gitea is a CGO0 plain internal HTTP service; no QUIC/DTLS/CMP/CMS server or network curl/Git transfer occurs. Rootless setup uses local shell/config writes only. Health calls only PostgreSQL/cache. No remote credentials, ambient authentication, outgoing server or untrusted input is supplied to these OS clients. |
| Gitea Expat High/Medium, go-git High/Medium, x/image VP8L High | No XML import, repository clone/checkout/content, archive, image/avatar upload or renderer is exercised. Authentication is required, registration and uploads are disabled, and there are zero Gitea accounts/repositories on this path. These are not accepted for future provider/content use. |
| Gitea x/mod sumdb High, gRPC High, OpenPGP Unknown | No module/package service, external sumdb, actions/runner/gRPC endpoint, signing/key input or provider repository operation is used; packages/actions are disabled. |
| Gitea x/text High and GO-2026-5841 s2 dictionary | Symbol findings are real, not suppressed: malformed UTF-8 normalization and attacker dictionaries are excluded by the health-only fixed ASCII request/empty synthetic-state scope. No claimed general Gitea safety; a local trusted developer can still call other loopback routes, which is outside this acceptance scope. |

Gitea has 2 Critical and 13 High Trivy package findings and 12 govulncheck
module/package/symbol advisory groups. No aggregate clean-image claim is made.
Exact stock `routers/web/healthcheck/check.go` executes database/cache ping and
fixed JSON serialization; it does not execute the listed content features.
Before P1-003 creates its first provider object, these findings and dependency
closure **must** be reassessed for the expanded reachable path.

## Existing host prerequisite scope

Arch signature-validated installed packages: bubblewrap0.11.2-1
LGPL-2.0-or-later (`/usr/bin/bwrap` SHA256
`6ad2138a73d592acb43525432965e3c66f6fad8a2f3d610c6ca0b6855e993cbe`),
tar1.35-5 GPL-3.0-or-later (`8bd961dfeee3543f158f550566a66e78c713a9ad5b88432bab93b63f2bb9347c`),
git2.55.0-1 GPL-2.0-only (`93473c28694fd72bd889364107cd2770514de59780885a6a4aafca4d602e30ad`).
All three executables are root-owned0755, not setuid. Package integrity checks
report ownership differences on shared container directories only, not modified
executables. Node/Go remain the repository-approved pinned wrappers. No host
package, Docker ACL/group, sudo permission or TLS trust-store modification occurs.

The [Arch tar](https://security.archlinux.org/package/tar) and
[Git](https://security.archlinux.org/package/git) trackers plus
[upstream Git advisories](https://github.com/git/git/security/advisories) were
checked on2026-09-05; their listed findings are fixed before these exact versions.
Host tar consumes only hash-verified fixed archives with traversal checks; Git
uses fixed HTTPS upstream sources/commits and no untrusted repository/config.

Fresh upstream review found bwrap High
[GHSA-pxhw-h44j-8pfx](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx),
fixed0.12.0: setup-time creation through attacker-controlled image symlinks may
escape via `/oldroot`. It is not a runtime escape. This proposed inapplicability
is **only** for the actual fixed digest-verified stock images, fresh private
synthetic state, fixed mount destinations and no attacker-controlled files or
arguments. It is not a residual-risk waiver or general bwrap approval. Stop if
any such input can reach setup; do not extend this path to imports/untrusted PRs.
The older setuid advisory is fixed in0.11.2 and setuid is not used. Prefer a
separately reviewed0.12+ prerequisite when available; do not silently install it.

## Evidence, rollback and activation

Original private archive SHA256
`4caaf53c565ecfa601305738a37aba06f4305e798307acba882e286b1921117f`
contains source inventory `ce9a0f15b345039cb6854abbd1ae327278d75c4eaaed47fd6cdc376fa9ab29bf`,
all scanner JSON and exact binary module manifests. Supplement
`2626be2d0fbcef47aa20daf69a6183e17ea689aeddf5b02ecbf75cea2ea1af28`
adds full missed licenses, exact BUSL file headers and APK inventory. Neither
contains credentials. Reviewers have the private archive and exact source trees;
do not publish private fixture databases or credentials as review evidence.

Combined review archive v2 SHA256
`459b44b88181fe1822152549482f640cd52b6df4d85d2b36b068aa721bdcfd51`
preserves the original reports plus supplement and exact linux/amd64 NATS
provenance (`b7e8d1c0c7bc4340952cacfd9988a666e09a40195c24d9cccc5b7f32f3ce571e`).

Actual four-service proof passed stock Gitea/PostgreSQL health and OpenFGA401/200.
Distinct auth protocol check passed30 real HTTP calls: exact model readback,
idempotent tuple writes, Team direct roles, and hierarchy/owning-Team
noninheritance. Actual worker/NATS proof passed authenticated200, wrong-password503,
broker-down503, bounded SIGTERM and clean ports. This proves transport/protocol
integration, not outbox delivery, policy activation or Checkpoint A completion.

There is no prior accepted Gitea/FGA/NATS dev-stack rollback version. Rollback is
`down`/disable the launcher while preserving private state, reverting only this
slice, and re-evaluating a fresh candidate. Do not downgrade/reuse a rejected
image or destroy data. Review expires on scope/version/source/config changes,
new applicable advisory, or the Checkpoint A to P1-003 boundary. Normal `up`
may be enabled only after distinct approvals, notice installation and actual
API/bootstrap integration; a metadata flag alone is not approval evidence.
