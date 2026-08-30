# Stead development foundation

This guide covers the bounded `STEAD-P1-001` foundation. It does not authorize a later
Phase 1 issue, provider integration, or a change to the canonical ontology. The normative
architecture remains [`MASTER_BUILD_DIRECTIVE.md`](../architecture/MASTER_BUILD_DIRECTIVE.md),
and issue ownership remains in the machine-readable implementation catalog.

## Toolchain

The repository pins:

| Tool | Version | Use |
|---|---:|---|
| Node.js | `26.8.1` | `stead-web` and local contract validators |
| npm | major `11` | exact workspace lock installation |
| Go | `1.27.0` | `stead-api`, `stead-worker`, and `steadctl` |
| Ruby | `3.4.10` for contributors; CI compatibility floor `3.2.0` | standard-library-only governance and contract validators |

`.tool-versions`, `go.mod`, `package.json`, and `package-lock.json` are the source-controlled
pins. CI executes exact, checksum-bound Node and Go archives without third-party setup actions.
On Linux amd64, `scripts/run_pinned_go.sh` downloads the official archive, verifies SHA-256
`675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685` before execution.
It never overwrites or trusts a host Go toolchain. The executable foundation gate currently
supports Linux x64 only; another platform requires its own reviewed archive and digest.

`scripts/run_pinned_node.sh` applies the same rule to the official Node `26.8.1` Linux x64
archive, verifying archive SHA-256
`3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d`
and extracted binary SHA-256
`19235a9b678f84729464c52623f92de130a165452747c6826d3fdc13df3abcc3`; it never executes
a host `node` or `npm` binary.
CI uses the host runner's Ruby only after checking the documented compatibility floor; the
Ruby validators install no gems and load only the standard library. The repository does not
execute `setup-node`, `setup-go`, or `setup-ruby` actions.

Required host utilities are `bash`, `make`, `curl`, `sha256sum`, and `tar`. Docker is not
required by the foundation. Do not substitute a floating toolchain, action tag, or image.

## First validation

From the repository root:

```bash
scripts/run_pinned_node.sh npm ci --ignore-scripts --no-audit --no-fund
make foundation-check
```

`npm ci` must use the checked-in lockfile. Lifecycle scripts are disabled for the current
dependency set. `make foundation-check` performs Go formatting/vet/test/build, frontend
typecheck/build, JSON Schema/AsyncAPI/OpenAPI validation, the npm vulnerability gate,
dependency/provenance validation, Phase 0 contract validation, the checked-in OpenFGA 1.1
relation-model suite, and the architecture foundation contract. The repository-owned model
evaluator supports exactly the relation forms used by the canonical model, validates tuple
type restrictions, and executes all 16 suites and 80 assertions. The upstream OpenFGA CLI
`0.7.20` is deliberately not downloaded or executed because its current binary dependency
tree does not pass the no-unwaived-High gate. Production OpenFGA remains mandatory; a future
CLI test tool requires its own vulnerability-clean exact approval.

Initial acquisition and `npm audit` require outbound access. Checked-in validators perform
no contract upload. Build logs, telemetry, caches, and artifacts must not contain secrets,
protected bodies, authorization tuples, or classified data.

## Component interfaces

Concrete component names are part of the Stead interface:

| Source | Deployable or command |
|---|---|
| `apps/web` | `stead-web` |
| `apps/core` | `stead-api` |
| `apps/worker` | `stead-worker` |
| `apps/steadctl` | `steadctl` |

The current programs are foundation probes, not feature implementations. They must not
call provider-specific business APIs, bypass canonical Stead APIs, implement authorization
locally, or expose Gitea/Devlane ontology as product contracts.

## Dependency and provenance changes

Every direct dependency, GitHub action, downloaded executable/toolchain, source snapshot,
and separately distributed third-party component needs an exact record in
[`dependency-approvals.yaml`](../governance/dependency-approvals.yaml). The registry is
fail-closed and governed by the
[`license-and-dependency-approval` workflow](../governance/license-and-dependency-approval.md).

The initial 15 exact records are `APPROVED` by distinct independent QA and security
reviewers. The default validator also permits a future branch to carry
`REVIEWED_PENDING_INDEPENDENT_APPROVAL` candidates while checking their pins and boundaries:

```bash
ruby scripts/validate_dependencies.rb
```

Release verification additionally requires every active dependency to have independently
recorded `APPROVED` evidence:

```bash
ruby scripts/validate_dependencies.rb --release
```

Never change a candidate to `APPROVED` as part of its implementation. Independent review
must supply the identities and timestamp. A version, digest, source, license, use,
distribution mode, permissions, or transitive-graph change reopens review. Restore the
previous manifest and lockfile together when rolling back; then rerun audit, contract,
build, notice, and provenance checks.

The initial AsyncAPI validator intentionally uses `@asyncapi/specs`, `yaml`, and AJV rather
than `@asyncapi/cli`; the latter and `ajv-cli` are prohibited direct candidates because
their evaluated dependency trees contained high/critical advisories. Do not reintroduce
them without a new clean evaluation and independent approval.

## Devlane boundary

[`devlane-provenance.yaml`](../governance/devlane-provenance.yaml) pins the upstream commit,
tree, and license blob. No Devlane code or asset has been imported. Before the first import:

1. obtain independent approval for the exact source and proposed distribution;
2. record every source path, destination path, digest, modification, and notice;
3. remove backend, routing, and ontology coupling;
4. verify the frontend uses canonical Stead APIs and product concepts; and
5. run security, accessibility, contract, bundle, and notice tests.

Devlane is a visual/component source, not a Stead ontology or backend. Its MIT notice is
already retained in [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) as a regression
fixture. An update is a new source candidate; rollback restores the last approved import
ledger and retains notices for any derived material that remains distributed.

## CI boundary

`.github/workflows/ci.yml` runs on pull requests and `main`, grants only `contents: read`,
does not persist checkout credentials, disables action caches, pins actions by full commit,
installs the npm lock with lifecycle scripts disabled, and turns off supported telemetry
by default. It receives no Stead deployment secret and does not publish artifacts. Release,
signing, protected-domain runners, cache partitioning, and promotion remain later owned
work and require their own independent gates.

Keep changes short-lived and requirement/test linked. A green foundation check does not
grant authority to cross module ownership or begin a dependency-blocked issue.
