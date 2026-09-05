# Local development service boundary

`P1-DEV-STACK` uses the exact non-distributed candidates in `dev-services.json`.
The rootless Linux amd64 harness requires the existing host `bwrap`, `tar`, `git`
and verified repository Node/Go wrappers. It does not alter Docker permissions,
install host packages, change system trust, or require sudo.

```sh
scripts/run_pinned_node.sh node --test scripts/dev_stack.test.mjs
scripts/run_pinned_node.sh node scripts/dev_stack.mjs probe-infrastructure
```

The explicit intake command creates a fresh private synthetic fixture under
`.cache/stead-intake-*`, acquires and hashes exact platform images, rebuilds the
stock OpenFGA source with the pinned Go toolchain, and exercises real PostgreSQL,
stock Gitea, OpenFGA and NATS. It tests service readiness and OpenFGA authentication,
then stops all processes without deleting fixture data. A bounded
`--hold-seconds=300` supports independent live protocol checks. Intake execution
is **not** independent dependency approval or Stead product activation.

The normal `up`, `down`, `status` and `smoke` command path is staged but remains
fail-closed until exact service intake approvals and the real API/bootstrap,
worker, signed-policy and HTTPS web consumers are integrated. It must not be
reported as seven-service or Checkpoint A acceptance yet. The Docker Compose
variant and Makefile integration remain unimplemented pending that integration.

Normal state is scoped to this checkout's `.cache/stead-dev` directory. Files are
private, secrets are generated per project, normal shutdown preserves data, and
there is no destructive reset command. Each infrastructure process receives a
read-only image filesystem, a separate user/process namespace, no capabilities,
and only its explicit private configuration/data mounts. Rootless service TCP
listeners bind `127.0.0.1`; host networking is shared, so this is a trusted local
developer boundary, not a hostile-local-user or network-egress sandbox. Browser
code receives no infrastructure credentials. Stock Gitea SSH, repository imports,
mirrors, actions, packages and untrusted upload surfaces are disabled for this
candidate's security review scope.

The Gitea binary's transitive source inventory also contains
`github.com/couchbase/goutils v0.3.0` with file-level BSL-1.1. Its explicit
non-production grant is intake evidence, not a production/distribution approval
or an automatic license-policy decision. The Gitea candidate remains pending
scoped license and security review; stock-provider status alone does not approve
its dependency closure.

The two NATS streams and required-consumer registry remain WS-07-owned bootstrap
inputs. This launcher creates one account and scoped service-role credentials;
it does not invent consumer classes or authorize product content.

No image, fixture, source checkout, generated credential, internal image SBOM or
intake evidence belongs in a product image, release, installer or air-gap bundle.
Runtime Stead dependencies retain the strict release notice/SBOM/security gate.
