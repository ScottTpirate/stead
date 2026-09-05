# providers/gitea

Inactive WS-03 stock Gitea adapter, using only Go's existing standard library.
There is **no exported network constructor or dispatcher**, API/worker wiring,
credential loader, or permission assertion. WS-06 consumed-handle enforcement
must be integrated before application calls. Provider tokens are not Stead
authorization. Ordinary UI reads remain local-projection-backed.

The private executor supports one bounded call for each of:

- Private initialized repository creation and repository lookup.
- Issue creation, lookup, body-only `content_version` edit, first ten issues.
- Main-branch root Markdown file creation, lookup and blob-SHA conditional update.

`RepositoryRef`, `IssueRef`, `IssueRevision`, `MarkdownRef`, and `BlobRevision`
are opaque backend values. They cannot be manufactured by another package and
have redacted formatting; they are neither canonical IDs nor authorization.
Returned Issue/Markdown content is protected data, not logging material.
No provider URLs, error bodies, credentials, headers or cursors are returned.

The first profile is deliberately restricted to numeric-port HTTP on
`127.0.0.1`, as exercised in the isolated synthetic probe. It is not a remote
production/TLS profile. Five-second calls have bounded headers/body, no proxy,
cookie jar, compression, redirects, connection reuse, automatic retry, follow-up
GET, Link following or background execution. Payloads are bounded UTF-8; IDs and
versions use exact `int64`, never JSON float64 conversion. The first issue page
is explicitly incomplete and cannot be used as a full reconciliation inventory.

Nil error means one validated authoritative response; it does **not** mean the
Stead transaction, projection, audit/outbox, final fence or effect lifecycle has
committed. `CallError.Completion()` distinguishes pre-dispatch failure, failed
read, provider rejection, body-edit version conflict, and uncertain write.
Uncertain includes timeout/disconnect, redirects, invalid success responses,
server failures and generic file 422. No write is replayed, and no failure grants
reuse of a consumed effect handle. Recovery needs its own fresh authorization.
Successful mutation responses supply the initial result without a verification
read. Markdown SHA is content CAS (not whole-branch/ABA protection); issue edits
send only body plus version because stock multi-field edits are not atomic.

Evidence and limits: operations are based on the documented stock REST routes
in upstream `cf0f4dce72a8799e8afe5307be7470caf6936dba`, the exact successor
backend SHA-256 `baa9f7f8d3acd4e92e9e009d4e1356377a4371074a16d207a92b309f907eec68`,
and the retained successful 28-call isolated probe. The probe already showed
stale Markdown SHA rejection, but **not** stale issue-version rejection. The
pinned `routers/api/v1/repo/issue.go` and `models/issues/issue_update.go` implement
the body-only precheck/transactional CAS and increment even on identical content;
the opt-in consumer adds actual stale-version verification. No upstream source
was copied/imported. [Official API usage](https://docs.gitea.com/development/api-usage/).

Run the synthetic HTTP contract tests with the pinned Go toolchain:

```sh
scripts/run_pinned_go.sh go test -race ./providers/gitea
```

`real_contract_test.go` is Linux-only and excluded unless built with
`-tags=gitea_contract`. It must **not** run against an existing installation.
After independent exact review, the existing private probe controller must add
the compiled test binary to its reviewed input manifest, launch a fresh isolated
fixture and supply `/state/adapter-contract.json` (0600, current UID) with exactly
`owner: "probe-admin"`, `admin_token` and a distinct no-grant `denied_token`.
The controller's existing private `/state/launch.json` is required, with a
different host network namespace; the consumer requires loopback-only networking
and explicit `STEAD_GITEA_CONTRACT=isolated-synthetic-v1`. It uses fixed fresh
`stead-adapter-tracker`/`stead-adapter-docs` names and never creates credentials,
launches services, removes repositories, or records response secrets. It logs
only method/status checks and aggregate call counts. Compiling it is not a live
provider-contract pass. The consumer has not yet been executed.

This slice does not complete P1-003: hidden Project mappings, board/labels,
permission sync, durable permits, bounded read scopes/claims, projections,
webhooks, reconciliation and provider-version matrix remain separate real
producer/consumer integrations, not empty scaffolds in this package.
