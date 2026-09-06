# tests/e2e

`checkpoint_a_browser.mjs` is the WS-13 real Checkpoint A browser entry point;
`checkpoint_a_browser_journey.mjs` drives the implemented UI through its generated
Platform API client. Neither file launches anything when imported. Ordinary CI
runs only the dependency-free owned-fixture boundary tests.

The opt-in command is:

```sh
STEAD_BROWSER_REVIEW=/absolute/private/accepted-review.json make checkpoint-a-browser
```

Do not run it until distinct non-author QA, security and architecture/license
reviews accept the exact source, private tool closure and **new real workload**.
The controller does not create or approve that record. Prior compatibility-only
acceptance is not real-workload admission. There are no downloads or additional
runtime dependencies; absent or changed approved local tools fail closed.
The carried manifest pins 512 browser/native files and 15 host baseline inputs;
it is not a complete host toolchain inventory. The already installed Git/Make
remain ordinary trusted operator/source-inspection prerequisites. Read-only Git
inspection disables external diff, fsmonitor, untracked-cache and global/system
configuration; it does not install a new Git dependency framework.

The private 0600 record has the closed `stead-checkpoint-a-browser-admission-v1`
shape in `validateAdmission` (scripts/checkpoint_a_browser_boundary.mjs):
`status: accepted`, `scope: one-fresh-real-checkpoint-a-browser-run`, UTC
`expiresAt` within 24 hours; separate exact clean `harness` repository/HEAD/tree
and five runtime-file hashes; exact application `source` repository/HEAD, implementation
revision/tree, approved-template/review and API binary SHA256s; exact `instance`
state directory, UUID, bootstrap, activation and public certificate digests;
the five `SOURCE_FILES` hashes; three distinct review roles
(`security`, `qa`, `architecture-license`) with reviewer identity, exact retained
evidence path/hash, `independentNonAuthor: true` and `disposition: accept`.
The record contains no credentials. Run the command from the reviewed harness
checkout; `source.repository` names the independently frozen application checkout.
The application's only permitted differences from its approved implementation
revision remain the two existing template approval records. Harness fixes do not
replace the running application, renew its activation or change its state. Both
clean source identities and the exact harness files are checked before and after
execution; results distinguish application and harness revisions. A fresh supported running.json,
supervisor identity, canonical bootstrap, API binary and TLS peer must match.
The two real listener processes must be direct children of that supervisor,
with fixed argv/current cwd, unchanged PID/start identities, matching executable
inodes and hashes, and ownership of the unique literal-loopback API/BFF socket
inodes. BFF argv binds the exact assets and fresh TLS paths. Its retained asset-root
descriptor must also match the current verified directory device/inode; replacing
the pathname cannot relabel an older opened root as the new build. Before and after the
run, every served dist file (including the hidden Vite manifest) must match the
existing committed frontend bundle inventory with no extra/missing entries.
No process environment is read; this is fresh-demo source attribution, not a
new attestation claim against malicious same-user host manipulation.
This is not a template activation bypass, source rebuild or instance provisioner.
Admission reviewers may import the nonauthorizing `verifyInputs`, `verifyHarness`
and `verifyIdentity` read-only diagnostics to exercise the actual preflight code.
These do not request TLS/HTTP, acquire credentials, claim an attempt or launch a browser.

Use a newly initialized, independently reviewed synthetic instance with two
unused one-time credentials. The old `/home/skilgore/stead/.cache/stead-dev`
installation is forbidden. Before credential acquisition, an exclusive fsynced
`checkpoint-a-browser-attempt.json` is written in the fresh state. A failed or
interrupted attempt is **not retried automatically**. Preserve it and obtain a
freshly reviewed instance for a new attempt; do not delete the marker to retry.

The namespace mounts only exact read-only tool/source files, its new public
certificate, a private result directory and one Unix byte relay. Credentials
travel once through stdin; no credential file, private TLS key, host trust store,
service configuration, provider data or host home is mounted. Browser HOME/NSS
and profiles are tmpfs. The only host connection is literal 127.0.0.1:18443;
the relay does not terminate TLS or implement CONNECT/SOCKS. Chromium's nested
user-namespace and seccomp sandbox remain enabled. No display, DBus, GPU or
device/driver tree is exposed. Both inherited core limits are zero.
The self-signed local server certificate is imported as an NSS trusted peer
(`P,,`), not a certificate authority (`C,,`), following
[Chromium's Linux certificate guidance](https://chromium.googlesource.com/chromium/src/+/master/docs/linux/cert_management.md).

The journey creates one Organization, parent/child Teams and general Project,
reads their details, reloads/refreshes, checks keyboard navigation and observes
the separate no-grant user's empty views and generic denied creation. It never
uses mock routes or API/test-auth hooks. Axe runs from the pinned 4.13.0 artifact
in a CDP isolated world with the actual product CSP preserved and CSP-blocked
unsafe eval disabled; a boolean-only eval/Function negative control must pass in
each exact audited world before axe. No script tag, bypassCSP or product policy change is used.
That exact instrumentation still requires successful actual execution, not just
syntax validation. Findings retain only bounded rule/impact/count metadata.

The command reports a private generated result directory containing closed
JSON proof and unchanged public/tool execution copies. The authorized exception
is **private preservation of the two established BFF session cookies**, never
the one-time setup credentials. After each completed login response, and with
one bounded observation fallback before browser closure if needed, the runner
reads cookies only for the fixed origin. It requires exactly one host-only
`__Host-stead_session`, Secure/HttpOnly/Strict, path `/`, a canonical 43-character
value and finite unexpired lifetime. The 0700 work directory receives exclusive
fsynced 0600 `checkpoint-a-cookie.json` and `unprivileged-session-cookie` files
in the existing `{origin,cookie}` format, plus separate private role/instance/
source/admission/expiry bindings. Partial files are retained and never overwritten.
The parent validates both files; proof contains only closed preservation states,
not cookie values, hashes or bindings. Absence/forced-kill ambiguity never proves
the setup credential unused and never authorizes login replay. These private
cookies may support separately authorized follow-on checks; this command does
not reuse them automatically or establish a restart/lifecycle test pass.

It never retains native stdout/stderr, DOM, screenshots, traces, one-time tokens,
headers, response bodies or exception messages. It closes the browser and namespace/relay; it neither
logs out nor stops/changes the host Stead stack. JS strings cannot be zeroized;
process and tmpfs disposal are part of the confinement, not a zeroization claim.

A completed UI journey is **not** proof of SQL/query counts, OpenFGA/provider
calls, audit/outbox durability, hierarchy authorization, known/unknown existence
nondisclosure, complete accessibility, TEST-009 or a release gate. Those require
separate actual backend inspection and release evidence. Sparse-access discovery
and provider integration are not implemented by this runner.

## Established-session SDK follow-on candidate

`scripts/checkpoint_a_followon.mjs` is a separate, test-only, dependency-free
GET workload. Its source needs independent QA/security review before actual
execution; browser-workload acceptance alone does not approve this command.
Importing it and running its synthetic unit tests do not access live services.

After the real browser attempt, provide its **private work directory**, its
accepted admission, the exact fresh application checkout, and a private 0600
JSON input containing six distinct UUIDv7 fields: `known_organization`,
`unknown_organization`, `known_team`, `unknown_team`, `known_project`,
`unknown_project`. Obtain known IDs through authorized Stead reads; the
independent PostgreSQL check must separately establish existence/absence.

```sh
env -i PATH=/usr/bin LANG=C.UTF-8 TZ=UTC \
  /tmp/stead-node-toolchain-26.8.1/toolchain/node-v26.8.1-linux-x64/bin/node \
  scripts/checkpoint_a_followon.mjs --live \
  --checkout /absolute/fresh/application-checkout \
  --browser-work /absolute/private/browser-run/work \
  --admission /absolute/private/browser-admission.json \
  --resources /absolute/private/resource-ids.json
```

No fallback token, login, logout, mutation, browser launch, provider, service
control, arbitrary SQL, download, or HTTP retry exists in this runner. Missing,
partial, stale, foreign or mismatched handoffs fail closed; it does not copy
cookies into the application state. Actual GET /session must match each
expected principal/instance and completed exchange revision, and preserve the
cookie's existing expiry. Require more than two minutes of remaining session
life. The current bootstrap sessions last eight hours; the initial activation
lasts 24 hours, and this command cannot renew either.

Four independent serial transports/SDK observation buffers issue 80 requests
in total: session checks before and after, and three rounds of known/unknown
Organization/Team/Project reads. Two workers use the authorized principal and
two use the no-grant principal. The client in-flight maximum is measured, not
server parallelism. Each completed HTTP correlation is joined to exactly one
matching API observation, retaining the existing numeric SQL/pool/anchor timing
fields. Unknown/missing counters fail rather than becoming zero. Failed HTTP
or SDK validation preserves the first failing stage and completed observations.
The proof distinguishes transport dispatch attempts, retained safely framed
responses and SDK-validated responses. A completed response rejected by the SDK
still retains its safe correlation/status/byte count; unavailable SDK timing is
`null`, never zero. A transport failure without a safe completed response is an
explicit unobserved dispatch attempt, not evidence that no HTTP request occurred.
Only reading delayed local telemetry is retried, at most four times.

Proof is an exclusive fsynced 0600 file in the supplied private work directory;
it contains resource IDs and request correlations needed for the separate SQL
check, not cookies, response bodies, protected titles or raw errors. Do not
publish it. The console emits only bounded scope/result/dispatch and response counts/file
name. Current application files, existing browser admission and prior browser
input-identity verification are bound before/after the run. The browser's H
revision/tree and source blobs remain pinned separately from application D;
the integration branch may advance after the completed browser attempt without
relabeling that attempt or its session binding. This runner reuses the exact
admitted read-only controller identity checks for current application executables,
process/socket ownership and held frontend distribution before/after its reads.
It does not invoke the controller main, browser tools, relay, or attempt claim.
This is synthetic-demo attribution, not attestation against a malicious host.

This is not browser/reload, list pagination, login/logout lifecycle, restart,
SQL audit persistence, outbox delivery, timing-nondisclosure, physical network
round-trip/server-lock measurement, product performance, or Phase 1 acceptance.
The unit command is `scripts/run_pinned_node.sh node --test
scripts/checkpoint_a_followon.test.mjs` and is included in foundation-check.

## Fixed resource discovery candidate

After separate exact-source execution review, a **successful** browser run with
both preserved sessions can supply the follow-on's private six-ID input using:

```sh
ulimit -S -c 0 && ulimit -H -c 0 && \
exec env -i PATH=/usr/bin LANG=C.UTF-8 TZ=UTC \
  /tmp/stead-node-toolchain-26.8.1/toolchain/node-v26.8.1-linux-x64/bin/node \
  scripts/checkpoint_a_discovery.mjs --live \
  --checkout /absolute/fresh/application-checkout \
  --browser-work /absolute/private/browser-run/work \
  --admission /absolute/private/browser-admission.json
```

Run this exact reviewed launch in a disposable shell from the clean harness
checkout. Clearing the environment before Node starts prevents inherited
NODE_OPTIONS/preloads and NODE_DEBUG from exposing cookie-bearing requests;
disabling both core limits prevents a later child from raising the soft limit.
The script cannot undo a preload or debug hook installed before it starts.

Five GETs only: verify both current sessions, then read one page of 20 each for
Organizations, Teams and Projects. BJA7ORG/BJA7PAR/BJA7CHD must be unique and the
child must reference the parent. Project.key is not exposed by this API, so the
unique exact browser fixture title/purpose, Organization, owning child and
Work/Docs-only capabilities/areas are checked; BJA7PRJ key and creation provenance
remain unproven. Any continuation/missing/duplicate match fails, without retry.
The private work directory receives exclusive fsynced 0600
`checkpoint-a-discovery.json` (closed correlations/counts/bindings) and, only on
success, `checkpoint-a-discovered-resources.json` (six UUIDv7 IDs). Existing files
are never overwritten. Synthetic unknown IDs are **not** evidence of absence;
the separate SQL check must establish that. No cookie/body/error is published,
and no login/logout, mutation, SQL, provider, browser or service action exists.
The failed browser attempts so far do not satisfy this command's prerequisites.

## Credential-free real-shell keyboard diagnostic

`scripts/checkpoint_a_keyboard.mjs` is a separate diagnostic for the current
login shell's unchanged CommandPalette, not a retry of the failed authenticated
journey. It needs exact non-author architecture/license, QA and security reviews
using `stead-checkpoint-a-keyboard-admission-v1`, scope
`one-credential-free-real-shell-keyboard-diagnostic`, and the eleven
`KEYBOARD_SOURCE_FILES` pins. Reuse the existing closed source/instance/reviewer
fields, but never relabel a browser or TLS admission. A new private exclusive
`<admission>.keyboard-attempt.json` sidecar permits one attempt; the application
browser marker and all retained data/sessions remain untouched.

From the clean reviewed harness checkout, after exact execution admission:

```sh
STEAD_KEYBOARD_REVIEW=/absolute/private/accepted-keyboard.json make checkpoint-a-keyboard
```

The recipe clears the environment before pinned Node starts and sets both core
limits to zero. Existing 512+15 input hashes, approved application D/source
bindings, actual process/listener/asset-root identity, public certificate and
staged bytes are checked before/after. No new application build/activation is
inferred when only the harness advances. The namespace reuses fixed P,, peer
trust, normal TLS/CSP/renderer sandbox, and the literal-loopback BFF byte relay.
There is no stdin, setup-token, session-cookie, private-key or host-trust ingress.

Two empty contexts/pages are created in the original order; only the first
navigates. Allowed requests are one GET `/`, each exact committed JS/CSS asset
at most once, and one GET `/api/v1/session` with expected 401. No Cookie,
Authorization, Set-Cookie, redirect, arbitrary API, login, mutation or download
is accepted. Routing is secondary assertion, not generic redirect interception;
the exact Stead static/session handlers must remain nonredirecting. The probe
does not focus the page forward, add sleeps, patch the DOM or change the app.

The original open/audit/Escape/return-focus/reopen/filter/Tab/Enter/route/skip
actions record finite substep IDs and dialog/focus/visibility booleans only,
including the first failed substep. No DOM, screenshot, selectors, raw exception,
headers, bodies, credentials or native stdout/stderr is retained. The outer
proof preserves the actual child exit/signal as well as closed inner evidence;
absence cannot become a successful exit. No automatic retry. Preserve failures
and independently inspect post-run cleanup and exact runtime/input continuity.

Axe is executed in the existing CSP-preserving isolated world only to reproduce
the original keyboard-stage ordering; this probe is not an accessibility audit,
authenticated/denied journey, Checkpoint A or Phase 1 pass. If the anonymous
shell does not reproduce the fault, do not infer the authenticated path fixed.
Owned synthetic tests are `scripts/run_pinned_node.sh node --test
scripts/checkpoint_a_keyboard.test.mjs`; they perform no live/browser operation.

## Credential-free real-origin TLS diagnostic

`scripts/checkpoint_a_tls.mjs` and `tests/e2e/checkpoint_a_tls.mjs` diagnose the
actual fresh BFF certificate without consuming a browser journey or session.
They require separate exact-source, tool-closure, instance and three distinct
non-author review dispositions before execution; they do not create approvals.
Use `STEAD_TLS_REVIEW=/absolute/private/accepted-tls-review.json make checkpoint-a-tls`.
Imports and `scripts/run_pinned_node.sh node --test scripts/checkpoint_a_tls.test.mjs`
run no live browser/native/service action. The test is in foundation-check.

The private 0600 admission has the existing closed identity/review fields, but
format `stead-checkpoint-a-tls-admission-v1`, scope
`one-credential-free-real-origin-tls-diagnostic`, and all eight `TLS_SOURCE_FILES`
hashes. It cannot authorize the real browser entrypoint. Its owned 0700 parent
receives an exclusive fsynced `<admission-path>.tls-attempt.json` sidecar before
execution. That diagnostic admission is one-use; the command never reads,
rewrites or removes the application's existing browser attempt marker. Keep
first failures. A new diagnostic requires a separate reviewed admission; it
does not authorize replaying the failed journey's one-time credentials.

The controller reuses the exact 512+15 input checks, separate frozen application
and harness identities, active executable/socket/held-dist checks and fixed byte
relay. Only existing public bootstrap/running/template metadata and the pinned
public certificate are read from the application; never secret service config,
one-time tokens, session/cookie files, private keys or provider state. No stdin
is passed to the namespace. Only the public certificate is added to its staged
fixture inputs: no session binding or credential ingress. Host trust/settings
and the application certificate/keys/state remain unchanged.

Four separate namespace-only HOME/NSS/browser profiles each navigate exactly
one document: untrusted, `C,,` comparison, `P,,` peer, and `P,,` wrong-name.
The wrong-name URL is fixed at `https://stead-wrong-host.invalid:18443/`, resolved
only to the same isolated 127.0.0.1 relay through one fixed Chromium host rule.
The initial-request route checks block non-document requests, assets, scripts,
API calls, methods other than GET and arbitrary hosts. This diagnostic requires
the exact source/binary/dist-pinned application's nonredirecting `/` handler
(`devweb/server.go` serves its static index). Playwright's context route does not
intercept every redirect hop; the final response URL check rejects a redirect
result after the fact, not before that network hop. This is not generic redirect
confinement. Under that exact nonredirecting-handler prerequisite, no Stead
application JavaScript is fetched and no login action occurs. Browser sandboxes, CSP and
normal certificate/hostname verification remain enabled. No certificate-ignore,
insecure-localhost, proxy or host trust flag is available.

The closed private proof records each profile's HTTP status (or null), a fixed
certificate/network failure category, bounded navigation/blocked counts with
explicit overflow, and CSP/sandbox booleans. It never retains raw error text,
native output, DOM, screenshots, response bodies/headers or credentials. A pass
requires untrusted certificate rejection, the peer's actual 200 response with
the exact CSP plus in-world eval/Function negative controls and renderer sandbox,
and wrong-name certificate-name rejection. The CA comparison's actual success
or certificate rejection is retained; it is not forced to confirm the presumed
cause. Missing evidence, unrelated network failures, cleanup failure or changed
inputs fail the diagnostic. This does not prove login, UI interactivity, a
full browser journey, Checkpoint A or a Phase 1 release pass.

## Actual HTTP denial to persisted audit collector


`make checkpoint-a-sql` is a separate test-only, read-only collector. Before live
use, independently review the exact collector/build, completed follow-on report
hash and execution scope; browser/follow-on acceptance does not activate it.

```sh
STEAD_CHECKPOINT_A_ADMISSION=/absolute/private/browser-admission.json \
STEAD_CHECKPOINT_A_ADMISSION_SHA256=<exact-64-lowerhex-file-hash> \
STEAD_CHECKPOINT_A_FOLLOWON=/absolute/private/completed-followon.json \
STEAD_CHECKPOINT_A_FOLLOWON_SHA256=<exact-64-lowerhex-file-hash> \
STEAD_CHECKPOINT_A_SQL_PROOF=/absolute/private/new-sql-proof.json \
make checkpoint-a-sql
```

Owned 0700 parents, exclusive 0600 inputs, exact hashes and no symlink/hardlink
aliases are required; output must not exist. The tagged live test fails missing
prerequisites, never skips, and is absent from ordinary unit selection. Normal
`TestCheckpointEvidence*` tests use only synthetic owned fixtures. The target
disables core dumps. Preserve the exact source/build and first failures privately.

The externally reviewed report hash binds trusted runner output. Ordinary JSON
parsing checks completion, app/instance/harness/admission bindings, six distinct
resource IDs, 80 unique correlations and the 54 read-404 selections (18 primary,
36 no-grant); it does not duplicate the producer's timing/worker/SDK validation.
Pinned existing Node helpers check public runtime/process/dist identity before
and after, with helper bytes verified before import and no browser or HTTP call.

The only secret input is the fresh state's `database-url`: its instance-derived
NOINHERIT API login at fixed `127.0.0.1:15432/stead`, with loopback-development
`sslmode=disable`. PG environment overrides, administrator/service DSNs, other
credentials/configuration, arbitrary SQL, initialization and provider calls are
not allowed. One bounded `REPEATABLE READ READ ONLY` transaction uses fixed
existing authorization/organization/project/audit execute roles and always rolls
back. It verifies namespace identity, three active/nonpending known resources,
three unknown IDs absent across all four canonical sets, and exactly one safe
NULL-resource denial per actual HTTP request ID with correct actor/action and
separate decision identity. Queries bound output and time, not scanned rows.

The exclusive fsynced proof retains hashes, instance, correlations, counts and
booleans—not credentials, raw SQL errors, audit rows, actors or resource names.
This proves only current canonical existence and persisted denial correlation;
not browser-created provenance, timing nondisclosure, outbox delivery, restart,
backup/restore, TEST-009 or Phase 1 acceptance. Missing audit evidence fails the
collector; it never retries HTTP to manufacture a replacement.
