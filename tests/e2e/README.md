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
