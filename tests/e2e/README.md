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
