# stead-web Wave 0 foundation

This is the original, non-import frontend foundation permitted by live issue #21. It
provides the canonical primary navigation, application shell, same-origin generated API
boundary, authorization-context-aware query store, contract-generated mocks, stable state
primitives, keyboard command navigation, System/Light/Dark tokens, safe browser performance
events, and explicit lazy capability chunks. It implements no domain workflow or browser
authorization decision.

Run the merge-safe checks from the repository root:

```bash
npm run typecheck
npm run test --workspace=@stead/web
npm run build
npm run validate:web-bundle
npm run measure:bundle --workspace=@stead/web
```

`measure:bundle` reports exact uncompressed bytes, level-9 gzip bytes, and SHA-256 digests
for the closed eager entry graph and the complete transitive Docs editor, Code, Delivery,
Administration, Migration, and analytics graphs. The eager static graph must expose exactly
those six roots as its dynamic frontier. Shared lazy chunks appear in every consuming
capability and exactly once in the stable unique total. It also binds the exact distribution
inventory, including HTML, Vite metadata, JavaScript, CSS, and any manifest-declared data
asset. Undeclared files, manifest chunks outside the governed graphs, unsupported binary or
source-map artifacts, and ungoverned HTML/CSS/JSON content fail the check. The eager gzip
delta is measured against the merged 60,808-byte minimal shell baseline; each newly
introduced lazy boundary has a zero-byte gzip baseline. The 250 KiB eager gzip ceiling
remains an absolute failure.

The `stead:performance` browser event contains only an allowlisted metric name, numeric
value, and unit. It never contains a route, resource ID, query, title, body, token, policy
input, or profile ID. Platform transport observations likewise expose only operation ID,
duration, status, and response byte count.

Two gates deliberately remain outside this branch:

- `DEP-APP-DEVLANE-SOURCE-7719DCAD` authorizes only an inert source reference with no
  distributed artifact. Devlane code/assets cannot be imported until WS-01 records and
  independently approves the exact proposed distribution and file-level provenance.
- The exact approved Vitest, React Testing Library, DOM Testing Library, user-event, and
  happy-dom unit harness is installed and covers shell behavior alongside the Node contract
  tests. Playwright and axe remain absent, so this branch does not claim the required real-
  browser accessibility, end-to-end, or visual-regression evidence.
