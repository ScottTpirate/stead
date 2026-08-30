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

`measure:bundle` reports exact level-9 gzip bytes for the eager entry graph and for Docs
editor, Code, Delivery, Administration, Migration, and analytics boundaries. The eager
delta is measured against the merged 60,808-byte minimal shell baseline; each newly
introduced lazy boundary has a zero-byte baseline. The 250 KiB eager ceiling remains an
absolute failure.

The `stead:performance` browser event contains only an allowlisted metric name, numeric
value, and unit. It never contains a route, resource ID, query, title, body, token, policy
input, or profile ID. Platform transport observations likewise expose only operation ID,
duration, status, and response byte count.

Two gates deliberately remain outside this branch:

- `DEP-APP-DEVLANE-SOURCE-7719DCAD` authorizes only an inert source reference with no
  distributed artifact. Devlane code/assets cannot be imported until WS-01 records and
  independently approves the exact proposed distribution and file-level provenance.
- Vitest, React Testing Library, Playwright, and axe are not approved or installed. The
  dependency-free Node tests cover generated operations, transport boundaries, query-state
  invalidation, canonical IA, semantic hooks, lazy imports, and ontology/provider guards;
  they do not claim the required browser, accessibility, or visual-regression evidence.
