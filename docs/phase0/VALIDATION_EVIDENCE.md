# Phase 0 validation evidence

Status: **Contract checks pass; approval and implementation-dependent tests remain pending**
Executed: 2026-08-29
Scope: reconciled Phase 0 specification and closeout artifacts

This record distinguishes executable contract evidence from future implementation evidence. It does not represent project-owner, architecture, QA, security, compliance, accreditation, or release approval. The `GATE-P0-APPROVED` dispositions in the closeout packet remain pending.

| Check | Command | Result |
|---|---|---|
| Canonical directive inventory | `ruby scripts/generate_directive_inventory.rb` followed by `ruby scripts/validate_phase0.rb` | 128 unique requirement headings; inventory checksum and traceability reciprocity pass. |
| OWGP representative resources | `node scripts/validate_owgp_examples.js` | 15/15 valid examples and six negative fixtures pass semantic checks, including closed label/entity fields, acting-principal restrictions, user/agent-only assignment, mandatory audit authentication/policy context, and event context. |
| Cross-contract structure and references | `ruby scripts/validate_contracts.rb` | 19 primary machine documents parse; filesystem and canonical `$id` references resolve through the checked-in registry; fixed ontology, OpenAPI, AsyncAPI, provider, label/deployment, OPA, migration, and OpenFGA matrix assertions pass. |
| Standalone JSON Schema resolution | `scripts/validate_json_schemas.sh` | All eight JSON Schema 2020-12 roots compile with pinned Ajv CLI 5.0.0 (Ajv 8) and `ajv-formats` 3.0.1 via their registered canonical `$id` values, including OWGP-composed actor, event, OPA-input, and migration schemas. |
| OpenAPI semantic validation | `npx --yes @redocly/cli@2.49.0 lint specs/openapi/platform-v1.yaml --extends=minimal` | Valid with zero errors and zero warnings. The CLI was used as an audit tool and is not a committed product dependency. |
| AsyncAPI semantic validation | `npx --yes @asyncapi/cli@6.0.2 validate specs/asyncapi/platform.yaml` | Valid with no governance issues; 74 event types are schema-bound to exactly one of 19 required channel families, each with send and receive operations. The CLI was used as an audit tool and is not a committed product dependency. |
| OpenFGA executable model | `fga model test --tests policies/openfga/model-tests.yaml` with official CLI v0.7.20 (`53f7369399e29251c0b2f786ac9f6946042d017e`) | 16/16 suites and 80/80 checks pass. |
| Phase 0 integrated gate | `ruby scripts/validate_phase0.rb` | Passes requirements, issues, dependency graph, 13 workstreams, release gate, ADR deadlines, security traceability, required artifacts, local links, agent-runtime scope guard, and nested contract runners. |
| Patch hygiene | `git diff --cached --check` before commit and `git show --check HEAD` after commit | Passes for tracked modifications and every new file. |
| Repository visibility | `gh repo view ScottTpirate/stead --json nameWithOwner,visibility,isPrivate,defaultBranchRef` | `ScottTpirate/stead` is private and uses `main` as the default branch. |

The integrated validator also confirms 33 threat findings, 47 classification-bypass controls, all later-phase issues directly blocked by `GATE-P0-APPROVED`, and no executable Agent runtime files under the reserved Agent module/provider paths.

## Intentionally pending evidence

- Project-owner, WS-01, WS-06, independent QA, and independently identified security approvals on one immutable revision.
- Phase 1 runtime, browser, accessibility, provider, security/classification, performance, backup/restore, and supported-upgrade results.
- Release-candidate signatures, SBOMs, SLSA provenance, policy-bundle digests/key IDs, vulnerability scans, and license-decision evidence for selected implementation dependencies.

Those items cannot truthfully exist in Phase 0 and remain release-blocking at their named gates.
