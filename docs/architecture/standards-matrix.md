# Standards matrix

| Surface | Required profile | Phase 0 source | Compatibility gate |
|---|---|---|---|
| HTTP API | OpenAPI 3.1.1, JSON Schema 2020-12, RFC 9457, UUIDv7, ETag | `specs/openapi/platform-v1.yaml` | lint, reference resolution, breaking-change detection |
| Domain/export | OWGP 0.1, JSON Schema, OSLC/PROV mappings | `specs/work-graph-profile/` | validate examples; stable-ID/relationship/label round trip |
| Events | CloudEvents 1.0, AsyncAPI 3.1.x | `specs/asyncapi/platform.yaml` | schema, replay, idempotency, version coexistence |
| Knowledge | Git, Markdown, OKF 0.2-compatible profile | knowledge contract | deterministic parse/write, safe rendering, Git round trip |
| Identity | OIDC, SCIM 2.0 | authorization contract | provider and trusted-attribute tests |
| Telemetry | OpenTelemetry/OTLP | observability contract | context propagation and sensitive-data exclusion |
| Artifacts | OCI, SPDX, SLSA-compatible provenance | artifact contract | digest, SBOM, signature/provenance verification |
| Security evidence | OSCAL 1.1.x | `specs/oscal/` planned profile | schema and claims review; no compliance assertion |
| Agent interoperability | MCP; future A2A/Agent Card | `specs/mcp/`, `specs/a2a/` | Platform API/policy reuse and runtime neutrality |

Mappings are profiles, not mandates for RDF/SPARQL, XACML, a graph database, cloud service, or vendor runtime. Version changes use compatibility windows and contract tests.
