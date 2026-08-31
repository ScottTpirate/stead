#!/usr/bin/env node

import process from "node:process";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { JSON_LIMITS, parseStrictJson, readStrictJson } from "./strict_json.mjs";

const schemaPaths = [
  "tests/performance/harness/performance-evidence-v1.schema.json",
  "tests/performance/harness/performance-dataset-v1.schema.json",
  "tests/performance/harness/performance-candidate-suite-v1.schema.json",
  "tests/performance/harness/performance-benchmark-artifact-v1.schema.json",
  "tests/performance/harness/performance-runner-output-v1.schema.json",
  "tests/performance/harness/performance-regression-review-v1.schema.json",
  "tests/performance/harness/performance-corpus-v1.schema.json",
  "tests/performance/harness/performance-frontend-baseline-v1.schema.json",
  "tests/performance/harness/performance-reviewer-authorities-v1.schema.json",
];
const evidencePath = "packages/test-fixtures/harness/performance/standard-request-boundary-valid.json";
const datasetPath = "tests/performance/datasets/standard-request-boundary-v1.json";
const baselinePath = "packages/test-fixtures/harness/performance/foundation-shell-baseline.json";
const authoritiesPath = "tests/performance/harness/performance-reviewer-authorities-v1.json";
const readJson = readStrictJson;

const schemas = await Promise.all(schemaPaths.map(readJson));
const [evidence, dataset, baseline, authorities] = await Promise.all([
  readJson(evidencePath),
  readJson(datasetPath),
  readJson(baselinePath),
  readJson(authoritiesPath),
]);
const validators = new Map();

for (const schema of schemas) {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  validators.set(schema.$id, validateWithFreshErrors(ajv.compile(schema)));
}

function validateWithFreshErrors(validate) {
  return (value) => ({ valid: validate(value), errors: structuredClone(validate.errors ?? []) });
}

const failures = [];
const assert = (condition, message) => {
  if (!condition) failures.push(message);
};

const evidenceValidator = validators.get("https://stead.dev/schemas/performance/evidence-v1.schema.json");
const datasetValidator = validators.get("https://stead.dev/schemas/performance/dataset-v1.schema.json");
const candidateValidator = validators.get("https://stead.dev/schemas/performance/candidate-suite-v1.schema.json");
const artifactValidator = validators.get("https://stead.dev/schemas/performance/benchmark-artifact-v1.schema.json");
const reviewValidator = validators.get("https://stead.dev/schemas/performance/regression-review-v1.schema.json");
const baselineValidator = validators.get("https://stead.dev/schemas/performance/frontend-baseline-v1.schema.json");
const authoritiesValidator = validators.get("https://stead.dev/schemas/performance/reviewer-authorities-v1.schema.json");

assert(evidenceValidator(evidence).valid, "reference evidence must satisfy its strict JSON Schema");
assert(datasetValidator(dataset).valid, "trusted dataset/scenario manifest must satisfy its strict JSON Schema");
assert(baselineValidator(baseline).valid, "frontend baseline must satisfy its strict JSON Schema");
assert(authoritiesValidator(authorities).valid, "reviewer authority registry must satisfy its strict JSON Schema");

const producerAuthority = structuredClone(evidence);
producerAuthority.candidate_eligible = true;
producerAuthority.count_budgets = { sql_queries: 9999 };
assert(!evidenceValidator(producerAuthority).valid, "producer-owned eligibility and budgets must be structurally impossible");

const unknownNested = structuredClone(evidence);
unknownNested.telemetry.records[0].undeclared = true;
assert(!evidenceValidator(unknownNested).valid, "unknown nested telemetry fields must fail closed");

const invalidRawSample = structuredClone(evidence);
invalidRawSample.raw_samples.response_bytes[0] = "x";
assert(!evidenceValidator(invalidRawSample).valid, "raw samples must be structurally typed");

const commitClaim = structuredClone(evidence);
commitClaim.disclosure_mode = "commit_boundary";
assert(!evidenceValidator(commitClaim).valid, "Phase 1 evidence must not inject a disclosure mode");

const oversizedBundle = structuredClone(evidence);
oversizedBundle.sizes.eager_javascript_gzip_bytes = 256001;
assert(!evidenceValidator(oversizedBundle).valid, "the 250 KiB eager JavaScript ceiling must be structural");

const vagueDataset = structuredClone(dataset);
delete vagueDataset.client.cpu_model;
delete vagueDataset.server.cpu_base_frequency_mhz;
delete vagueDataset.load_shapes[0].arrival_model;
delete vagueDataset.load_shapes[0].pacing_ms;
delete vagueDataset.load_shapes[0].duration_seconds;
assert(!datasetValidator(vagueDataset).valid, "device and load conditions must include exact CPU, arrival, pacing, and duration controls");

const genericArtifact = {
  artifact_type: "performance_benchmark_artifact",
  schema_version: "1.0",
  artifact_id: "generic-result-bypass",
  kind: "query_count",
  source_revision: "b".repeat(40),
  dataset_sha256: "c".repeat(64),
  scenario_ids: dataset.scenarios.map((scenario) => scenario.id),
  producer: { tool: "untrusted", version: "1", command: "true" },
  status: "PASS",
  measurements: [{ metric: "query_count.result", value: 1, unit: "count" }],
  measurements_sha256: "d".repeat(64),
  recorded_at: "2026-08-30T18:00:00Z",
};
assert(!artifactValidator(genericArtifact).valid, "one generic result artifact must not claim coverage for every scenario");

const selfAssertedReview = {
  artifact_type: "performance_regression_review",
  schema_version: "1.0",
  review_id: "self-asserted",
  source_revision: "b".repeat(40),
  dataset_sha256: "c".repeat(64),
  evidence_sha256: "d".repeat(64),
  scenario_id: "hot-composed-metadata",
  baseline_id: "invented",
  metric: "timings_ms.latency.p95",
  baseline: 1,
  current: 2,
  regression_percent: 100,
  reviewer: { identity: "qa@example.test", role: "independent_qa" },
  decision: "approved_exception",
  justification: "A producer asserted an independent role without immutable authority.",
  reviewed_at: "2026-08-30T18:00:00Z",
};
assert(!reviewValidator(selfAssertedReview).valid, "review identity and role without immutable authority and signature must be structurally rejected");

const candidateWithoutTrustedCI = {
  artifact_type: "performance_candidate_suite",
  schema_version: "1.0",
  suite_id: "synthetic-noncandidate",
  phase: "phase1",
  source: {
    revision: "b".repeat(40), controls_revision: "a".repeat(40), dirty: false,
    recorded_at: "2026-08-30T18:00:00Z", implementation_owner: "owner@example.test",
    tool_versions: { runner: "1" },
  },
  dataset: { path: datasetPath, sha256: "c".repeat(64) },
  runtime_components: [], evidence: [], benchmark_artifacts: [], regression_reviews: [],
};
assert(!candidateValidator(candidateWithoutTrustedCI).valid, "candidate suites must carry the protected trusted-CI binding and complete coverage");

const strictRejects = [
  '{"source":{"revision":"a","revision":"b"}}',
  '{"source":{"revision":"a","\\u0072evision":"b"}}',
  "[".repeat(JSON_LIMITS.maxDepth + 1) + "0" + "]".repeat(JSON_LIMITS.maxDepth + 1),
  JSON.stringify("x".repeat(JSON_LIMITS.maxStringBytes + 1)),
];
assert(strictRejects.every((source) => {
  try { parseStrictJson(source); return false; } catch (error) { return error instanceof SyntaxError; }
}), "the Node schema gate must reject duplicate decoded keys and one-over depth/string inputs before JSON.parse");
assert(Array.isArray(parseStrictJson("[".repeat(JSON_LIMITS.maxDepth) + "0" + "]".repeat(JSON_LIMITS.maxDepth))),
  "the exact JSON depth ceiling must remain accepted");
assert(parseStrictJson('{"a":1}', { maxBytes: 7 }).a === 1,
  "the exact JSON byte ceiling must remain accepted");
try {
  parseStrictJson('{"a":1}', { maxBytes: 6 });
  assert(false, "one-over JSON bytes must fail before parse");
} catch (error) {
  assert(error instanceof SyntaxError, "one-over JSON bytes must fail with a strict parse error");
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exit(1);
}

process.stdout.write("PASS all performance artifact schemas compile strictly and reject authority, coverage, and provenance bypasses\n");
