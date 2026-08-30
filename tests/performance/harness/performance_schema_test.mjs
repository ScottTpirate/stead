#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import process from "node:process";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaPaths = [
  "tests/performance/harness/performance-evidence-v1.schema.json",
  "tests/performance/harness/performance-dataset-v1.schema.json",
  "tests/performance/harness/performance-candidate-suite-v1.schema.json",
  "tests/performance/harness/performance-benchmark-artifact-v1.schema.json",
  "tests/performance/harness/performance-regression-review-v1.schema.json"
];
const evidencePath = "packages/test-fixtures/harness/performance/standard-request-boundary-valid.json";
const datasetPath = "tests/performance/datasets/standard-request-boundary-v1.json";
const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));

const schemas = await Promise.all(schemaPaths.map(readJson));
const [evidence, dataset] = await Promise.all([readJson(evidencePath), readJson(datasetPath)]);
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

assert(evidenceValidator(evidence).valid, "reference evidence must satisfy its strict JSON Schema");
assert(datasetValidator(dataset).valid, "trusted dataset/scenario manifest must satisfy its strict JSON Schema");

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
vagueDataset.network = "same region";
assert(!datasetValidator(vagueDataset).valid, "network conditions must use exact structured parameters");

if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exit(1);
}

process.stdout.write("PASS all performance artifact schemas compile strictly and reject authority bypasses\n");
