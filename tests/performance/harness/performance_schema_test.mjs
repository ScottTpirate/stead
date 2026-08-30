#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import process from "node:process";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaPath = "tests/performance/harness/performance-evidence-v1.schema.json";
const fixturePath = "packages/test-fixtures/harness/performance/standard-request-boundary-valid.json";
const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));

const [schema, fixture] = await Promise.all([readJson(schemaPath), readJson(fixturePath)]);
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);

const failures = [];
const assert = (condition, message) => {
  if (!condition) failures.push(message);
};
const errors = () => ajv.errorsText(validate.errors, { separator: "\n" });

assert(validate(fixture), `reference fixture violates the JSON Schema:\n${errors()}`);

const unknownField = structuredClone(fixture);
unknownField.undeclared = true;
assert(!validate(unknownField), "top-level unknown fields must fail closed");

const unknownScaleField = structuredClone(fixture);
unknownScaleField.scaling_trials[0].undeclared = true;
assert(!validate(unknownScaleField), "scaling-trial unknown fields must fail closed");

const missingLabel = structuredClone(fixture);
delete missingLabel.scenario.network;
assert(!validate(missingLabel), "required reproducibility labels must fail closed when absent");

const oversizedBundle = structuredClone(fixture);
oversizedBundle.sizes.eager_javascript_gzip_bytes = 256001;
assert(!validate(oversizedBundle), "the 250 KiB eager JavaScript ceiling must be structural");

if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exit(1);
}

process.stdout.write("PASS performance evidence JSON Schema and strict fixture checks\n");
