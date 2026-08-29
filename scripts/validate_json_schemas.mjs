#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import process from "node:process";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const paths = [
  "specs/work-graph-profile/owgp-v0.1.schema.json",
  "packages/event-schemas/common/actor-context/actor-context-v0.1.schema.json",
  "packages/event-schemas/stead/stead-event-v0.1.schema.json",
  "policies/policy-decision/input-v0.1.schema.json",
  "policies/policy-decision/output-v0.1.schema.json",
  "specs/migration/migration-job-v0.1.schema.json",
  "policies/security-label-profiles/profile-v0.1.schema.json",
  "policies/deployment-domains/domain-profile-v0.1.schema.json",
];

const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);

try {
  const schemas = await Promise.all(
    paths.map(async (path) => JSON.parse(await readFile(path, "utf8"))),
  );

  for (const schema of schemas) {
    ajv.addSchema(schema);
  }
  for (const schema of schemas) {
    ajv.getSchema(schema.$id);
  }

  console.log(
    `Standalone JSON Schema validation passed: ${schemas.length}/${paths.length} canonical schemas resolve by $id.`,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
