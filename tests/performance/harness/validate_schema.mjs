#!/usr/bin/env node

import process from "node:process";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readStrictJson } from "./strict_json.mjs";

const [schemaPath, ...documentPaths] = process.argv.slice(2);
if (!schemaPath || documentPaths.length === 0) {
  process.stderr.write("usage: validate_schema.mjs SCHEMA.json DOCUMENT.json [...]\n");
  process.exit(2);
}

const parseJson = readStrictJson;

try {
  const schema = await parseJson(schemaPath);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const results = [];

  for (const path of documentPaths) {
    const document = await parseJson(path);
    const valid = validate(document);
    results.push({
      path,
      valid,
      errors: valid ? [] : structuredClone(validate.errors ?? [])
    });
  }

  process.stdout.write(`${JSON.stringify({ schema: schemaPath, results })}\n`);
  process.exit(results.every((result) => result.valid) ? 0 : 1);
} catch (error) {
  process.stderr.write(`${error.name}: ${error.message}\n`);
  process.exit(2);
}
