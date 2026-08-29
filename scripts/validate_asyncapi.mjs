#!/usr/bin/env node

import process from "node:process";

import { readFile } from "node:fs/promises";

import asyncapiSpecs from "@asyncapi/specs";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { parse } from "yaml";

const path = "specs/asyncapi/stead.yaml";
const document = parse(await readFile(path, "utf8"));
const version = document?.asyncapi;
const schema = asyncapiSpecs.schemasWithoutId[version];

if (schema === undefined) {
  console.error(`Unsupported AsyncAPI version: ${String(version)}`);
  process.exitCode = 1;
} else {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);

  if (!validate(document)) {
    console.error(ajv.errorsText(validate.errors, { separator: "\n" }));
    process.exitCode = 1;
  } else {
    console.log(`AsyncAPI validation passed: ${path} (${version}).`);
  }
}
