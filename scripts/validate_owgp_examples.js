#!/usr/bin/env node

"use strict";

const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const schema = JSON.parse(
  fs.readFileSync(path.join(root, "specs/work-graph-profile/owgp-v0.1.schema.json"), "utf8"),
);
const examples = JSON.parse(
  childProcess.execFileSync(
    "ruby",
    [
      "-rjson",
      "-ryaml",
      "-e",
      'puts JSON.generate(YAML.safe_load_file("specs/work-graph-profile/examples.yaml", aliases: true))',
    ],
    { cwd: root, encoding: "utf8" },
  ),
).examples;

function resolveLocalReference(reference) {
  return reference
    .split("/")
    .slice(1)
    .map((token) => token.replace(/~1/g, "/").replace(/~0/g, "~"))
    .reduce((value, key) => value[key], schema);
}

function evaluatedProperties(contract, seen = new Set()) {
  if (!contract || seen.has(contract)) return new Set();
  seen.add(contract);
  if (contract.$ref) return evaluatedProperties(resolveLocalReference(contract.$ref), seen);

  const names = new Set(Object.keys(contract.properties || {}));
  for (const item of contract.allOf || []) {
    for (const name of evaluatedProperties(item, seen)) names.add(name);
  }
  return names;
}

function validate(value, contract, location, errors) {
  if (!contract) return;
  if (contract.$ref) {
    validate(value, resolveLocalReference(contract.$ref), location, errors);
    return;
  }

  for (const item of contract.allOf || []) validate(value, item, location, errors);

  if (contract.oneOf) {
    const matches = contract.oneOf.filter((item) => {
      const candidateErrors = [];
      validate(value, item, location, candidateErrors);
      return candidateErrors.length === 0;
    });
    if (matches.length !== 1) errors.push(`${location}: oneOf matched ${matches.length} alternatives`);
  }

  if (contract.type) {
    const accepted = Array.isArray(contract.type) ? contract.type : [contract.type];
    const actual = value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
    const integerMatch = actual === "number" && accepted.includes("integer") && Number.isInteger(value);
    if (!accepted.includes(actual) && !integerMatch) {
      errors.push(`${location}: expected ${accepted.join("|")}, received ${actual}`);
    }
  }

  if (Object.hasOwn(contract, "const") && value !== contract.const) {
    errors.push(`${location}: expected constant ${contract.const}, received ${value}`);
  }
  if (contract.enum && !contract.enum.some((candidate) => candidate === value)) {
    errors.push(`${location}: value ${value} is outside the enum`);
  }
  if (typeof value === "string" && contract.pattern && !new RegExp(contract.pattern).test(value)) {
    errors.push(`${location}: value does not match ${contract.pattern}`);
  }
  if (typeof value === "number") {
    if (contract.minimum !== undefined && value < contract.minimum) errors.push(`${location}: below minimum`);
    if (contract.maximum !== undefined && value > contract.maximum) errors.push(`${location}: above maximum`);
  }

  if (Array.isArray(value)) {
    if (contract.minItems !== undefined && value.length < contract.minItems) errors.push(`${location}: too few items`);
    if (contract.uniqueItems && new Set(value.map(JSON.stringify)).size !== value.length) {
      errors.push(`${location}: items are not unique`);
    }
    if (contract.items) {
      value.forEach((item, index) => validate(item, contract.items, `${location}[${index}]`, errors));
    }
    if (
      contract.contains &&
      !value.some((item) => {
        const candidateErrors = [];
        validate(item, contract.contains, location, candidateErrors);
        return candidateErrors.length === 0;
      })
    ) {
      errors.push(`${location}: contains constraint is not satisfied`);
    }
  }

  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const key of contract.required || []) {
      if (!Object.hasOwn(value, key)) errors.push(`${location}: missing ${key}`);
    }
    for (const [key, childContract] of Object.entries(contract.properties || {})) {
      if (Object.hasOwn(value, key)) validate(value[key], childContract, `${location}.${key}`, errors);
    }
    if (contract.additionalProperties === false) {
      const allowed = new Set(Object.keys(contract.properties || {}));
      for (const key of Object.keys(value)) {
        if (!allowed.has(key)) errors.push(`${location}: unexpected property ${key}`);
      }
    }
    if (contract.unevaluatedProperties === false) {
      const allowed = evaluatedProperties(contract);
      for (const key of Object.keys(value)) {
        if (!allowed.has(key)) errors.push(`${location}: unevaluated property ${key}`);
      }
    }
  }

  if (contract.if) {
    const conditionErrors = [];
    validate(value, contract.if, location, conditionErrors);
    validate(value, conditionErrors.length === 0 ? contract.then : contract.else, location, errors);
  }
}

const exampleDefinitions = {
  Organization: "Organization",
  DirectoryGroup: "DirectoryGroup",
  Team: "Team",
  Project: "Project",
  WorkItem: "WorkItem",
  Document: "Document",
  Repository: "Repository",
  PrincipalRef: "PrincipalRef",
  Agent: "Agent",
  AgentRun: "AgentRun",
  SecurityLabel: "SecurityLabel",
  Comment: "Comment",
  Activity: "Activity",
  Notification: "Notification",
  Audit: "AuditRecord",
};

const errors = [];
for (const [exampleName, definitionName] of Object.entries(exampleDefinitions)) {
  validate(examples[exampleName], schema.$defs[definitionName], exampleName, errors);
}

function expectInvalid(value, definitionName, testName) {
  const candidateErrors = [];
  validate(value, schema.$defs[definitionName], testName, candidateErrors);
  if (candidateErrors.length === 0) errors.push(`${testName}: invalid fixture unexpectedly passed`);
}

expectInvalid(
  {...examples.WorkItem.effective_security_label, unapproved_claim: "free-form"},
  "SecurityLabelValue",
  "SecurityLabelValue rejects undeclared claims",
);
expectInvalid(
  {type: "service_account", id: examples.PrincipalRef.id},
  "WorkAssigneeRef",
  "WorkAssigneeRef rejects service accounts",
);
expectInvalid(
  {type: "directory_group", id: examples.PrincipalRef.id},
  "ActingPrincipalRef",
  "ActingPrincipalRef rejects Directory Groups",
);
expectInvalid(
  {...examples.Project, unapproved_ontology_field: true},
  "Project",
  "Project rejects undeclared ontology fields",
);
const auditWithoutAuthentication = {...examples.Audit};
delete auditWithoutAuthentication.authentication_context;
expectInvalid(
  auditWithoutAuthentication,
  "AuditRecord",
  "AuditRecord requires authentication context",
);
const auditWithoutPolicyVersions = {...examples.Audit};
delete auditWithoutPolicyVersions.authorization_model_id;
delete auditWithoutPolicyVersions.policy_bundle_id;
expectInvalid(
  auditWithoutPolicyVersions,
  "AuditRecord",
  "AuditRecord requires authorization model and policy bundle versions",
);

if (errors.length > 0) {
  console.error(`OWGP example validation failed (${errors.length}):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`OWGP examples passed semantic schema checks: ${Object.keys(exampleDefinitions).length} valid and 6 negative fixtures`);
