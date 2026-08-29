#!/usr/bin/env node

"use strict";

const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const schema = JSON.parse(
  fs.readFileSync(path.join(root, "specs/work-graph-profile/owgp-v0.1.schema.json"), "utf8"),
);
const exampleDocument = JSON.parse(
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
);
const examples = exampleDocument.examples;
const configuredInstanceId = exampleDocument.shared.instance_id;
const configuredOriginValue = exampleDocument.shared.configured_origin;
const configuredOrigin = new URL(configuredOriginValue);

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
  Instance: "Instance",
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

function canonicalUuid(uri) {
  const prefix = "urn:uuid:";
  return typeof uri === "string" && uri.startsWith(prefix) ? uri.slice(prefix.length) : null;
}

function resourceReferenceErrors(resource, trustedOriginValue = configuredOriginValue) {
  const identityErrors = [];
  const trustedOrigin = new URL(trustedOriginValue);
  const uriUuid = canonicalUuid(resource.uri);
  if (uriUuid === null) {
    identityErrors.push("canonical URI is not a registered urn:uuid identifier");
  } else if (uriUuid !== resource.id) {
    identityErrors.push("canonical URI UUID differs from resource ID");
  }

  if (Object.hasOwn(resource, "browser_url")) {
    try {
      const browserUrl = new URL(resource.browser_url);
      const expected = `${trustedOriginValue}/r/${resource.kind}/${resource.id}`;
      if (browserUrl.username || browserUrl.password) {
        identityErrors.push("browser URL must not contain userinfo");
      }
      if (browserUrl.origin !== trustedOrigin.origin) {
        identityErrors.push("browser URL authority differs from the configured trusted origin");
      }
      if (resource.browser_url !== expected || browserUrl.search || browserUrl.hash) {
        identityErrors.push("browser URL is not the exact server-derived kind/UUID locator");
      }
    } catch {
      identityErrors.push("browser URL is invalid");
    }
  }

  return identityErrors;
}

function resourceEnvelopeErrors(resource) {
  const identityErrors = resourceReferenceErrors(resource);
  if (resource.instance_id !== configuredInstanceId) {
    identityErrors.push("envelope instance_id differs from the configured instance");
  }

  if (resource.kind === "instance") {
    if (
      resource.id !== resource.instance_id ||
      resource.scope_kind !== "instance" ||
      resource.scope_id !== resource.instance_id
    ) {
      identityErrors.push("Instance resource must be self-scoped to its instance UUID");
    }
  } else if (resource.kind === "organization") {
    if (resource.scope_kind !== "instance" || resource.scope_id !== resource.instance_id) {
      identityErrors.push("Organization resource must be scoped to its instance UUID");
    }
    if (resource.organization_id !== resource.id) {
      identityErrors.push("Organization resource organization_id must equal its canonical ID");
    }
  } else if (
    resource.scope_kind !== "organization" ||
    resource.scope_id !== resource.organization_id
  ) {
    identityErrors.push("Organization-owned resource scope must equal organization_id");
  }

  return identityErrors;
}

function nestedResourceReferenceErrors(value, location, skipCurrent = false) {
  const identityErrors = [];
  if (!value || typeof value !== "object") return identityErrors;
  if (
    !skipCurrent &&
    !Array.isArray(value) &&
    Object.hasOwn(value, "kind") &&
    Object.hasOwn(value, "id") &&
    Object.hasOwn(value, "uri")
  ) {
    for (const error of resourceReferenceErrors(value)) {
      identityErrors.push(`${location}: ${error}`);
    }
  }
  for (const [key, child] of Object.entries(value)) {
    const childLocation = Array.isArray(value) ? `${location}[${key}]` : `${location}.${key}`;
    identityErrors.push(...nestedResourceReferenceErrors(child, childLocation));
  }
  return identityErrors;
}

if (
  configuredOrigin.protocol !== "https:" ||
  configuredOrigin.username ||
  configuredOrigin.password ||
  configuredOrigin.pathname !== "/" ||
  configuredOrigin.search ||
  configuredOrigin.hash ||
  configuredOriginValue !== configuredOrigin.origin
) {
  errors.push("configured_origin must be an exact canonical HTTPS origin without userinfo, path, query, or fragment");
}

for (const [exampleName, resource] of Object.entries(examples)) {
  if (!resource.kind) continue;
  for (const error of resourceEnvelopeErrors(resource)) errors.push(`${exampleName}: ${error}`);
  errors.push(...nestedResourceReferenceErrors(resource, exampleName, true));
}

function expectInvalid(value, definitionName, testName) {
  const candidateErrors = [];
  validate(value, schema.$defs[definitionName], testName, candidateErrors);
  if (candidateErrors.length === 0) errors.push(`${testName}: invalid fixture unexpectedly passed`);
}

function expectIdentityInvalid(value, testName, nested = false) {
  const identityErrors = nested
    ? nestedResourceReferenceErrors(value, testName, true)
    : resourceEnvelopeErrors(value);
  if (identityErrors.length === 0) errors.push(`${testName}: invalid fixture unexpectedly passed`);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
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

expectInvalid(
  {...examples.Project, uri: "https://gitea.example/provider/project/42"},
  "Project",
  "Project rejects a provider URL as canonical URI",
);
expectInvalid(
  {...examples.Project, browser_url: "https://stead.example/o/acme/projects/ONB"},
  "Project",
  "Project rejects a display-path browser URL",
);
expectInvalid(
  {...examples.Project, uri: examples.Project.uri.replace(/:([0-9a-f]{8}-[0-9a-f]{4})-7/, ":$1-4")},
  "Project",
  "Project rejects a non-UUIDv7 canonical URI component",
);
expectInvalid(
  {...examples.Project, browser_url: `https://alice@stead.example/r/project/${examples.Project.id}`},
  "Project",
  "Project rejects browser URL userinfo",
);

expectIdentityInvalid(
  {...examples.Project, uri: "urn:uuid:018f0000-0000-7000-8000-000000000099"},
  "Project rejects envelope resource UUID mismatch",
);
expectIdentityInvalid(
  {...examples.Project, instance_id: "018f0000-0000-7000-8000-000000000099"},
  "Project rejects configured instance mismatch",
);
expectIdentityInvalid(
  {...examples.Instance, scope_id: examples.Organization.id},
  "Instance rejects invalid self-scope",
);
expectIdentityInvalid(
  {...examples.Organization, organization_id: "018f0000-0000-7000-8000-000000000099"},
  "Organization rejects organization_id mismatch",
);
expectIdentityInvalid(
  {...examples.Project, scope_id: "018f0000-0000-7000-8000-000000000099"},
  "Project rejects Organization scope mismatch",
);
expectIdentityInvalid(
  {
    ...examples.Project,
    browser_url: "https://stead.example/r/project/018f0000-0000-7000-8000-000000000099",
  },
  "Project rejects browser UUID mismatch",
);
expectIdentityInvalid(
  {...examples.Project, browser_url: `https://foreign.example/r/project/${examples.Project.id}`},
  "Project rejects foreign browser authority",
);
expectIdentityInvalid(
  {...examples.Project, browser_url: `https://alice@stead.example/r/project/${examples.Project.id}`},
  "Project rejects browser URL userinfo semantically",
);

const nestedReferenceMismatch = clone(examples.Comment);
nestedReferenceMismatch.subject.uri = "urn:uuid:018f0000-0000-7000-8000-000000000099";
expectIdentityInvalid(
  nestedReferenceMismatch,
  "Comment rejects nested ResourceRef UUID mismatch",
  true,
);

function schemaErrorsFor(value, definitionName) {
  const candidateErrors = [];
  validate(value, schema.$defs[definitionName], definitionName, candidateErrors);
  return candidateErrors;
}

const namedTests = new Map();
namedTests.set(
  "T-ADR-0001-URI-GRAMMAR",
  schemaErrorsFor(examples.Project, "Project").length === 0 &&
    schemaErrorsFor({...examples.Project, uri: "https://gitea.example/provider/project/42"}, "Project").length > 0 &&
    schemaErrorsFor({...examples.Project, uri: "urn:uuid:018f0000-0000-4000-8000-000000000005"}, "Project").length > 0 &&
    schemaErrorsFor({...examples.Project, uri: "urn:uuid:NOT-A-UUID"}, "Project").length > 0,
);

namedTests.set(
  "T-ADR-0001-SCOPE",
  resourceEnvelopeErrors(examples.Instance).length === 0 &&
    resourceEnvelopeErrors(examples.Organization).length === 0 &&
    resourceEnvelopeErrors(examples.Project).length === 0 &&
    resourceEnvelopeErrors({...examples.Instance, scope_id: examples.Organization.id}).length > 0 &&
    resourceEnvelopeErrors({...examples.Organization, organization_id: examples.Project.id}).length > 0 &&
    resourceEnvelopeErrors({...examples.Project, scope_id: examples.Team.id}).length > 0,
);

namedTests.set(
  "T-ADR-0001-KIND-ID",
  resourceReferenceErrors(examples.Project).length === 0 &&
    resourceReferenceErrors({...examples.Project, uri: examples.Organization.uri}).length > 0 &&
    resourceReferenceErrors({...examples.Project, browser_url: examples.Organization.browser_url}).length > 0 &&
    nestedResourceReferenceErrors(nestedReferenceMismatch, "Comment", true).length > 0,
);

const alternateOrigin = "https://stead-secondary.example";
const alternateProject = {
  ...examples.Project,
  browser_url: `${alternateOrigin}/r/${examples.Project.kind}/${examples.Project.id}`,
};
namedTests.set(
  "T-ADR-0001-HOST-INDEPENDENCE",
  alternateProject.id === examples.Project.id &&
    alternateProject.uri === examples.Project.uri &&
    alternateProject.browser_url !== examples.Project.browser_url &&
    resourceReferenceErrors(alternateProject, alternateOrigin).length === 0 &&
    resourceReferenceErrors({...examples.Project, browser_url: `https://foreign.example/r/project/${examples.Project.id}`}).length > 0 &&
    resourceReferenceErrors({...examples.Project, browser_url: `https://alice@stead.example/r/project/${examples.Project.id}`}).length > 0,
);

for (const [testId, passed] of namedTests) {
  if (passed) {
    console.log(`PASS ${testId}`);
  } else {
    errors.push(`${testId}: named ADR contract evidence failed`);
  }
}

if (errors.length > 0) {
  console.error(`OWGP example validation failed (${errors.length}):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(
  `OWGP examples passed semantic schema checks: ${Object.keys(exampleDefinitions).length} valid, 10 schema-negative fixtures, and 9 identity/security semantic negative fixtures`,
);
