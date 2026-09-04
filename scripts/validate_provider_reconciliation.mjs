#!/usr/bin/env node

import process from "node:process";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

import Ajv2020 from "ajv/dist/2020.js";
import {
  isAlias,
  isMap,
  isPair,
  isScalar,
  isSeq,
  parseAllDocuments,
} from "yaml";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTRACT_PATH = "specs/provider-reconciliation/gitea-v1.yaml";
const SCHEMA_PATH = "specs/provider-reconciliation/gitea-v1.schema.json";
const DEFAULT_YAML_LIMITS = Object.freeze({ maxBytes: 256 * 1024, maxDepth: 32, maxNodes: 4096 });
const CROSS_CONTRACT_YAML_LIMITS = Object.freeze({ maxBytes: 512 * 1024, maxDepth: 32, maxNodes: 32_768 });

export class ContractValidationError extends Error {}

const rejectUnsafeText = (bytes, filename, limits) => {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new TypeError(`${filename}: parser input must be bytes`);
  }
  if (bytes.length > limits.maxBytes) {
    throw new ContractValidationError(`${filename}: YAML input exceeds ${limits.maxBytes} bytes`);
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new ContractValidationError(`${filename}: UTF-8 BOM is prohibited`);
  }

  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ContractValidationError(`${filename}: invalid UTF-8`);
  }
  if (source.includes("\ufeff")) {
    throw new ContractValidationError(`${filename}: BOM characters are prohibited`);
  }
  if (source.includes("\r")) {
    throw new ContractValidationError(`${filename}: CR and CRLF encodings are prohibited`);
  }
  if (/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/u.test(source)) {
    throw new ContractValidationError(`${filename}: unsafe control character`);
  }
  if (/^%/mu.test(source)) {
    throw new ContractValidationError(`${filename}: YAML directives are prohibited`);
  }
  return source;
};

const inspectNode = (node, filename, limits, location = "$", depth = 0, budget = { nodes: 0 }, seen = new Set()) => {
  if (node == null) return;
  if (depth > limits.maxDepth) {
    throw new ContractValidationError(`${filename}: YAML nesting exceeds ${limits.maxDepth} at ${location}`);
  }
  budget.nodes += 1;
  if (budget.nodes > limits.maxNodes) {
    throw new ContractValidationError(`${filename}: YAML node count exceeds ${limits.maxNodes}`);
  }
  if (seen.has(node)) {
    throw new ContractValidationError(`${filename}: cyclic YAML node at ${location}`);
  }
  if (isAlias(node)) {
    throw new ContractValidationError(`${filename}: aliases are prohibited at ${location}`);
  }
  if (node.anchor) {
    throw new ContractValidationError(`${filename}: anchors are prohibited at ${location}`);
  }
  if (node.tag) {
    throw new ContractValidationError(`${filename}: explicit YAML tags are prohibited at ${location}`);
  }

  if (isMap(node)) {
    seen.add(node);
    const keys = new Set();
    for (const pair of node.items) {
      budget.nodes += 2;
      if (budget.nodes > limits.maxNodes) {
        throw new ContractValidationError(`${filename}: YAML node count exceeds ${limits.maxNodes}`);
      }
      if (!isPair(pair) || !isScalar(pair.key) || typeof pair.key.value !== "string") {
        throw new ContractValidationError(`${filename}: mapping keys must be simple strings at ${location}`);
      }
      if (pair.key.anchor || pair.key.tag) {
        throw new ContractValidationError(`${filename}: tagged or anchored keys are prohibited at ${location}`);
      }
      const key = pair.key.value;
      if (key === "<<") {
        throw new ContractValidationError(`${filename}: YAML merge keys are prohibited at ${location}`);
      }
      if (keys.has(key)) {
        throw new ContractValidationError(`${filename}: duplicate key ${JSON.stringify(key)} at ${location}`);
      }
      keys.add(key);
      inspectNode(pair.value, filename, limits, `${location}.${key}`, depth + 1, budget, seen);
    }
    seen.delete(node);
  } else if (isSeq(node)) {
    seen.add(node);
    node.items.forEach((item, index) => inspectNode(item, filename, limits, `${location}[${index}]`, depth + 1, budget, seen));
    seen.delete(node);
  }
};

export const parseStrictYaml = (bytes, filename = "<input>", configuredLimits = {}) => {
  const limits = { ...DEFAULT_YAML_LIMITS, ...configuredLimits };
  const source = rejectUnsafeText(bytes, filename, limits);
  const documents = parseAllDocuments(source, {
    strict: true,
    uniqueKeys: true,
    merge: false,
    schema: "core",
  });
  if (documents.length !== 1) {
    throw new ContractValidationError(`${filename}: exactly one YAML document is required`);
  }
  const document = documents[0];
  const parserProblems = [...document.errors, ...document.warnings];
  if (parserProblems.length > 0) {
    throw new ContractValidationError(`${filename}: ${parserProblems.map(({ message }) => message).join("; ")}`);
  }
  inspectNode(document.contents, filename, limits);
  return document.toJS({ mapAsMap: false, maxAliasCount: 0 });
};

const readStrictYaml = async (relativePath, limits = {}) =>
  parseStrictYaml(await readFile(path.join(ROOT, relativePath)), relativePath, limits);

const loadSchemaValidator = async () => {
  const schema = JSON.parse(await readFile(path.join(ROOT, SCHEMA_PATH), "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  return ajv.compile(schema);
};

export const validateContractDocument = async (document) => {
  const validate = await loadSchemaValidator();
  if (!validate(document)) {
    const detail = validate.errors
      .map(({ instancePath, message }) => `${instancePath || "/"} ${message}`)
      .join("; ");
    throw new ContractValidationError(`${CONTRACT_PATH}: schema validation failed: ${detail}`);
  }
};

const oneBy = (records, field, value, label) => {
  const matches = records.filter((record) => record?.[field] === value);
  if (matches.length !== 1) {
    throw new ContractValidationError(`${label}: expected exactly one ${field}=${value}, found ${matches.length}`);
  }
  return matches[0];
};

const sameSet = (left, right) =>
  left.length === right.length && left.every((value) => new Set(right).has(value));

export const validateProviderRegistryBoundaries = (contract, registry) => {
  const registryBoundaries = {
    owner: contract.owner,
    status: contract.status,
    source: CONTRACT_PATH,
    provider: "gitea",
    authorization_scope_owner: contract.authorization.provider_read_scope.owner,
    execution_claim_owner: contract.persistence.reconciliation_state_owner,
    execution_scope: contract.authorization.provider_read_scope.execution_scope,
    protected_audit_evidence_owner: contract.persistence.protected_audit_evidence_owner,
    protected_audit_evidence_resolution_port: contract.persistence.protected_audit_evidence_resolution_port,
    protected_audit_evidence_consumer: contract.persistence.protected_audit_evidence_consumer,
    core_outbox_owner: contract.persistence.core_outbox_owner,
    audit_record_schema_owner: contract.persistence.audit_schema_owner,
    audit_record_materialization_owner: contract.persistence.audit_materialization_owner,
    ordinary_ui_synchronous_provider_calls: contract.authority.ordinary_ui_synchronous_provider_calls,
    activation_gate: contract.activation_gate,
  };
  for (const [field, expected] of Object.entries(registryBoundaries)) {
    if (registry[field] !== expected) {
      throw new ContractValidationError(`provider interface registry ${field} must be ${JSON.stringify(expected)}`);
    }
  }
};

export const validateCrossContractBoundaries = async (contract) => {
  const eligibleCalls = new Set(contract.authorization.provider_read_scope.eligible_calls);
  const readEffectOverlap = contract.authorization.effect_permit.required_for.filter((effect) => eligibleCalls.has(effect));
  if (readEffectOverlap.length > 0) {
    throw new ContractValidationError(`eligible read calls and durable effect-permit classes must be disjoint: ${readEffectOverlap.join(", ")}`);
  }

  const catalog = await readStrictYaml(
    "docs/planning/implementation-issue-catalog.yaml",
    CROSS_CONTRACT_YAML_LIMITS,
  );
  const providerInterfaces = await readStrictYaml(
    "specs/provider-interfaces.yaml",
    CROSS_CONTRACT_YAML_LIMITS,
  );
  const gate = oneBy(catalog.adr_decision_gates, "adr_id", "ADR-CAND-008", "ADR gate catalog");
  const registry = oneBy(
    providerInterfaces.reconciliation_contracts,
    "id",
    contract.contract_id,
    "provider interface registry",
  );

  const expectedGate = {
    decision_record: contract.decision_record,
    project_owner_approval_required: true,
  };
  if (!["PROPOSED", "ACCEPTED"].includes(gate.state)) {
    throw new ContractValidationError("ADR-CAND-008 state must be PROPOSED or ACCEPTED");
  }
  for (const [field, expected] of Object.entries(expectedGate)) {
    if (gate[field] !== expected) {
      throw new ContractValidationError(`ADR-CAND-008 ${field} must be ${JSON.stringify(expected)}`);
    }
  }

  validateProviderRegistryBoundaries(contract, registry);

  const ownership = new Map([
    ["STEAD-P1-002", "WS-02"],
    ["STEAD-P1-003", "WS-03"],
    ["STEAD-P1-006", "WS-06"],
    ["STEAD-P1-007", "WS-07"],
  ]);
  for (const [issueId, expectedOwner] of ownership) {
    const issue = oneBy(catalog.issues, "id", issueId, "implementation issue catalog");
    if (issue.owner !== expectedOwner) {
      throw new ContractValidationError(`${issueId} owner must be ${expectedOwner}`);
    }
    if (issueId === "STEAD-P1-003" && !issue.owned_directories.includes("specs/provider-reconciliation")) {
      throw new ContractValidationError("STEAD-P1-003 must own specs/provider-reconciliation");
    }
  }

  const adrSource = await readFile(path.join(ROOT, contract.decision_record), "utf8");
  const requirementLine = adrSource.match(/^- \*\*Requirement IDs:\*\*\s*(.+)$/mu)?.[1] ?? "";
  const adrRequirements = [...requirementLine.matchAll(/`([A-Z]+-[0-9]{3})`/gu)].map((match) => match[1]);
  if (!sameSet(contract.requirements, adrRequirements)) {
    throw new ContractValidationError("contract requirements must match the ADR-0009 Requirement IDs header");
  }

  const examples = Object.values(contract.field_classes).flatMap(({ examples: values }) => values);
  if (new Set(examples).size !== examples.length) {
    throw new ContractValidationError("field-class examples must belong to exactly one class");
  }
};

export const validateRepositoryContract = async () => {
  const contract = await readStrictYaml(CONTRACT_PATH);
  await validateContractDocument(contract);
  await validateCrossContractBoundaries(contract);
  return contract;
};

const invokedAsScript = process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (invokedAsScript) {
  try {
    await validateRepositoryContract();
    console.log(`Gitea reconciliation contract validation passed: ${CONTRACT_PATH}.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
