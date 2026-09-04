import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  parseStrictYaml,
  validateContractDocument,
  validateCrossContractBoundaries,
  validateProviderRegistryBoundaries,
  validateRepositoryContract,
} from "../../../scripts/validate_provider_reconciliation.mjs";

const contractPath = "specs/provider-reconciliation/gitea-v1.yaml";
const providerInterfacesPath = "specs/provider-interfaces.yaml";
const bytes = (source) => Buffer.from(source, "utf8");

test("repository Gitea reconciliation contract is valid", async () => {
  const contract = await validateRepositoryContract();
  assert.equal(contract.contract_id, "P-SCM-RECONCILIATION-GITEA-V1");
});

test("strict parser accepts a single plain UTF-8 YAML document", () => {
  assert.deepEqual(parseStrictYaml(bytes("key: value\n")), { key: "value" });
});

const rejectedSources = [
  ["UTF-8 BOM", Buffer.from([0xef, 0xbb, 0xbf, 0x61, 0x3a, 0x20, 0x62, 0x0a])],
  ["invalid UTF-8", Buffer.from([0xff])],
  ["NUL", bytes("key: \u0000\n")],
  ["control character", bytes("key: \u001f\n")],
  ["Arabic letter mark", bytes("key: \u061cvalue\n")],
  ["left-to-right mark", bytes("key: \u200evalue\n")],
  ["bidirectional embedding", bytes("key: \u202avalue\n")],
  ["bidirectional override", bytes("key: \u202evalue\n")],
  ["bidirectional isolate", bytes("key: \u2066value\n")],
  ["bidirectional isolate end", bytes("key: \u2069value\n")],
  ["BMP noncharacter range start", bytes("key: \ufdd0value\n")],
  ["BMP noncharacter range end", bytes("key: \ufdefvalue\n")],
  ["supplementary-plane FFFE noncharacter", bytes("key: \u{1fffe}value\n")],
  ["supplementary-plane FFFF noncharacter", bytes("key: \u{1ffff}value\n")],
  ["multiple documents", bytes("a: b\n---\nc: d\n")],
  ["directive", bytes("%YAML 1.2\n---\na: b\n")],
  ["custom tag", bytes("a: !custom value\n")],
  ["tagged key", bytes("!custom key: value\n")],
  ["anchor", bytes("a: &anchor value\n")],
  ["alias", bytes("a: *anchor\n")],
  ["merge key", bytes("<<: value\n")],
  ["complex key", bytes("? [a, b]\n: value\n")],
  ["non-string key", bytes("1: value\n")],
  ["duplicate key", bytes("a: first\na: second\n")],
  ["byte limit", Buffer.alloc((256 * 1024) + 1, 0x61)],
  ["depth limit", bytes(`${Array.from({ length: 34 }, (_, index) => `${"  ".repeat(index)}level_${index}:\n`).join("")}${"  ".repeat(34)}value: final\n`)],
  ["node limit", bytes(Array.from({ length: 1400 }, (_, index) => `key_${index}: value\n`).join(""))],
];

for (const [name, input] of rejectedSources) {
  test(`strict parser rejects ${name}`, () => {
    assert.throws(() => parseStrictYaml(input, `${name}.yaml`));
  });
}

test("strict parser accepts valid code points adjacent to noncharacter boundaries", () => {
  assert.deepEqual(
    parseStrictYaml(bytes("before_range: \ufdcf\nafter_range: \ufdf0\nbefore_plane_end: \u{1fffd}\n")),
    { before_range: "﷏", after_range: "ﷰ", before_plane_end: "🿽" },
  );
});

test("schema rejects unknown fields", async () => {
  const contract = parseStrictYaml(await readFile(contractPath), contractPath);
  contract.unknown_field = true;
  await assert.rejects(() => validateContractDocument(contract), /additional properties/i);
});

test("schema rejects invalid types", async () => {
  const contract = parseStrictYaml(await readFile(contractPath), contractPath);
  contract.authority.ordinary_ui_synchronous_provider_calls = "zero";
  await assert.rejects(() => validateContractDocument(contract), /schema validation failed/i);
});

for (const binding of [
  "provider_enforcement_fence",
  "resource_fence",
  "unique_execution_claim",
  "process_instance_holder_identity",
  "monotonic_fencing_token",
  "claim_deadline",
]) {
  test(`schema requires provider-read security binding ${binding}`, async () => {
    const contract = parseStrictYaml(await readFile(contractPath), contractPath);
    contract.authorization.provider_read_scope.required_bindings =
      contract.authorization.provider_read_scope.required_bindings.filter((value) => value !== binding);
    await assert.rejects(() => validateContractDocument(contract), /schema validation failed/i);
  });
}

test("schema rejects provider authority over central-security fields", async () => {
  const contract = parseStrictYaml(await readFile(contractPath), contractPath);
  contract.field_classes.central_security.provider_change = "accept_provider_as_authority";
  await assert.rejects(() => validateContractDocument(contract), /schema validation failed/i);
});

test("schema rejects moving authorization_tuple out of central_security", async () => {
  const contract = parseStrictYaml(await readFile(contractPath), contractPath);
  contract.field_classes.central_security.examples =
    contract.field_classes.central_security.examples.filter((value) => value !== "authorization_tuple");
  contract.field_classes.provider_content.examples.push("authorization_tuple");
  await assert.rejects(() => validateContractDocument(contract), /schema validation failed/i);
});

test("schema rejects rewriting audit materialization", async () => {
  const contract = parseStrictYaml(await readFile(contractPath), contractPath);
  contract.persistence.audit_record_materialization = "rewriting_upsert";
  await assert.rejects(() => validateContractDocument(contract), /schema validation failed/i);
});

for (const field of ["execution_scope", "protected_audit_evidence_resolution_port", "audit_record_materialization"]) {
  test(`registry check rejects altered ${field}`, async () => {
    const contract = parseStrictYaml(await readFile(contractPath), contractPath);
    const interfaces = parseStrictYaml(
      await readFile(providerInterfacesPath),
      providerInterfacesPath,
      { maxBytes: 512 * 1024, maxNodes: 32_768 },
    );
    const registry = structuredClone(
      interfaces.reconciliation_contracts.find(({ id }) => id === contract.contract_id),
    );
    registry[field] = "weakened_boundary";
    assert.throws(() => validateProviderRegistryBoundaries(contract, registry), new RegExp(field));
  });
}

test("cross-contract check keeps eligible reads disjoint from durable effects", async () => {
  const contract = parseStrictYaml(await readFile(contractPath), contractPath);
  contract.authorization.effect_permit.required_for[0] =
    contract.authorization.provider_read_scope.eligible_calls[0];
  await assert.rejects(() => validateCrossContractBoundaries(contract), /must be disjoint/i);
});
