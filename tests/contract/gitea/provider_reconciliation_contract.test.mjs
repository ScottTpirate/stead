import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  parseStrictYaml,
  validateContractDocument,
  validateCrossContractBoundaries,
  validateRepositoryContract,
} from "../../../scripts/validate_provider_reconciliation.mjs";

const contractPath = "specs/provider-reconciliation/gitea-v1.yaml";
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

test("cross-contract check keeps eligible reads disjoint from durable effects", async () => {
  const contract = parseStrictYaml(await readFile(contractPath), contractPath);
  contract.authorization.effect_permit.required_for[0] =
    contract.authorization.provider_read_scope.eligible_calls[0];
  await assert.rejects(() => validateCrossContractBoundaries(contract), /must be disjoint/i);
});
