#!/usr/bin/env node

import { readFile, readdir } from "node:fs/promises";
import process from "node:process";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML from "yaml";

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

  const profileSchemaId = "https://stead.example/policies/security-label-profiles/profile-v0.1.schema.json";
  const domainSchemaId = "https://stead.example/policies/deployment-domains/domain-profile-v0.1.schema.json";
  const validateProfile = ajv.getSchema(profileSchemaId);
  const validateDomain = ajv.getSchema(domainSchemaId);
  const yamlFiles = async (directory) =>
    (await readdir(directory))
      .filter((name) => name.endsWith(".yaml"))
      .sort()
      .map((name) => `${directory}/${name}`);
  const readYaml = async (path) => YAML.parse(await readFile(path, "utf8"));

  const productionProfilePaths = await yamlFiles("policies/security-label-profiles");
  const fixtureProfilePaths = await yamlFiles("tests/contract/fixtures/security-label-profiles");
  const profileEntries = await Promise.all(
    [...productionProfilePaths, ...fixtureProfilePaths].map(async (path) => [path, await readYaml(path)]),
  );
  const profiles = new Map();
  for (const [path, profile] of profileEntries) {
    if (!validateProfile(profile)) {
      throw new Error(`${path} does not conform to the declarative profile schema: ${ajv.errorsText(validateProfile.errors)}`);
    }
    if (profiles.has(profile.profile_id)) {
      throw new Error(`${path} repeats profile_id ${profile.profile_id}`);
    }
    profiles.set(profile.profile_id, profile);

    const sensitivityIds = profile.sensitivity_order;
    const markingIds = profile.presentation.sensitivity_markings.map(({ id }) => id);
    if (JSON.stringify(sensitivityIds) !== JSON.stringify(markingIds)) {
      throw new Error(`${path} presentation must cover every sensitivity ID exactly and in canonical order`);
    }
    if (profile.profile_purpose === "external_regime_mapping" && profile.authoritative_sources.length === 0) {
      throw new Error(`${path} claims an external regime without authoritative source provenance`);
    }
  }

  const productionDomainPaths = await yamlFiles("policies/deployment-domains");
  const fixtureDomainPaths = await yamlFiles("tests/contract/fixtures/deployment-domains");
  const domainEntries = await Promise.all(
    [...productionDomainPaths, ...fixtureDomainPaths].map(async (path) => [path, await readYaml(path)]),
  );

  const domainErrors = (domain) => {
    const errors = [];
    const profileIds = domain.label_profile_ceilings.map(({ profile_id }) => profile_id);
    if (new Set(profileIds).size !== profileIds.length) errors.push("duplicate profile ceiling");

    for (const binding of domain.label_profile_ceilings) {
      const profile = profiles.get(binding.profile_id);
      if (!profile) {
        errors.push(`unknown profile ${binding.profile_id}`);
        continue;
      }
      if (profile.version !== binding.profile_version) errors.push(`profile version mismatch for ${binding.profile_id}`);
      if (!profile.sensitivity_order.includes(binding.classification_ceiling)) {
        errors.push(`foreign or unknown ceiling ${binding.classification_ceiling} for ${binding.profile_id}`);
      }
    }

    for (const bridge of domain.approved_profile_bridges) {
      if (bridge.from_profile_id === bridge.to_profile_id) errors.push(`bridge ${bridge.bridge_id} is not cross-profile`);
      const fromBinding = domain.label_profile_ceilings.find(({ profile_id }) => profile_id === bridge.from_profile_id);
      const toBinding = domain.label_profile_ceilings.find(({ profile_id }) => profile_id === bridge.to_profile_id);
      if (!fromBinding || !toBinding) {
        errors.push(`bridge ${bridge.bridge_id} references a profile without a domain ceiling`);
        continue;
      }
      if (bridge.from_profile_version !== fromBinding.profile_version) errors.push(`bridge ${bridge.bridge_id} from-version mismatch`);
      if (bridge.to_profile_version !== toBinding.profile_version) errors.push(`bridge ${bridge.bridge_id} to-version mismatch`);
    }
    return errors;
  };

  for (const [path, domain] of domainEntries) {
    if (!validateDomain(domain)) {
      throw new Error(`${path} does not conform to the deployment-domain schema: ${ajv.errorsText(validateDomain.errors)}`);
    }
    const errors = domainErrors(domain);
    if (errors.length > 0) throw new Error(`${path}: ${errors.join("; ")}`);
  }

  const multiProfileFixture = domainEntries.find(([path]) => path.endsWith("multi-profile-high-assurance.yaml"))?.[1];
  if (!multiProfileFixture || multiProfileFixture.approved_profile_bridges.length !== 0) {
    throw new Error("synthetic multi-profile domain must prove fail-closed composition without a bridge");
  }
  if (
    multiProfileFixture.label_profile_ceilings.some(({ profile_id }) => profile_id === "us_government") ||
    multiProfileFixture.assurance.policy_signature_threshold < 2 ||
    !multiProfileFixture.assurance.validated_cryptographic_module_required
  ) {
    throw new Error("synthetic non-government domain must prove profile-neutral high-assurance controls");
  }

  const duplicateCeiling = structuredClone(multiProfileFixture);
  duplicateCeiling.label_profile_ceilings.push(structuredClone(duplicateCeiling.label_profile_ceilings[0]));
  if (!domainErrors(duplicateCeiling).includes("duplicate profile ceiling")) {
    throw new Error("duplicate per-profile ceiling must fail closed");
  }
  const foreignCeiling = structuredClone(multiProfileFixture);
  foreignCeiling.label_profile_ceilings[0].classification_ceiling = "TOP_SECRET";
  if (!domainErrors(foreignCeiling).some((error) => error.startsWith("foreign or unknown ceiling"))) {
    throw new Error("a sensitivity value from another vocabulary must fail closed");
  }
  const mismatchedBridge = structuredClone(multiProfileFixture);
  mismatchedBridge.approved_profile_bridges.push({
    bridge_id: "synthetic_bridge",
    from_profile_id: "commercial",
    from_profile_version: "9.9.9",
    to_profile_id: "regulated_example",
    to_profile_version: "7.2.1",
    direction: "from_to",
    signed_approval_digest: `sha256:${"0".repeat(64)}`,
  });
  if (!domainErrors(mismatchedBridge).includes("bridge synthetic_bridge from-version mismatch")) {
    throw new Error("a signed bridge whose profile version differs from the ceiling binding must fail closed");
  }

  const allowedByCeiling = (domain, label) => {
    const binding = domain.label_profile_ceilings.find(({ profile_id }) => profile_id === label.profile_id);
    const profile = profiles.get(label.profile_id);
    if (!binding || !profile || binding.profile_version !== profile.version) return false;
    const valueIndex = profile.sensitivity_order.indexOf(label.sensitivity_level);
    const ceilingIndex = profile.sensitivity_order.indexOf(binding.classification_ceiling);
    return valueIndex >= 0 && ceilingIndex >= 0 && valueIndex <= ceilingIndex;
  };
  if (
    !allowedByCeiling(multiProfileFixture, { profile_id: "commercial", sensitivity_level: "internal" }) ||
    allowedByCeiling(multiProfileFixture, { profile_id: "commercial", sensitivity_level: "restricted" }) ||
    allowedByCeiling(multiProfileFixture, { profile_id: "unknown_profile", sensitivity_level: "internal" })
  ) {
    throw new Error("profile-qualified ceiling evaluation must allow only known values at or below the matching profile ceiling");
  }

  console.log(
    `Standalone JSON Schema validation passed: ${schemas.length}/${paths.length} schemas, ${profileEntries.length} profiles, and ${domainEntries.length} deployment domains.`,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
