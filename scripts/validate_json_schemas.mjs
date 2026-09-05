#!/usr/bin/env node

import { readFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import process from "node:process";
import { execFileSync } from "node:child_process";

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

  // Validate actual emitted Go payloads, not hand-written lookalike fixtures.
  // The full canonical CloudEvent envelope also requires dataschema; the OWGP
  // references nested inside data require canonical URI as well as kind/id.
  const asyncapi = YAML.parse(await readFile("specs/asyncapi/stead.yaml", "utf8"));
  const asyncapiID = "https://stead.example/specs/asyncapi/stead.yaml";
  ajv.addSchema({ $id: asyncapiID, components: { schemas: asyncapi.components.schemas } });
  const createdEvents = JSON.parse(execFileSync("scripts/run_pinned_go.sh", ["go", "run", "./tests/contract/audit/emit_created_events"], { encoding: "utf8", timeout: 60000, maxBuffer: 1 << 20 }));
  if (!Array.isArray(createdEvents) || createdEvents.length !== 7) throw new Error("created/effect event producer fixtures missing");
  for (const event of createdEvents) {
    const envelope = event.type === "stead.authorization.effect_changed.v1" ? "AuthorizationCloudEventEnvelope" : event.data.resource.kind === "project" ? "ProjectCloudEventEnvelope" : "OrganizationCloudEventEnvelope";
    const validate = ajv.getSchema(`${asyncapiID}#/components/schemas/${envelope}`);
    if (!validate(event)) throw new Error(`emitted ${event.type} does not conform: ${ajv.errorsText(validate.errors)}`);
    for (const field of ["resource", "container"]) {
      const missingURI = structuredClone(event);
      delete missingURI.data[field].uri;
      if (validate(missingURI)) throw new Error(`created event accepted missing ${field} URI`);
    }
    const missingSchema = structuredClone(event);
    delete missingSchema.dataschema;
    if (validate(missingSchema)) throw new Error("created event accepted missing dataschema");
  }

  const profileSchemaId = "https://stead.example/policies/security-label-profiles/profile-v0.1.schema.json";
  const domainSchemaId = "https://stead.example/policies/deployment-domains/domain-profile-v0.1.schema.json";
  const domainSchema = schemas.find(({ $id }) => $id === domainSchemaId);
  const validateProfile = ajv.getSchema(profileSchemaId);
  const validateDomain = ajv.getSchema(domainSchemaId);
  if (!domainSchema?.required?.includes("disclosure_revocation_mode")) {
    throw new Error("deployment-domain schema must require disclosure_revocation_mode");
  }
  if (JSON.stringify(domainSchema?.properties?.disclosure_revocation_mode?.enum) !== JSON.stringify(["request_boundary", "commit_boundary"])) {
    throw new Error("deployment-domain disclosure_revocation_mode must be the exact closed request_boundary/commit_boundary enum");
  }
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
  const digestFile = async (path) => `sha256:${createHash("sha256").update(await readFile(path)).digest("hex")}`;
  const termKey = ({ dimension, id }) => `${dimension}:${id}`;
  const termsForProfile = (profile) => ({
    sensitivity: new Set(profile.sensitivity_order),
    handling_regime: new Set(profile.handling_regimes),
    category: new Set(profile.allowed_categories.flatMap(({ id, subcategories }) => [id, ...subcategories.map((subcategory) => `${id}/${subcategory}`)])),
    compartment_namespace: new Set(profile.allowed_compartments),
    dissemination_control: new Set(profile.dissemination_controls),
    releasability_group: new Set(profile.releasability_groups),
    export_control: new Set(profile.export_controls.map(({ id }) => id)),
  });
  const profileSemanticErrors = (profile) => {
    const errors = [];
    const vocabulary = termsForProfile(profile);
    const semanticGroups = [
      profile.semantics.implications,
      profile.semantics.incompatibilities,
      profile.semantics.sensitivity_constraints,
      profile.semantics.dimension_requirements,
      profile.semantics.context_requirements,
    ];
    const ruleIds = semanticGroups.flat().map(({ rule_id }) => rule_id);
    if (new Set(ruleIds).size !== ruleIds.length) errors.push("duplicate semantic rule ID");

    const sourceIds = profile.authoritative_sources.map(({ source_id }) => source_id);
    if (new Set(sourceIds).size !== sourceIds.length) errors.push("duplicate source ID");
    const categoryIds = profile.allowed_categories.map(({ id }) => id);
    if (new Set(categoryIds).size !== categoryIds.length) errors.push("duplicate category ID");
    const exportIds = profile.export_controls.map(({ id }) => id);
    if (new Set(exportIds).size !== exportIds.length) errors.push("duplicate export-control ID");
    const mappingIds = profile.semantics.registry_mappings.map(({ mapping_id }) => mapping_id);
    if (new Set(mappingIds).size !== mappingIds.length) errors.push("duplicate registry-mapping ID");

    const validateTerm = (term, location) => {
      if (!vocabulary[term.dimension]?.has(term.id)) errors.push(`${location} has dangling term ${termKey(term)}`);
    };
    for (const implication of profile.semantics.implications) {
      implication.when_all.forEach((term) => validateTerm(term, implication.rule_id));
      implication.require_all.forEach((term) => validateTerm(term, implication.rule_id));
    }
    for (const incompatibility of profile.semantics.incompatibilities) {
      incompatibility.all_of.forEach((term) => validateTerm(term, incompatibility.rule_id));
    }
    for (const constraint of profile.semantics.sensitivity_constraints) {
      constraint.when_any.forEach((term) => validateTerm(term, constraint.rule_id));
      constraint.allowed_sensitivity_levels.forEach((id) => {
        if (!vocabulary.sensitivity.has(id)) errors.push(`${constraint.rule_id} has dangling sensitivity ${id}`);
      });
    }
    for (const requirement of profile.semantics.dimension_requirements) {
      requirement.when_all.forEach((term) => validateTerm(term, requirement.rule_id));
    }
    for (const requirement of profile.semantics.context_requirements) {
      requirement.when_all.forEach((term) => validateTerm(term, requirement.rule_id));
    }
    for (const mapping of profile.semantics.registry_mappings) {
      validateTerm({ dimension: mapping.dimension, id: mapping.internal_id }, mapping.mapping_id);
      const source = profile.authoritative_sources.find(({ source_id }) => source_id === mapping.source_id);
      if (!source) errors.push(`${mapping.mapping_id} references unknown source ${mapping.source_id}`);
      else if (source.source_kind !== "authoritative_snapshot") errors.push(`${mapping.mapping_id} source is not an authoritative snapshot`);
      else if (mapping.mapping_provenance.source_revision !== source.source_version_or_date) errors.push(`${mapping.mapping_id} source revision is stale or mismatched`);
    }
    for (const control of profile.export_controls) {
      control.source_ids.forEach((sourceId) => {
        if (!sourceIds.includes(sourceId)) errors.push(`export control ${control.id} references unknown source ${sourceId}`);
      });
    }

    const graph = new Map();
    for (const implication of profile.semantics.implications) {
      for (const from of implication.when_all) {
        const edges = graph.get(termKey(from)) || new Set();
        implication.require_all.forEach((to) => edges.add(termKey(to)));
        graph.set(termKey(from), edges);
      }
    }
    const visiting = new Set();
    const visited = new Set();
    const cyclic = (node) => {
      if (visiting.has(node)) return true;
      if (visited.has(node)) return false;
      visiting.add(node);
      for (const target of graph.get(node) || []) if (cyclic(target)) return true;
      visiting.delete(node);
      visited.add(node);
      return false;
    };
    if ([...graph.keys()].some((node) => cyclic(node))) errors.push("cyclic semantic implication");

    for (const implication of profile.semantics.implications) {
      const closure = new Set(implication.when_all.map(termKey));
      let changed = true;
      while (changed) {
        changed = false;
        for (const rule of profile.semantics.implications) {
          if (rule.when_all.every((term) => closure.has(termKey(term)))) {
            for (const term of rule.require_all) {
              if (!closure.has(termKey(term))) {
                closure.add(termKey(term));
                changed = true;
              }
            }
          }
        }
      }
      for (const incompatibility of profile.semantics.incompatibilities) {
        if (incompatibility.all_of.every((term) => closure.has(termKey(term)))) {
          errors.push(`${implication.rule_id} implies incompatible terms from ${incompatibility.rule_id}`);
        }
      }
    }
    return errors;
  };
  const verifyProfileArtifacts = async (profile) => {
    const errors = [];
    for (const source of profile.authoritative_sources.filter(({ source_kind }) => source_kind === "authoritative_snapshot")) {
      try {
        if ((await digestFile(source.payload_path)) !== source.snapshot_digest) errors.push(`${source.source_id} snapshot digest mismatch`);
      } catch {
        errors.push(`${source.source_id} snapshot payload missing`);
      }
    }
    for (const mapping of profile.semantics.registry_mappings) {
      for (const coverage of mapping.mapping_provenance.tested_coverage) {
        try {
          if ((await digestFile(coverage.evidence_path)) !== coverage.evidence_digest) errors.push(`${mapping.mapping_id} evidence digest mismatch`);
        } catch {
          errors.push(`${mapping.mapping_id} evidence payload missing`);
        }
      }
    }
    return errors;
  };

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
    const semanticErrors = profileSemanticErrors(profile);
    const artifactErrors = await verifyProfileArtifacts(profile);
    if (semanticErrors.length > 0 || artifactErrors.length > 0) {
      throw new Error(`${path}: ${[...semanticErrors, ...artifactErrors].join("; ")}`);
    }
  }

  const syntheticProfile = profiles.get("regulated_example");
  if (!syntheticProfile || syntheticProfile.semantics.implications.length === 0 || syntheticProfile.semantics.incompatibilities.length === 0 || syntheticProfile.semantics.sensitivity_constraints.length === 0 || syntheticProfile.semantics.dimension_requirements.length === 0 || syntheticProfile.semantics.context_requirements.length === 0 || syntheticProfile.semantics.registry_mappings.length === 0) {
    throw new Error("synthetic third profile must exercise every generic semantic table without a profile-ID branch");
  }
  const unknownSemanticField = structuredClone(syntheticProfile);
  unknownSemanticField.semantics.executable = "allow";
  if (validateProfile(unknownSemanticField)) throw new Error("unknown or executable profile semantics must fail schema validation");
  const nonMonotoneImplication = structuredClone(syntheticProfile);
  nonMonotoneImplication.semantics.implications[0].require_all = [{ dimension: "releasability_group", id: "synthetic_staff" }];
  if (validateProfile(nonMonotoneImplication)) throw new Error("an implication that could broaden releasability must fail schema validation");
  const danglingTerm = structuredClone(syntheticProfile);
  danglingTerm.semantics.implications[0].require_all[0].id = "unknown_term";
  if (!profileSemanticErrors(danglingTerm).some((error) => error.includes("dangling term"))) throw new Error("dangling semantic terms must fail closed");
  const duplicateCategory = structuredClone(syntheticProfile);
  duplicateCategory.allowed_categories.push({ id: "synthetic_category", subcategories: ["different_subcategory"] });
  if (!profileSemanticErrors(duplicateCategory).includes("duplicate category ID")) throw new Error("duplicate semantic vocabulary IDs must fail closed");
  const cyclicRules = structuredClone(syntheticProfile);
  cyclicRules.semantics.implications.push({
    rule_id: "synthetic_cycle",
    when_all: [{ dimension: "handling_regime", id: "review_required" }],
    require_all: [{ dimension: "category", id: "synthetic_category" }],
  });
  if (!profileSemanticErrors(cyclicRules).includes("cyclic semantic implication")) throw new Error("cyclic semantic implications must fail closed");
  const contradictoryRules = structuredClone(syntheticProfile);
  contradictoryRules.semantics.implications[0].when_all.push({ dimension: "dissemination_control", id: "public_release" });
  if (!profileSemanticErrors(contradictoryRules).some((error) => error.includes("implies incompatible terms"))) throw new Error("contradictory semantic implications must fail closed");
  const digestMismatch = structuredClone(syntheticProfile);
  digestMismatch.authoritative_sources[0].snapshot_digest = `sha256:${"0".repeat(64)}`;
  if (!(await verifyProfileArtifacts(digestMismatch)).some((error) => error.includes("snapshot digest mismatch"))) throw new Error("source snapshot digest mismatch must fail closed");
  const evidenceMismatch = structuredClone(syntheticProfile);
  evidenceMismatch.semantics.registry_mappings[0].mapping_provenance.tested_coverage[0].evidence_digest = `sha256:${"0".repeat(64)}`;
  if (!(await verifyProfileArtifacts(evidenceMismatch)).some((error) => error.includes("evidence digest mismatch"))) throw new Error("mapping test-evidence digest mismatch must fail closed");
  const staleMapping = structuredClone(syntheticProfile);
  staleMapping.semantics.registry_mappings[0].mapping_provenance.source_revision = "stale-fixture";
  if (!profileSemanticErrors(staleMapping).some((error) => error.includes("source revision is stale or mismatched"))) throw new Error("stale mapping provenance must fail closed");
  const uriOnlyExternalProfile = structuredClone(syntheticProfile);
  uriOnlyExternalProfile.profile_id = "external_uri_only";
  uriOnlyExternalProfile.profile_purpose = "external_regime_mapping";
  uriOnlyExternalProfile.authoritative_sources = [{ source_kind: "reference", source_id: "live_uri", title: "Live URI only", uri: "https://example.invalid/registry", source_version_or_date: "today", mapped_scope: "unverified" }];
  uriOnlyExternalProfile.semantics.registry_mappings = [];
  if (validateProfile(uriOnlyExternalProfile)) throw new Error("external-regime mappings with URI/date-only provenance must fail schema validation");

  const productionDomainPaths = await yamlFiles("policies/deployment-domains");
  const fixtureDomainPaths = await yamlFiles("tests/contract/fixtures/deployment-domains");
  const domainEntries = await Promise.all(
    [...productionDomainPaths, ...fixtureDomainPaths].map(async (path) => [path, await readYaml(path)]),
  );

  const domainErrors = (domain) => {
    const errors = [];
    for (const [profileId, binding] of Object.entries(domain.label_profile_ceilings)) {
      const profile = profiles.get(profileId);
      if (!profile) {
        errors.push(`unknown profile ${profileId}`);
        continue;
      }
      if (profile.version !== binding.profile_version) errors.push(`profile version mismatch for ${profileId}`);
      if (!profile.sensitivity_order.includes(binding.classification_ceiling)) {
        errors.push(`foreign or unknown ceiling ${binding.classification_ceiling} for ${profileId}`);
      }
    }
    if (domain.approved_profile_bridges.length !== 0) errors.push("v0.1 rejects every non-empty profile bridge set");
    return errors;
  };

  for (const [path, domain] of domainEntries) {
    if (!validateDomain(domain)) {
      throw new Error(`${path} does not conform to the deployment-domain schema: ${ajv.errorsText(validateDomain.errors)}`);
    }
    const errors = domainErrors(domain);
    if (errors.length > 0) throw new Error(`${path}: ${errors.join("; ")}`);
  }

  for (const starterName of ["commercial.yaml", "us-government.yaml"]) {
    const starter = domainEntries.find(([path]) => path === `policies/deployment-domains/${starterName}`)?.[1];
    if (starter?.disclosure_revocation_mode !== "request_boundary") {
      throw new Error(`${starterName} must select request_boundary explicitly`);
    }
  }

  const multiProfileFixture = domainEntries.find(([path]) => path.endsWith("multi-profile-high-assurance.yaml"))?.[1];
  if (!multiProfileFixture || multiProfileFixture.approved_profile_bridges.length !== 0) {
    throw new Error("synthetic multi-profile domain must prove fail-closed composition without a bridge");
  }
  if (
    Object.hasOwn(multiProfileFixture.label_profile_ceilings, "us_government") ||
    !Object.hasOwn(multiProfileFixture.label_profile_ceilings, "commercial") ||
    multiProfileFixture.disclosure_revocation_mode !== "commit_boundary" ||
    multiProfileFixture.assurance.policy_signature_threshold < 2 ||
    !multiProfileFixture.assurance.validated_cryptographic_module_required ||
    multiProfileFixture.assurance.lowering_approval_threshold !== 3 ||
    syntheticProfile.lowering_approval.minimum_approvers !== 3
  ) {
    throw new Error("synthetic non-government domain must prove profile-neutral high-assurance and threshold-three controls");
  }

  const missingDisclosureMode = structuredClone(multiProfileFixture);
  delete missingDisclosureMode.disclosure_revocation_mode;
  if (validateDomain(missingDisclosureMode)) {
    throw new Error("deployment-domain schema must reject a missing disclosure_revocation_mode");
  }
  const unknownDisclosureMode = structuredClone(multiProfileFixture);
  unknownDisclosureMode.disclosure_revocation_mode = "profile_selected";
  if (validateDomain(unknownDisclosureMode)) {
    throw new Error("deployment-domain schema must reject an unknown disclosure_revocation_mode");
  }

  const validateCeilingMap = ajv.getSchema(`${domainSchemaId}#/$defs/ProfileCeilingMap`);
  if (!validateCeilingMap || !validateCeilingMap(multiProfileFixture.label_profile_ceilings)) throw new Error("shared profile-ceiling map did not validate");
  if (validateCeilingMap([
    { profile_id: "commercial", profile_version: "1.0.0", classification_ceiling: "internal" },
    { profile_id: "commercial", profile_version: "9.9.9", classification_ceiling: "restricted" },
  ])) {
    throw new Error("array-shaped duplicate/conflicting runtime ceilings must be structurally rejected");
  }
  const foreignCeiling = structuredClone(multiProfileFixture);
  foreignCeiling.label_profile_ceilings.commercial.classification_ceiling = "TOP_SECRET";
  if (!domainErrors(foreignCeiling).some((error) => error.startsWith("foreign or unknown ceiling"))) {
    throw new Error("a sensitivity value from another vocabulary must fail closed");
  }
  const forbiddenBridge = structuredClone(multiProfileFixture);
  forbiddenBridge.approved_profile_bridges.push({
    bridge_id: "synthetic_bridge",
    from_profile_id: "commercial",
    from_profile_version: "1.0.0",
    to_profile_id: "regulated_example",
    to_profile_version: "7.2.1",
    direction: "from_to",
    operations: ["join"],
    signed_approval_digest: `sha256:${"0".repeat(64)}`,
  });
  if (validateDomain(forbiddenBridge) || !domainErrors(forbiddenBridge).includes("v0.1 rejects every non-empty profile bridge set")) {
    throw new Error("the v0.1 deployment-domain contract must reject every non-empty bridge list");
  }

  const allowedByCeiling = (domain, label) => {
    const binding = domain.label_profile_ceilings[label.profile_id];
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

  const validatePolicyOutput = ajv.getSchema("https://stead.example/policies/policy-decision/output-v0.1.schema.json");
  for (const minimumApprovers of [1, 2, 3]) {
    const output = {
      allow: true,
      decision_id: `decision-${minimumApprovers}`,
      policy_bundle_id: "activation-set-example",
      reason_codes: ["lowering_authorized"],
      obligations: ["require_approval_threshold"],
      approval_requirement: {
        minimum_approvers: minimumApprovers,
        distinct_approvers: true,
        human_approvers_required: minimumApprovers > 1,
        policy_basis: [
          { source_kind: "security_label_profile", source_id: "regulated_example", source_version: "7.2.1" },
          { source_kind: "deployment_domain", source_id: "high-assurance-private-example", source_version: "3.0.0" },
        ],
      },
      cache: { permitted: false, max_age_seconds: 0, invalidation_keys: [] },
    };
    if (!validatePolicyOutput(output)) throw new Error(`generic policy output could not represent approval threshold ${minimumApprovers}: ${ajv.errorsText(validatePolicyOutput.errors)}`);
  }
  const missingApprovalData = {
    allow: true,
    decision_id: "decision-missing-approval-data",
    policy_bundle_id: "activation-set-example",
    reason_codes: ["lowering_authorized"],
    obligations: ["require_approval_threshold"],
    cache: { permitted: false, max_age_seconds: 0, invalidation_keys: [] },
  };
  if (validatePolicyOutput(missingApprovalData)) throw new Error("approval-threshold obligation without parameter data must fail closed");
  const incompleteApprovalBasis = {
    ...missingApprovalData,
    approval_requirement: {
      minimum_approvers: 3,
      distinct_approvers: true,
      human_approvers_required: true,
      policy_basis: [{ source_kind: "security_label_profile", source_id: "regulated_example", source_version: "7.2.1" }],
    },
  };
  if (validatePolicyOutput(incompleteApprovalBasis)) throw new Error("approval threshold without both profile and deployment policy bases must fail closed");

  console.log(
    `Standalone JSON Schema validation passed: ${schemas.length}/${paths.length} schemas, ${profileEntries.length} profiles, and ${domainEntries.length} deployment domains.`,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
