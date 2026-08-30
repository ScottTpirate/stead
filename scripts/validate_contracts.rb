#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "pathname"
require "set"
require "uri"
require "yaml"

ROOT = Pathname.new(__dir__).parent.expand_path

PROFILE_SOURCE_DOCUMENTS = Dir.glob(ROOT.join("policies/security-label-profiles/*.yaml")).sort.map do |path|
  Pathname.new(path).relative_path_from(ROOT).to_s
end.freeze
DEPLOYMENT_DOMAIN_DOCUMENTS = Dir.glob(ROOT.join("policies/deployment-domains/*.yaml")).sort.map do |path|
  Pathname.new(path).relative_path_from(ROOT).to_s
end.freeze
HIGH_ASSURANCE_DOMAIN_FIXTURE = "tests/contract/fixtures/deployment-domains/multi-profile-high-assurance.yaml"

DOCUMENTS = %w[
  specs/schema-registry.yaml
  specs/work-graph-profile/owgp-v0.1.schema.json
  specs/openapi/platform-v1.yaml
  specs/asyncapi/stead.yaml
  specs/provider-interfaces.yaml
  specs/mcp/compatibility-v0.1.yaml
  specs/migration/migration-job-v0.1.schema.json
  specs/migration/canonical-model-v0.1.yaml
  packages/event-schemas/common/actor-context/actor-context-v0.1.schema.json
  packages/event-schemas/stead/stead-event-v0.1.schema.json
  policies/policy-decision/input-v0.1.schema.json
  policies/policy-decision/output-v0.1.schema.json
  policies/policy-decision/decision-table.yaml
  policies/security-label-profiles/profile-v0.1.schema.json
  policies/deployment-domains/domain-profile-v0.1.schema.json
  policies/openfga/model-tests.yaml
] + PROFILE_SOURCE_DOCUMENTS + DEPLOYMENT_DOMAIN_DOCUMENTS + [HIGH_ASSURANCE_DOMAIN_FIXTURE]
DOCUMENTS.freeze

JSON_SCHEMA_DOCUMENTS = %w[
  specs/work-graph-profile/owgp-v0.1.schema.json
  packages/event-schemas/common/actor-context/actor-context-v0.1.schema.json
  packages/event-schemas/stead/stead-event-v0.1.schema.json
  policies/policy-decision/input-v0.1.schema.json
  policies/policy-decision/output-v0.1.schema.json
  specs/migration/migration-job-v0.1.schema.json
  policies/security-label-profiles/profile-v0.1.schema.json
  policies/deployment-domains/domain-profile-v0.1.schema.json
].freeze

CANONICAL_KINDS = %w[
  instance organization user directory_group agent agent_run service_principal team
  initiative project cycle work_item document repository branch commit pull_request
  build deployment release package artifact attachment comment activity notification
  audit_record security_label
].freeze

FINAL_DEFINITIONS = %w[
  Instance Organization User DirectoryGroup Agent AgentRun ServicePrincipal Team
  Initiative Project Cycle WorkItem Document Repository Branch Commit PullRequest
  Build Deployment Release Package Artifact Attachment Comment Activity Notification
  AuditRecord SecurityLabel
].freeze

EXPECTED_EVENT_CATALOG = {
  "organizationEvents" => %w[stead.organization.created.v1 stead.organization.updated.v1 stead.team.created.v1 stead.team.updated.v1 stead.team.reparented.v1 stead.team.membership_changed.v1],
  "identityEvents" => %w[stead.identity.provisioned.v1 stead.identity.updated.v1 stead.identity.suspended.v1 stead.agent.registered.v1 stead.agent.revoked.v1],
  "authorizationEvents" => %w[stead.authorization.model_activated.v1 stead.authorization.tuple_changed.v1 stead.authorization.delegation_revoked.v1 stead.authorization.policy_activated.v1],
  "classificationEvents" => %w[stead.classification.label_raised.v1 stead.classification.label_lowered.v1 stead.classification.profile_activated.v1 stead.classification.ceiling_changed.v1 stead.classification.attribute_changed.v1],
  "projectEvents" => %w[stead.project.created.v1 stead.project.updated.v1 stead.project.capability_changed.v1 stead.initiative.changed.v1 stead.cycle.changed.v1],
  "workEvents" => %w[stead.workitem.created.v1 stead.workitem.updated.v1 stead.workitem.assigned.v1 stead.workitem.related.v1],
  "commentEvents" => %w[stead.comment.created.v1 stead.comment.updated.v1 stead.comment.deleted.v1],
  "knowledgeEvents" => %w[stead.document.created.v1 stead.document.updated.v1 stead.document.review_requested.v1 stead.document.approved.v1 stead.document.superseded.v1],
  "scmEvents" => %w[stead.scm.repository_changed.v1 stead.scm.branch_changed.v1 stead.scm.commit_recorded.v1 stead.scm.pull_request_changed.v1 stead.scm.reconciled.v1],
  "ciEvents" => %w[stead.ci.build_changed.v1 stead.ci.deployment_changed.v1 stead.ci.runner_changed.v1 stead.ci.action_changed.v1],
  "artifactEvents" => %w[stead.artifact.artifact_changed.v1 stead.artifact.package_changed.v1 stead.artifact.release_changed.v1],
  "attachmentEvents" => %w[stead.attachment.created.v1 stead.attachment.scanned.v1 stead.attachment.deleted.v1],
  "storageEvents" => %w[stead.storage.scan_changed.v1 stead.storage.retention_changed.v1 stead.storage.provider_operation_changed.v1],
  "searchGraphEvents" => %w[stead.search_graph.rebuild_started.v1 stead.search_graph.rebuild_completed.v1 stead.search_graph.rebuild_failed.v1],
  "notificationEvents" => %w[stead.notification.created.v1 stead.notification.read.v1 stead.notification.delivery_changed.v1 stead.notification.suppressed.v1],
  "auditEvents" => %w[stead.audit.checkpoint_created.v1 stead.audit.export_changed.v1],
  "migrationEvents" => %w[stead.migration.stage_changed.v1 stead.migration.reconciled.v1 stead.migration.cutover_changed.v1],
  "operationsEvents" => %w[stead.operations.install_changed.v1 stead.operations.upgrade_changed.v1 stead.operations.backup_changed.v1 stead.operations.restore_changed.v1 stead.operations.doctor_changed.v1],
  "deadLetterEvents" => %w[stead.dead_letter.recorded.v1 stead.dead_letter.replayed.v1]
}.freeze

def parse(path)
  source = path.read(encoding: "UTF-8")
  return JSON.parse(source) if path.extname == ".json"

  YAML.safe_load(source, permitted_classes: [], permitted_symbols: [], aliases: false, filename: path.to_s)
end

def each_node(value, &block)
  yield value
  case value
  when Hash
    value.each_value { |child| each_node(child, &block) }
  when Array
    value.each { |child| each_node(child, &block) }
  end
end

def validate_instance(value, schema, location, failures)
  expected_type = schema["type"]
  type_matches = case expected_type
                 when "object" then value.is_a?(Hash)
                 when "array" then value.is_a?(Array)
                 when "string" then value.is_a?(String)
                 when "integer" then value.is_a?(Integer)
                 when "boolean" then value == true || value == false
                 when nil then true
                 else true
                 end
  unless type_matches
    failures << "#{location}: expected #{expected_type}"
    return
  end

  failures << "#{location}: expected constant #{schema['const'].inspect}" if schema.key?("const") && value != schema["const"]
  failures << "#{location}: value is outside enum" if schema["enum"].is_a?(Array) && !schema["enum"].include?(value)

  if value.is_a?(Hash)
    Array(schema["required"]).each do |key|
      failures << "#{location}: missing #{key}" unless value.key?(key)
    end
    properties = schema["properties"] || {}
    value.each do |key, child|
      validate_instance(child, properties[key], "#{location}.#{key}", failures) if properties[key]
      failures << "#{location}: unexpected property #{key}" if schema["additionalProperties"] == false && !properties.key?(key)
    end
  elsif value.is_a?(Array)
    failures << "#{location}: too few items" if schema["minItems"] && value.length < schema["minItems"]
    failures << "#{location}: duplicate items" if schema["uniqueItems"] && value.uniq.length != value.length
    value.each_with_index { |child, index| validate_instance(child, schema["items"], "#{location}[#{index}]", failures) } if schema["items"]
  end
end

def pointer(document, fragment)
  return document if fragment.nil? || fragment.empty?
  raise "fragment must be a JSON Pointer" unless fragment.start_with?("/")

  fragment.split("/").drop(1).reduce(document) do |value, token|
    key = token.gsub("~1", "/").gsub("~0", "~")
    value.fetch(value.is_a?(Array) ? Integer(key, 10) : key)
  end
end

failures = []
documents = {}

DOCUMENTS.each do |relative|
  path = ROOT.join(relative)
  begin
    documents[relative] = parse(path)
  rescue StandardError => error
    failures << "#{relative}: cannot parse contract (#{error.message.lines.first.strip})"
  end
end

schema_ids = {}
JSON_SCHEMA_DOCUMENTS.each do |relative|
  schema_id = documents.dig(relative, "$id")
  if schema_id.is_a?(String) && !schema_id.empty?
    failures << "duplicate canonical schema $id #{schema_id}" if schema_ids.key?(schema_id)
    schema_ids[schema_id] = relative
  else
    failures << "#{relative}: canonical JSON Schema must declare $id"
  end
end

registry_entries = Array(documents.dig("specs/schema-registry.yaml", "schemas"))
registry_map = registry_entries.each_with_object({}) do |entry, map|
  next unless entry.is_a?(Hash)

  schema_id = entry["id"]
  path = entry["path"]
  failures << "schema registry contains duplicate id #{schema_id}" if map.key?(schema_id)
  map[schema_id] = path
  failures << "schema registry #{schema_id} points to unknown path #{path}" unless JSON_SCHEMA_DOCUMENTS.include?(path)
  failures << "schema registry #{schema_id} does not match #{path} $id" unless documents.dig(path, "$id") == schema_id
end
missing_registry_ids = schema_ids.keys - registry_map.keys
unexpected_registry_ids = registry_map.keys - schema_ids.keys
failures << "schema registry omits canonical ids: #{missing_registry_ids.join(', ')}" unless missing_registry_ids.empty?
failures << "schema registry has unknown ids: #{unexpected_registry_ids.join(', ')}" unless unexpected_registry_ids.empty?

documents.each do |relative, document|
  each_node(document) do |node|
    next unless node.is_a?(Hash) && node["$ref"].is_a?(String)

    reference = node["$ref"]
    file_part, fragment = reference.split("#", 2)
    target_relative = if reference.match?(%r{\Ahttps?://})
                        registry_map[file_part]
                      elsif file_part.nil? || file_part.empty?
                        relative
                      else
                        ROOT.join(relative).dirname.join(file_part).cleanpath.relative_path_from(ROOT).to_s
                      end
    begin
      raise "canonical schema id is not registered" unless target_relative

      target_document = documents[target_relative] ||= parse(ROOT.join(target_relative))
      if JSON_SCHEMA_DOCUMENTS.include?(relative) && file_part && !file_part.empty? && !reference.match?(%r{\Ahttps?://})
        resolved_id = URI.join(document.fetch("$id"), file_part).to_s
        expected_id = target_document["$id"]
        raise "relative ref resolves to #{resolved_id}, not target $id #{expected_id}" unless resolved_id == expected_id
      end
      pointer(target_document, fragment)
    rescue StandardError => error
      failures << "#{relative}: unresolved $ref #{reference.inspect} (#{error.message.lines.first.strip})"
    end
  end
end

owgp = documents["specs/work-graph-profile/owgp-v0.1.schema.json"] || {}
definitions = owgp["$defs"] || {}
resource_kinds = definitions.dig("ResourceRef", "properties", "kind", "enum") || []
failures << "OWGP ResourceRef canonical kind enum mismatch" unless resource_kinds == CANONICAL_KINDS
assignee_kinds = definitions.dig("WorkAssigneeRef", "allOf", 1, "properties", "type", "enum") || []
failures << "OWGP WorkAssigneeRef must be exactly user or agent" unless assignee_kinds == %w[user agent]
missing_definitions = FINAL_DEFINITIONS - definitions.keys
failures << "OWGP omits fixed entities: #{missing_definitions.join(', ')}" unless missing_definitions.empty?
failures << "OWGP omits the profile-driven SecurityPresentation contract" unless definitions.key?("SecurityPresentation")
resource_envelope_required = Array(definitions.dig("ResourceEnvelope", "required"))
failures << "Every authorized resource representation must carry server-derived security presentation data" unless resource_envelope_required.include?("security_presentation")
FINAL_DEFINITIONS.each do |name|
  definition = definitions[name]
  next unless definition
  failures << "OWGP #{name} must reject unevaluated properties" unless definition["unevaluatedProperties"] == false
end
union_refs = Array(owgp["oneOf"]).filter_map { |entry| entry["$ref"]&.split("/")&.last }
missing_union_members = FINAL_DEFINITIONS - union_refs
failures << "OWGP top-level union omits: #{missing_union_members.join(', ')}" unless missing_union_members.empty?

openapi = documents["specs/openapi/platform-v1.yaml"] || {}
failures << "OpenAPI version must be 3.1.1" unless openapi["openapi"] == "3.1.1"
operations = Array(openapi["paths"]).flat_map do |_path, path_item|
  path_item.select { |method, operation| %w[get post put patch delete].include?(method) && operation.is_a?(Hash) }.values
end
operation_ids = operations.filter_map { |operation| operation["operationId"] }
failures << "OpenAPI operationId values must be unique" unless operation_ids.uniq.length == operation_ids.length
%w[/organizations/{organization_id}/documents /teams/{team_id}/documents /projects/{project_id}/documents].each do |path|
  failures << "OpenAPI omits scoped document path #{path}" unless openapi.dig("paths", path, "get")
end
failures << "OpenAPI must not use an ambiguous /documents list endpoint" if openapi.dig("paths", "/documents")
create_ref = openapi.dig("paths", "/projects/{project_id}/work-items", "post", "requestBody", "content", "application/json", "schema", "$ref")
failures << "OpenAPI create Work Item must use WorkItemCreate" unless create_ref == "#/components/schemas/WorkItemCreate"
patch_parameters = openapi.dig("paths", "/work-items/{work_item_id}", "patch", "parameters") || []
failures << "OpenAPI Work Item update must require If-Match" unless patch_parameters.any? { |entry| entry["$ref"] == "#/components/parameters/IfMatch" }
project_view_ref = openapi.dig("paths", "/projects/{project_id}", "get", "responses", "200", "$ref")
failures << "OpenAPI Project read must use filtered ProjectView" unless project_view_ref == "#/components/responses/ProjectView"
failures << "OpenAPI SearchResult must reject undeclared disclosure fields" unless openapi.dig("components", "schemas", "SearchResult", "additionalProperties") == false
%w[ProjectView SearchResult].each do |schema_name|
  presentation_ref = openapi.dig("components", "schemas", schema_name, "properties", "security_presentation", "$ref")
  failures << "OpenAPI #{schema_name} must expose the shared profile-driven security presentation" unless presentation_ref == "../work-graph-profile/owgp-v0.1.schema.json#/$defs/SecurityPresentation"
end
failures << "OpenAPI Problem must reject undeclared disclosure fields" unless openapi.dig("components", "schemas", "Problem", "additionalProperties") == false
search_results_schema = openapi.dig("components", "responses", "SearchResults", "content", "application/json", "schema") || {}
failures << "OpenAPI SearchResults wrapper must reject undeclared aggregate fields" unless search_results_schema["additionalProperties"] == false

asyncapi = documents["specs/asyncapi/stead.yaml"] || {}
failures << "AsyncAPI version must be 3.1.x" unless asyncapi["asyncapi"].to_s.start_with?("3.1.")
event_type_pattern = asyncapi.dig("components", "schemas", "SteadCloudEventEnvelope", "properties", "type", "pattern")
failures << "AsyncAPI base CloudEvent envelope must enforce the Stead event namespace" unless event_type_pattern == '^stead\\.[a-z0-9_]+\\.[a-z0-9_]+\\.v[1-9][0-9]*$'
operation_refs = Array(asyncapi["operations"]).each_with_object(Hash.new { |hash, key| hash[key] = Set.new }) do |(_name, operation), refs|
  refs[operation["action"]] << operation.dig("channel", "$ref")
end
(asyncapi["channels"] || {}).each_key do |channel|
  reference = "#/channels/#{channel}"
  failures << "AsyncAPI channel #{channel} has no send operation" unless operation_refs["send"].include?(reference)
  failures << "AsyncAPI channel #{channel} has no receive operation" unless operation_refs["receive"].include?(reference)
end
required_event_channels = EXPECTED_EVENT_CATALOG.keys
missing_event_channels = required_event_channels - (asyncapi["channels"] || {}).keys
failures << "AsyncAPI omits event catalog channels: #{missing_event_channels.join(', ')}" unless missing_event_channels.empty?
unexpected_event_channels = (asyncapi["channels"] || {}).keys - required_event_channels
failures << "AsyncAPI adds unapproved event catalog channels: #{unexpected_event_channels.join(', ')}" unless unexpected_event_channels.empty?
(asyncapi["channels"] || {}).each do |channel, contract|
  address = contract["address"]
  unless address.is_a?(String) && address.match?(%r{\Astead\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\z})
    failures << "AsyncAPI channel #{channel} address must use stead.<domain>.<action>.v<major>"
  end

  declared_types = contract["x-event-types"]
  failures << "AsyncAPI channel #{channel} must enumerate event types" unless declared_types.is_a?(Array) && !declared_types.empty?
  failures << "AsyncAPI channel #{channel} differs from the approved event catalog" unless declared_types == EXPECTED_EVENT_CATALOG[channel]

  message_refs = Array(contract["messages"]).filter_map { |_name, message| message["$ref"] }
  if message_refs.length != 1
    failures << "AsyncAPI channel #{channel} must bind exactly one event-family message"
    next
  end

  begin
    message = pointer(asyncapi, message_refs.first.delete_prefix("#"))
    payload_ref = message.dig("payload", "$ref")
    payload = pointer(asyncapi, payload_ref.to_s.delete_prefix("#"))
    constrained_types = payload.dig("allOf", 1, "properties", "type", "enum")
    failures << "AsyncAPI channel #{channel} family schema must enforce its declared event types" unless constrained_types == declared_types
  rescue StandardError => error
    failures << "AsyncAPI channel #{channel} has an invalid event-family binding (#{error.message.lines.first.strip})"
  end
end
all_event_types = (asyncapi["channels"] || {}).values.flat_map { |contract| Array(contract["x-event-types"]) }
failures << "AsyncAPI event type values must belong to exactly one channel family" unless all_event_types.uniq.length == all_event_types.length

event_data = documents["packages/event-schemas/stead/stead-event-v0.1.schema.json"] || {}
event_required = event_data["required"] || []
failures << "Event data must require idempotency_key" unless event_required.include?("idempotency_key")
failures << "Event data must not require capability context" if event_required.include?("capability_context") || event_required.include?("capabilities")
actor_required = documents.dig("packages/event-schemas/common/actor-context/actor-context-v0.1.schema.json", "required") || []
failures << "Actor context must require correlation and causation IDs" unless %w[correlation_id causation_id].all? { |field| actor_required.include?(field) }

providers = documents["specs/provider-interfaces.yaml"] || {}
Array(providers["interfaces"]).each do |interface|
  failures << "Provider #{interface['id']} has no operation contract" unless interface["operations"].is_a?(Array) && !interface["operations"].empty?
end
failures << "Provider common contract omits operation semantics" unless providers.dig("common_contract", "operation_semantics").is_a?(Hash)

label_schema = documents["policies/security-label-profiles/profile-v0.1.schema.json"] || {}
required_label_fields = %w[profile_purpose scope authoritative_sources allowed_categories allowed_compartments dissemination_controls releasability_groups export_controls normalization dominance join releasable_to_join cross_profile_composition lowering lowering_approval semantics presentation bundle_signing]
missing_label_fields = required_label_fields - Array(label_schema["required"])
failures << "Security-label profile schema omits: #{missing_label_fields.join(', ')}" unless missing_label_fields.empty?
profiles_by_id = {}
PROFILE_SOURCE_DOCUMENTS.each do |path|
  name = File.basename(path, ".yaml")
  profile = documents[path] || {}
  missing = Array(label_schema["required"]) - profile.keys
  failures << "#{name} label profile omits: #{missing.join(', ')}" unless missing.empty?
  validate_instance(profile, label_schema, "#{name} label profile", failures)
  profile_id = profile["profile_id"]
  failures << "#{name} label profile repeats profile_id #{profile_id}" if profiles_by_id.key?(profile_id)
  profiles_by_id[profile_id] = profile
  failures << "#{name} label profile version must be semantic x.y.z" unless profile["version"].to_s.match?(/\A\d+\.\d+\.\d+\z/)
  sensitivity_ids = Array(profile["sensitivity_order"])
  marking_ids = Array(profile.dig("presentation", "sensitivity_markings")).map { |marking| marking["id"] }
  failures << "#{name} label profile presentation must cover every sensitivity in canonical order" unless marking_ids == sensitivity_ids
  if profile["profile_purpose"] == "external_regime_mapping" && Array(profile["authoritative_sources"]).empty?
    failures << "#{name} external-regime profile must identify authoritative sources"
  end
  failures << "#{name} label profile must use the closed Stead semantic-rule contract" unless profile.dig("semantics", "rule_contract") == "stead.security-profile-rules.v1" && profile.dig("semantics", "representability") == "closed_profile_semantics_v1" && profile.dig("semantics", "unmapped_behavior") == "deny"
  failures << "#{name} label profile must be activated only through the Stead Policy Activation Set" unless profile.dig("bundle_signing", "format") == "stead-policy-activation-set-dsse-v1"
end
%w[commercial us_government].each do |reference_profile_id|
  failures << "Starter/reference profile #{reference_profile_id} must remain available as non-privileged data" unless profiles_by_id.key?(reference_profile_id)
end
government_reference = profiles_by_id["us_government"] || {}
government_categories = Array(government_reference["allowed_categories"])
failures << "US-government starter profile must enumerate its limited CUI test mappings" unless government_categories.any? { |entry| entry["id"].to_s.start_with?("CUI_") && Array(entry["subcategories"]).any? }
failures << "US-government-oriented starter must remain reference-only until exact mapping evidence exists" unless government_reference["profile_purpose"] == "starter_reference"
failures << "US-government starter profile must declare limitations and reference provenance" if Array(government_reference.dig("scope", "limitations")).empty? || Array(government_reference["authoritative_sources"]).empty?

deployment_schema = documents["policies/deployment-domains/domain-profile-v0.1.schema.json"] || {}
failures << "Deployment-domain v0.1 must reject every non-empty bridge set" unless deployment_schema.dig("properties", "approved_profile_bridges", "maxItems") == 0
failures << "Deployment-domain v0.1 bridge item schema must accept no latent bridge shape" unless deployment_schema.dig("properties", "approved_profile_bridges", "items") == false
expected_disclosure_modes = %w[request_boundary commit_boundary]
failures << "Deployment-domain v0.1 must require disclosure_revocation_mode" unless Array(deployment_schema["required"]).include?("disclosure_revocation_mode")
unless deployment_schema.dig("properties", "disclosure_revocation_mode", "enum") == expected_disclosure_modes
  failures << "Deployment-domain v0.1 disclosure_revocation_mode must be the exact closed request_boundary/commit_boundary enum"
end
DEPLOYMENT_DOMAIN_DOCUMENTS.each do |path|
  name = File.basename(path, ".yaml")
  domain = documents[path] || {}
  missing = Array(deployment_schema["required"]) - domain.keys
  failures << "#{name} deployment-domain profile omits: #{missing.join(', ')}" unless missing.empty?
  validate_instance(domain, deployment_schema, "#{name} deployment-domain profile", failures)
  bindings = domain["label_profile_ceilings"] || {}
  failures << "#{name} deployment domain ceilings must be a profile-ID-keyed map" unless bindings.is_a?(Hash) && !bindings.empty?
  bindings.each do |profile_id, binding|
    profile = profiles_by_id[profile_id]
    unless profile
      failures << "#{name} deployment domain references unknown profile #{profile_id}"
      next
    end
    failures << "#{name} deployment domain profile version mismatch for #{profile_id}" unless binding["profile_version"] == profile["version"]
    failures << "#{name} deployment domain ceiling #{binding['classification_ceiling']} is foreign or unknown for #{profile_id}" unless Array(profile["sensitivity_order"]).include?(binding["classification_ceiling"])
  end
  failures << "#{name} deployment domain must not activate a v0.1 profile bridge" unless Array(domain["approved_profile_bridges"]).empty?
end

starter_domains = DEPLOYMENT_DOMAIN_DOCUMENTS.to_h { |path| [File.basename(path, ".yaml"), documents[path] || {}] }
%w[commercial us-government].each do |name|
  failures << "#{name} starter domain must select request_boundary explicitly" unless starter_domains.dig(name, "disclosure_revocation_mode") == "request_boundary"
end
synthetic_high_assurance_domain = documents[HIGH_ASSURANCE_DOMAIN_FIXTURE] || {}
validate_instance(synthetic_high_assurance_domain, deployment_schema, "synthetic high-assurance deployment-domain fixture", failures)
unless synthetic_high_assurance_domain["disclosure_revocation_mode"] == "commit_boundary" &&
       synthetic_high_assurance_domain.fetch("label_profile_ceilings", {}).key?("commercial") &&
       !synthetic_high_assurance_domain.fetch("label_profile_ceilings", {}).key?("us_government")
  failures << "Synthetic non-government high-assurance domain must select commit_boundary for a profile also used under request_boundary, without a privileged profile ID"
end

missing_mode_domain = starter_domains.fetch("commercial", {}).dup
missing_mode_domain.delete("disclosure_revocation_mode")
missing_mode_failures = []
validate_instance(missing_mode_domain, deployment_schema, "missing-mode deployment domain", missing_mode_failures)
failures << "Deployment-domain schema must reject a missing disclosure_revocation_mode" unless missing_mode_failures.any? { |failure| failure.end_with?("missing disclosure_revocation_mode") }

unknown_mode_domain = starter_domains.fetch("commercial", {}).merge("disclosure_revocation_mode" => "profile_selected")
unknown_mode_failures = []
validate_instance(unknown_mode_domain, deployment_schema, "unknown-mode deployment domain", unknown_mode_failures)
failures << "Deployment-domain schema must reject an unknown disclosure_revocation_mode" unless unknown_mode_failures.any? { |failure| failure.include?("disclosure_revocation_mode: value is outside enum") }

policy_input = documents["policies/policy-decision/input-v0.1.schema.json"] || {}
failures << "policy-decision input must use structured authorization" unless Array(policy_input["required"]).include?("authorization") && !policy_input.key?("relationship_authorized")
agent_terms = policy_input.dig("properties", "authorization", "properties", "agent_intersection", "required") || []
expected_agent_terms = %w[delegator_authority agent_authority task_scope runtime_domain session_environment resource_handling revocation_current]
failures << "policy-decision input omits agent authorization intersection terms" unless agent_terms == expected_agent_terms
%w[data_flow_context ci_context infrastructure_context].each do |context|
  failures << "policy-decision input omits #{context}" unless policy_input.dig("properties", context).is_a?(Hash)
end
required_policy_context = policy_input.dig("properties", "policy_context", "required") || []
failures << "policy-decision input must declare required policy contexts" unless required_policy_context.include?("required_contexts")
profile_ceiling_ref = "../deployment-domains/domain-profile-v0.1.schema.json#/$defs/ProfileCeilingMap"
profile_ceiling_locations = [
  policy_input.dig("properties", "agent_context", "properties", "classification_ceilings", "$ref"),
  policy_input.dig("properties", "session", "properties", "classification_ceilings", "$ref"),
  policy_input.dig("properties", "data_flow_context", "properties", "destination", "properties", "label_profile_ceilings", "$ref"),
  policy_input.dig("properties", "infrastructure_context", "properties", "label_profile_ceilings", "$ref")
]
failures << "Every policy-decision ceiling context must use the shared profile-qualified ceiling contract" unless profile_ceiling_locations.all? { |reference| reference == profile_ceiling_ref }
policy_output = documents["policies/policy-decision/output-v0.1.schema.json"] || {}
output_obligations = Array(policy_output.dig("properties", "obligations", "items", "enum"))
failures << "Policy output must use a parameterized approval-threshold obligation" unless output_obligations.include?("require_approval_threshold") && !output_obligations.include?("require_two_person_approval")
approval_fields = Array(policy_output.dig("properties", "approval_requirement", "required"))
failures << "Policy output approval requirement must carry threshold, separation, human-principal, and policy-basis data" unless %w[minimum_approvers distinct_approvers human_approvers_required policy_basis].all? { |field| approval_fields.include?(field) }
policy_cases = Array(documents.dig("policies/policy-decision/decision-table.yaml", "cases"))
policy_ids = policy_cases.filter_map { |entry| entry["id"] }
failures << "policy decision case IDs must use the implementation-neutral POLICY prefix" unless policy_ids.all? { |id| id.start_with?("POLICY-") }
failures << "policy decision case IDs must be unique" unless policy_ids.uniq.length == policy_ids.length
policy_table = documents["policies/policy-decision/decision-table.yaml"] || {}
expected_combining_rule = "allow = authorization.relationship.allowed AND policy decision allow AND authorization.provider_path.allowed AND no explicit deny; agents additionally require every authorization.agent_intersection term"
failures << "policy decision table must preserve the central combining rule" unless policy_table["combining_rule"] == expected_combining_rule
failures << "policy decision table must default to deny" unless policy_table["default"] == "deny"
%w[POLICY-001B POLICY-007 POLICY-008 POLICY-009 POLICY-010 POLICY-011 POLICY-011A POLICY-012 POLICY-012A POLICY-012B POLICY-013 POLICY-013A POLICY-014 POLICY-014A POLICY-AGENT-008 POLICY-HIERARCHY-001 POLICY-LEAK-001].each do |id|
  failures << "policy decision table omits #{id}" unless policy_ids.include?(id)
end
policy_coverage = documents.dig("policies/policy-decision/decision-table.yaml", "coverage_rules") || {}
expected_policy_coverage = {
  "decision_rows" => "100_percent",
  "critical_policy_mutation_score" => "at_least_90_percent",
  "deterministic_replay" => "identical_input_and_policy_bundle_revision_produces_semantically_identical_output_excluding_decision_id",
  "differential_conformance" => "required_when_multiple_evaluators_are_supported",
  "missing_input" => "deny",
  "unknown_profile_or_bundle" => "deny",
  "stale_consistency_fence" => "deny",
  "evaluator_timeout_or_unavailable" => "deny",
  "malformed_result_or_unsupported_obligation" => "deny",
  "approval_thresholds" => "effective_profile_and_deployment_policy_supports_1_2_3_or_higher"
}
expected_policy_coverage.each do |rule, expected|
  failures << "policy decision coverage rule #{rule} must be #{expected}" unless policy_coverage[rule] == expected
end

mcp_authorization = documents.dig("specs/mcp/compatibility-v0.1.yaml", "authorization")
failures << "MCP must reuse the central implementation-neutral authorization decision" unless mcp_authorization == "same_central_authorization_decision_as_platform_api"

fga_tests = documents["policies/openfga/model-tests.yaml"] || {}
test_suites = Array(fga_tests["tests"])
check_assertions = test_suites.sum do |suite|
  Array(suite["check"]).sum { |check| check["assertions"].is_a?(Hash) ? check["assertions"].length : 0 }
end
failures << "OpenFGA test matrix must contain at least 16 suites" if test_suites.length < 16
failures << "OpenFGA test matrix must contain at least 80 assertions" if check_assertions < 80

security_label_value = definitions["SecurityLabelValue"] || {}
failures << "OWGP SecurityLabelValue must reject undeclared fields" unless security_label_value["unevaluatedProperties"] == false
{
  "Commit.authored_by" => definitions.dig("Commit", "allOf", 1, "properties", "authored_by", "$ref"),
  "PullRequest.author" => definitions.dig("PullRequest", "allOf", 1, "properties", "author", "$ref"),
  "Release.approved_by" => definitions.dig("Release", "allOf", 1, "properties", "approved_by", "items", "$ref")
}.each do |field, reference|
  failures << "OWGP #{field} must use ActingPrincipalRef" unless reference == "#/$defs/ActingPrincipalRef"
end

migration_schema = documents["specs/migration/migration-job-v0.1.schema.json"] || {}
migration_validation = migration_schema.dig("properties", "validation", "required") || []
%w[provenance_complete authorization_non_regression].each do |field|
  failures << "Migration validation omits #{field}" unless migration_validation.include?(field)
end
checkpoint_stages = migration_schema.dig("properties", "checkpoint", "properties", "stage", "enum") || []
job_stages = migration_schema.dig("properties", "stage", "enum") || []
failures << "Migration checkpoint stage must use the job stage enum" unless checkpoint_stages == job_stages

audit_required = definitions.dig("AuditRecord", "allOf", 1, "required") || []
expected_audit_context = %w[authentication_context authorization_model_id policy_bundle_id change_context]
missing_audit_context = expected_audit_context - audit_required
failures << "OWGP AuditRecord omits mandatory audit context: #{missing_audit_context.join(', ')}" unless missing_audit_context.empty?
failures << "OWGP AuthenticationContext must be closed" unless definitions.dig("AuthenticationContext", "additionalProperties") == false
failures << "OWGP AuditChangeContext must define hashes, controlled delta, and not-applicable modes" unless Array(definitions.dig("AuditChangeContext", "oneOf")).length == 3

production_code_paths = Dir.glob(ROOT.join("{apps,internal,modules,providers}/**/*.{go,js,jsx,mjs,ts,tsx}"), File::FNM_EXTGLOB).select { |path| File.file?(path) }
production_code_paths.each do |path|
  source = File.read(path, encoding: "UTF-8")
  next unless source.match?(/\b(?:commercial|us_government|us-government)\b/)

  failures << "#{Pathname.new(path).relative_path_from(ROOT)}: production code must not branch on starter/reference profile IDs"
end

if failures.empty?
  puts "Contract validation passed: documents=#{documents.length} refs=resolved openfga_suites=#{test_suites.length} openfga_assertions=#{check_assertions}"
  exit 0
end

warn "Contract validation failed (#{failures.length}):"
failures.each { |failure| warn "- #{failure}" }
exit 1
