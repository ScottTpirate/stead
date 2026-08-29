#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "pathname"
require "set"
require "yaml"

ROOT = Pathname.new(__dir__).parent.expand_path

DOCUMENTS = %w[
  specs/work-graph-profile/owgp-v0.1.schema.json
  specs/openapi/platform-v1.yaml
  specs/asyncapi/platform.yaml
  specs/provider-interfaces.yaml
  specs/migration/migration-job.schema.json
  specs/migration/canonical-model-v0.1.yaml
  packages/event-schemas/common/actor-context/actor-context.schema.json
  packages/event-schemas/platform/platform-event.schema.json
  policies/opa/input.schema.json
  policies/opa/output.schema.json
  policies/opa/decision-table.yaml
  policies/security-label-profiles/profile.schema.json
  policies/security-label-profiles/commercial.yaml
  policies/security-label-profiles/us-government.yaml
  policies/deployment-domains/domain-profile.schema.json
  policies/deployment-domains/commercial.yaml
  policies/deployment-domains/us-government.yaml
  policies/openfga/model-tests.yaml
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
  "organizationEvents" => %w[platform.organization.created.v1 platform.organization.updated.v1 platform.team.created.v1 platform.team.updated.v1 platform.team.reparented.v1 platform.team.membership_changed.v1],
  "identityEvents" => %w[platform.identity.provisioned.v1 platform.identity.updated.v1 platform.identity.suspended.v1 platform.agent.registered.v1 platform.agent.revoked.v1],
  "authorizationEvents" => %w[platform.authorization.model_activated.v1 platform.authorization.tuple_changed.v1 platform.authorization.delegation_revoked.v1 platform.authorization.policy_activated.v1],
  "classificationEvents" => %w[platform.classification.label_raised.v1 platform.classification.label_lowered.v1 platform.classification.profile_activated.v1 platform.classification.ceiling_changed.v1 platform.classification.attribute_changed.v1],
  "projectEvents" => %w[platform.project.created.v1 platform.project.updated.v1 platform.project.capability_changed.v1 platform.initiative.changed.v1 platform.cycle.changed.v1],
  "workEvents" => %w[platform.workitem.created.v1 platform.workitem.updated.v1 platform.workitem.assigned.v1 platform.workitem.related.v1],
  "commentEvents" => %w[platform.comment.created.v1 platform.comment.updated.v1 platform.comment.deleted.v1],
  "knowledgeEvents" => %w[platform.document.created.v1 platform.document.updated.v1 platform.document.review_requested.v1 platform.document.approved.v1 platform.document.superseded.v1],
  "scmEvents" => %w[platform.scm.repository_changed.v1 platform.scm.branch_changed.v1 platform.scm.commit_recorded.v1 platform.scm.pull_request_changed.v1 platform.scm.reconciled.v1],
  "ciEvents" => %w[platform.ci.build_changed.v1 platform.ci.deployment_changed.v1 platform.ci.runner_changed.v1 platform.ci.action_changed.v1],
  "artifactEvents" => %w[platform.artifact.artifact_changed.v1 platform.artifact.package_changed.v1 platform.artifact.release_changed.v1],
  "attachmentEvents" => %w[platform.attachment.created.v1 platform.attachment.scanned.v1 platform.attachment.deleted.v1],
  "storageEvents" => %w[platform.storage.scan_changed.v1 platform.storage.retention_changed.v1 platform.storage.provider_operation_changed.v1],
  "searchGraphEvents" => %w[platform.search_graph.rebuild_started.v1 platform.search_graph.rebuild_completed.v1 platform.search_graph.rebuild_failed.v1],
  "notificationEvents" => %w[platform.notification.created.v1 platform.notification.read.v1 platform.notification.delivery_changed.v1 platform.notification.suppressed.v1],
  "auditEvents" => %w[platform.audit.checkpoint_created.v1 platform.audit.export_changed.v1],
  "migrationEvents" => %w[platform.migration.stage_changed.v1 platform.migration.reconciled.v1 platform.migration.cutover_changed.v1],
  "operationsEvents" => %w[platform.operations.install_changed.v1 platform.operations.upgrade_changed.v1 platform.operations.backup_changed.v1 platform.operations.restore_changed.v1 platform.operations.doctor_changed.v1],
  "deadLetterEvents" => %w[platform.dead_letter.recorded.v1 platform.dead_letter.replayed.v1]
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

documents.each do |relative, document|
  each_node(document) do |node|
    next unless node.is_a?(Hash) && node["$ref"].is_a?(String)

    reference = node["$ref"]
    next if reference.match?(%r{\Ahttps?://})

    file_part, fragment = reference.split("#", 2)
    target_relative = if file_part.nil? || file_part.empty?
                        relative
                      else
                        ROOT.join(relative).dirname.join(file_part).cleanpath.relative_path_from(ROOT).to_s
                      end
    begin
      target_document = documents[target_relative] ||= parse(ROOT.join(target_relative))
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

asyncapi = documents["specs/asyncapi/platform.yaml"] || {}
failures << "AsyncAPI version must be 3.1.x" unless asyncapi["asyncapi"].to_s.start_with?("3.1.")
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

event_data = documents["packages/event-schemas/platform/platform-event.schema.json"] || {}
event_required = event_data["required"] || []
failures << "Event data must require idempotency_key" unless event_required.include?("idempotency_key")
failures << "Event data must not require capability context" if event_required.include?("capability_context") || event_required.include?("capabilities")
actor_required = documents.dig("packages/event-schemas/common/actor-context/actor-context.schema.json", "required") || []
failures << "Actor context must require correlation and causation IDs" unless %w[correlation_id causation_id].all? { |field| actor_required.include?(field) }

providers = documents["specs/provider-interfaces.yaml"] || {}
Array(providers["interfaces"]).each do |interface|
  failures << "Provider #{interface['id']} has no operation contract" unless interface["operations"].is_a?(Array) && !interface["operations"].empty?
end
failures << "Provider common contract omits operation semantics" unless providers.dig("common_contract", "operation_semantics").is_a?(Hash)

label_schema = documents["policies/security-label-profiles/profile.schema.json"] || {}
required_label_fields = %w[allowed_categories allowed_compartments dissemination_controls releasability_groups export_controls join lowering two_person_lowering]
missing_label_fields = required_label_fields - Array(label_schema["required"])
failures << "Security-label profile schema omits: #{missing_label_fields.join(', ')}" unless missing_label_fields.empty?
%w[commercial us-government].each do |name|
  profile = documents["policies/security-label-profiles/#{name}.yaml"] || {}
  missing = Array(label_schema["required"]) - profile.keys
  failures << "#{name} label profile omits: #{missing.join(', ')}" unless missing.empty?
  validate_instance(profile, label_schema, "#{name} label profile", failures)
end
government_categories = Array(documents.dig("policies/security-label-profiles/us-government.yaml", "allowed_categories"))
failures << "US-government profile must enumerate CUI categories/subcategories" unless government_categories.any? { |entry| entry["id"].to_s.start_with?("CUI_") && Array(entry["subcategories"]).any? }

deployment_schema = documents["policies/deployment-domains/domain-profile.schema.json"] || {}
%w[commercial us-government].each do |name|
  profile = documents["policies/deployment-domains/#{name}.yaml"] || {}
  missing = Array(deployment_schema["required"]) - profile.keys
  failures << "#{name} deployment-domain profile omits: #{missing.join(', ')}" unless missing.empty?
  validate_instance(profile, deployment_schema, "#{name} deployment-domain profile", failures)
end

opa_input = documents["policies/opa/input.schema.json"] || {}
failures << "OPA input must use structured authorization" unless Array(opa_input["required"]).include?("authorization") && !opa_input.key?("relationship_authorized")
agent_terms = opa_input.dig("properties", "authorization", "properties", "agent_intersection", "required") || []
expected_agent_terms = %w[delegator_authority agent_authority task_scope runtime_domain session_environment resource_handling revocation_current]
failures << "OPA input omits agent authorization intersection terms" unless agent_terms == expected_agent_terms
%w[data_flow_context ci_context infrastructure_context].each do |context|
  failures << "OPA input omits #{context}" unless opa_input.dig("properties", context).is_a?(Hash)
end
required_policy_context = opa_input.dig("properties", "policy_context", "required") || []
failures << "OPA input must declare required policy contexts" unless required_policy_context.include?("required_contexts")
opa_cases = Array(documents.dig("policies/opa/decision-table.yaml", "cases"))
opa_ids = opa_cases.filter_map { |entry| entry["id"] }
%w[OPA-001B OPA-007 OPA-008 OPA-009 OPA-010 OPA-011 OPA-011A OPA-012 OPA-013 OPA-013A OPA-014 OPA-014A OPA-AGENT-008 OPA-HIERARCHY-001 OPA-LEAK-001].each do |id|
  failures << "OPA decision table omits #{id}" unless opa_ids.include?(id)
end

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

migration_schema = documents["specs/migration/migration-job.schema.json"] || {}
migration_validation = migration_schema.dig("properties", "validation", "required") || []
%w[provenance_complete authorization_non_regression].each do |field|
  failures << "Migration validation omits #{field}" unless migration_validation.include?(field)
end
checkpoint_stages = migration_schema.dig("properties", "checkpoint", "properties", "stage", "enum") || []
job_stages = migration_schema.dig("properties", "stage", "enum") || []
failures << "Migration checkpoint stage must use the job stage enum" unless checkpoint_stages == job_stages

if failures.empty?
  puts "Contract validation passed: documents=#{documents.length} refs=resolved openfga_suites=#{test_suites.length} openfga_assertions=#{check_assertions}"
  exit 0
end

warn "Contract validation failed (#{failures.length}):"
failures.each { |failure| warn "- #{failure}" }
exit 1
