#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"

SEED = 2_026_083_001
CARDINALITIES = {
  "organizations" => 10,
  "teams" => 80,
  "team_edges" => 70,
  "people" => 1_000,
  "agents" => 100,
  "projects" => 200,
  "work_items" => 10_000,
  "documents" => 5_000,
  "document_versions" => 20_000,
  "relationships" => 30_000,
  "activity_events" => 100_000,
  "inbox_entries" => 25_000,
  "audit_events" => 100_000,
  "repositories" => 50,
  "pull_requests" => 2_000,
  "builds" => 5_000,
  "packages" => 1_000,
  "releases" => 500
}.freeze

CLASSIFICATIONS = %w[baseline:internal baseline:confidential baseline:restricted].freeze
DEPARTMENTS = %w[operations finance people legal research product support security].freeze
WORK_STATUSES = %w[backlog ready in_progress blocked review done].freeze
DOC_STATUSES = %w[draft review published archived].freeze
PR_STATUSES = %w[open merged closed].freeze
BUILD_STATUSES = %w[queued running succeeded failed cancelled].freeze
PRIORITIES = %w[low normal high urgent].freeze
RELATIONSHIP_TYPES = %w[references implements informs blocks].freeze
TITLE_NOUNS = %w[access budget charter handbook onboarding policy process roadmap service training].freeze
TITLE_VERBS = %w[align approve document improve investigate migrate prepare reconcile review validate].freeze
SEARCH_TOPICS = [
  "benefits enrollment", "customer escalation", "data retention", "incident response",
  "new hire onboarding", "quarterly planning", "research approval", "security access review",
  "supplier risk", "team operating model", "travel reimbursement", "workplace safety"
].freeze

def stable_id(kind, index)
  digest = Digest::SHA256.hexdigest("stead-standard-v1\0#{SEED}\0#{kind}\0#{index}")
  "#{kind.delete_suffix("s")}_#{digest[0, 24]}"
end

def title_for(kind, index)
  verb = TITLE_VERBS[index % TITLE_VERBS.length]
  noun = TITLE_NOUNS[(index / TITLE_VERBS.length) % TITLE_NOUNS.length]
  "#{verb.capitalize} #{noun} #{kind.delete_suffix("s")} #{index + 1}"
end

organizations = CARDINALITIES["organizations"].times.map do |index|
  {
    "id" => stable_id("organizations", index),
    "slug" => format("organization-%02d", index + 1),
    "name" => "Stead Reference Organization #{index + 1}",
    "classification" => CLASSIFICATIONS[index % CLASSIFICATIONS.length],
    "status" => "active"
  }
end

teams = []
team_edges = []
organizations.each_with_index do |organization, organization_index|
  8.times do |local_index|
    index = (organization_index * 8) + local_index
    parent_index = if local_index.zero?
                     nil
                   elsif local_index <= 3
                     organization_index * 8
                   else
                     (organization_index * 8) + (((local_index - 1) % 3) + 1)
                   end
    team = {
      "id" => stable_id("teams", index),
      "organization_id" => organization["id"],
      "parent_team_id" => parent_index ? stable_id("teams", parent_index) : nil,
      "slug" => format("org-%02d-team-%02d", organization_index + 1, local_index + 1),
      "name" => "#{DEPARTMENTS[local_index]} team #{organization_index + 1}",
      "classification" => CLASSIFICATIONS[(organization_index + local_index) % CLASSIFICATIONS.length],
      "status" => "active"
    }
    teams << team
    if parent_index
      team_edges << {
        "parent_team_id" => stable_id("teams", parent_index),
        "child_team_id" => team["id"],
        "depth" => local_index <= 3 ? 1 : 2
      }
    end
  end
end

people = CARDINALITIES["people"].times.map do |index|
  organization_index = index / 100
  {
    "id" => stable_id("people", index),
    "organization_id" => organizations[organization_index]["id"],
    "home_team_id" => teams[(organization_index * 8) + (index % 8)]["id"],
    "display_name" => "Reference Person #{index + 1}",
    "department" => DEPARTMENTS[index % DEPARTMENTS.length],
    "status" => index % 40 == 0 ? "inactive" : "active"
  }
end

agents = CARDINALITIES["agents"].times.map do |index|
  organization_index = index / 10
  {
    "id" => stable_id("agents", index),
    "organization_id" => organizations[organization_index]["id"],
    "name" => "Reference Agent #{index + 1}",
    "runtime_kind" => %w[external_a2a external_mcp external_api][index % 3],
    "status" => index % 20 == 0 ? "disabled" : "active",
    "delegated_by_person_id" => people[(organization_index * 100) + (index % 100)]["id"]
  }
end

projects = CARDINALITIES["projects"].times.map do |index|
  organization_index = index / 20
  software = (index % 4).zero?
  {
    "id" => stable_id("projects", index),
    "organization_id" => organizations[organization_index]["id"],
    "team_id" => teams[(organization_index * 8) + (index % 8)]["id"],
    "slug" => format("org-%02d-project-%03d", organization_index + 1, (index % 20) + 1),
    "name" => title_for("projects", index),
    "status" => %w[planned active paused completed][index % 4],
    "classification" => CLASSIFICATIONS[index % CLASSIFICATIONS.length],
    "capabilities" => software ? %w[work docs code delivery] : %w[work docs]
  }
end

work_items = CARDINALITIES["work_items"].times.map do |index|
  project_index = index % projects.length
  organization_index = project_index / 20
  agent_assigned = (index % 10).zero?
  {
    "id" => stable_id("work_items", index),
    "project_id" => projects[project_index]["id"],
    "organization_id" => organizations[organization_index]["id"],
    "title" => title_for("work_items", index),
    "search_text" => "#{SEARCH_TOPICS[index % SEARCH_TOPICS.length]} work with an accountable owner, acceptance criteria, due-date context, and cross-team handoff.",
    "status" => WORK_STATUSES[index % WORK_STATUSES.length],
    "priority" => PRIORITIES[(index / 3) % PRIORITIES.length],
    "classification" => CLASSIFICATIONS[(project_index + index) % CLASSIFICATIONS.length],
    "creator_person_id" => people[(organization_index * 100) + (index % 100)]["id"],
    "assignee_type" => agent_assigned ? "agent" : "person",
    "assignee_id" => if agent_assigned
                       agents[(organization_index * 10) + (index % 10)]["id"]
                     else
                       people[(organization_index * 100) + ((index * 7) % 100)]["id"]
                     end,
    "estimate_points" => [1, 2, 3, 5, 8, 13][index % 6]
  }
end

documents = CARDINALITIES["documents"].times.map do |index|
  organization_index = index / 500
  project_index = (organization_index * 20) + (index % 20)
  scope_type = %w[organization team project][index % 3]
  scope_id = case scope_type
             when "organization" then organizations[organization_index]["id"]
             when "team" then teams[(organization_index * 8) + (index % 8)]["id"]
             else projects[project_index]["id"]
             end
  {
    "id" => stable_id("documents", index),
    "organization_id" => organizations[organization_index]["id"],
    "scope_type" => scope_type,
    "scope_id" => scope_id,
    "project_id" => scope_type == "project" ? projects[project_index]["id"] : nil,
    "slug" => format("knowledge-%05d", index + 1),
    "title" => title_for("documents", index),
    "search_text" => "Knowledge for #{SEARCH_TOPICS[(index * 5) % SEARCH_TOPICS.length]} including purpose, decision context, responsible team, review cadence, and related work.",
    "status" => DOC_STATUSES[index % DOC_STATUSES.length],
    "classification" => CLASSIFICATIONS[(organization_index + index) % CLASSIFICATIONS.length],
    "author_person_id" => people[(organization_index * 100) + (index % 100)]["id"],
    "word_count" => 250 + ((index * 137) % 4_751)
  }
end

document_versions = CARDINALITIES["document_versions"].times.map do |index|
  document_index = index / 4
  ordinal = (index % 4) + 1
  {
    "id" => stable_id("document_versions", index),
    "document_id" => documents[document_index]["id"],
    "ordinal" => ordinal,
    "git_blob_sha256" => Digest::SHA256.hexdigest("document-version\0#{SEED}\0#{document_index}\0#{ordinal}"),
    "author_person_id" => documents[document_index]["author_person_id"],
    "state" => ordinal == 4 ? "current" : "historical"
  }
end

relationships = CARDINALITIES["relationships"].times.map do |index|
  source = work_items[index % work_items.length]
  organization_index = organizations.index { |organization| organization["id"] == source["organization_id"] }
  target = documents[(organization_index * 500) + (((index * 17) + (index / work_items.length)) % 500)]
  {
    "id" => stable_id("relationships", index),
    "source_type" => "work_item",
    "source_id" => source["id"],
    "target_type" => "document",
    "target_id" => target["id"],
    "relationship_type" => RELATIONSHIP_TYPES[index % RELATIONSHIP_TYPES.length],
    "organization_id" => source["organization_id"]
  }
end

activity_events = CARDINALITIES["activity_events"].times.map do |index|
  work = work_items[index % work_items.length]
  agent_actor = (index % 25).zero?
  organization_index = projects.index { |project| project["id"] == work["project_id"] } / 20
  {
    "id" => stable_id("activity_events", index),
    "organization_id" => work["organization_id"],
    "actor_type" => agent_actor ? "agent" : "person",
    "actor_id" => agent_actor ? agents[(organization_index * 10) + (index % 10)]["id"] : people[(organization_index * 100) + (index % 100)]["id"],
    "verb" => %w[created updated assigned commented completed][index % 5],
    "object_type" => "work_item",
    "object_id" => work["id"],
    "sequence" => index + 1
  }
end

inbox_entries = CARDINALITIES["inbox_entries"].times.map do |index|
  event = activity_events[(index * 3) % activity_events.length]
  organization_index = organizations.index { |organization| organization["id"] == event["organization_id"] }
  {
    "id" => stable_id("inbox_entries", index),
    "organization_id" => organizations[organization_index]["id"],
    "recipient_person_id" => people[(organization_index * 100) + (index % 100)]["id"],
    "activity_event_id" => event["id"],
    "state" => %w[unread read archived][index % 3],
    "reason" => %w[assignment mention subscription review][index % 4]
  }
end

audit_events = CARDINALITIES["audit_events"].times.map do |index|
  work = work_items[index % work_items.length]
  organization_index = (index % projects.length) / 20
  {
    "id" => stable_id("audit_events", index),
    "organization_id" => work["organization_id"],
    "principal_type" => (index % 50).zero? ? "agent" : "person",
    "principal_id" => if (index % 50).zero?
                        agents[(organization_index * 10) + (index % 10)]["id"]
                      else
                        people[(organization_index * 100) + (index % 100)]["id"]
                      end,
    "operation" => %w[work.read work.update document.read search.query project.read][index % 5],
    "resource_type" => "work_item",
    "resource_id" => work["id"],
    "decision" => index % 20 == 0 ? "deny" : "allow",
    "sequence" => index + 1
  }
end

software_projects = projects.select { |project| project["capabilities"].include?("code") }
repositories = CARDINALITIES["repositories"].times.map do |index|
  project = software_projects[index]
  {
    "id" => stable_id("repositories", index),
    "project_id" => project["id"],
    "name" => "repository-#{index + 1}",
    "default_branch" => "main",
    "visibility" => "project",
    "provider_projection_state" => %w[current current current reconciling][index % 4]
  }
end

pull_requests = CARDINALITIES["pull_requests"].times.map do |index|
  repository = repositories[index % repositories.length]
  project = projects.find { |candidate| candidate["id"] == repository["project_id"] }
  organization_index = organizations.index { |organization| organization["id"] == project["organization_id"] }
  {
    "id" => stable_id("pull_requests", index),
    "repository_id" => repository["id"],
    "number" => (index / repositories.length) + 1,
    "title" => title_for("pull_requests", index),
    "status" => PR_STATUSES[index % PR_STATUSES.length],
    "author_person_id" => people[(organization_index * 100) + (index % 100)]["id"]
  }
end

builds = CARDINALITIES["builds"].times.map do |index|
  {
    "id" => stable_id("builds", index),
    "repository_id" => repositories[index % repositories.length]["id"],
    "pull_request_id" => pull_requests[index % pull_requests.length]["id"],
    "status" => BUILD_STATUSES[index % BUILD_STATUSES.length],
    "duration_ms" => 5_000 + ((index * 7919) % 895_001),
    "has_sbom" => (index % 10) != 0
  }
end

packages = CARDINALITIES["packages"].times.map do |index|
  {
    "id" => stable_id("packages", index),
    "repository_id" => repositories[index % repositories.length]["id"],
    "name" => "stead-reference-package-#{index + 1}",
    "version" => format("1.%d.%d", (index / 100) % 10, index % 100),
    "format" => %w[oci npm generic][index % 3],
    "size_bytes" => 1_024 + ((index * 65_537) % 52_427_776)
  }
end

releases = CARDINALITIES["releases"].times.map do |index|
  repository = repositories[index % repositories.length]
  project = projects.find { |candidate| candidate["id"] == repository["project_id"] }
  organization_index = organizations.index { |organization| organization["id"] == project["organization_id"] }
  package = packages[index % packages.length]
  {
    "id" => stable_id("releases", index),
    "repository_id" => repository["id"],
    "package_id" => package["id"],
    "name" => "Release #{index + 1}",
    "state" => %w[draft published withdrawn][index % 3],
    "approver_person_id" => people[(organization_index * 100) + ((index * 11) % 100)]["id"]
  }
end

document = {
  "artifact_type" => "performance_corpus",
  "schema_version" => "1.0",
  "dataset_id" => "stead-standard-request-boundary-v1",
  "generator_seed" => SEED,
  "cardinalities" => CARDINALITIES,
  "organizations" => organizations,
  "teams" => teams,
  "team_edges" => team_edges,
  "people" => people,
  "agents" => agents,
  "projects" => projects,
  "work_items" => work_items,
  "documents" => documents,
  "document_versions" => document_versions,
  "relationships" => relationships,
  "activity_events" => activity_events,
  "inbox_entries" => inbox_entries,
  "audit_events" => audit_events,
  "repositories" => repositories,
  "pull_requests" => pull_requests,
  "builds" => builds,
  "packages" => packages,
  "releases" => releases
}

STDOUT.write(JSON.generate(document))
STDOUT.write("\n")
