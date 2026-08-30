#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"

SEED = 2_026_083_001
CARDINALITIES = {
  "organizations" => 10,
  "teams" => 80,
  "team_edges" => 70,
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

def deterministic_digest(kind, index)
  Digest::SHA256.hexdigest("stead-standard-v1\0#{SEED}\0#{kind}\0#{index}")
end

records = CARDINALITIES.flat_map do |kind, count|
  (0...count).map do |index|
    {
      "kind" => kind,
      "ordinal" => index,
      "stable_digest" => deterministic_digest(kind, index)
    }
  end
end

document = {
  "dataset_id" => "stead-standard-request-boundary-v1",
  "generator_seed" => SEED,
  "cardinalities" => CARDINALITIES,
  "records" => records
}

STDOUT.write(JSON.generate(document))
STDOUT.write("\n")
