#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require_relative "evidence_contract"

if ARGV.empty?
  warn "usage: ruby tests/performance/harness/verify_evidence.rb EVIDENCE.json [...]"
  exit 2
end

results = ARGV.map do |path|
  evidence = Stead::PerformanceEvidence.load(path)
  errors = evidence.validate
  {
    path: path,
    evidence_id: evidence.document.is_a?(Hash) ? evidence.document["evidence_id"] : nil,
    status: errors.empty? ? "PASS" : "FAIL",
    errors: errors
  }
rescue JSON::ParserError => error
  { path: path, status: "FAIL", errors: ["invalid JSON: #{error.message}"] }
rescue SystemCallError => error
  { path: path, status: "FAIL", errors: [error.message] }
end

puts JSON.pretty_generate(
  contract: "PERF-001..PERF-006",
  schema_version: Stead::PerformanceEvidence::SCHEMA_VERSION,
  results: results
)

exit(results.all? { |result| result[:status] == "PASS" } ? 0 : 1)
