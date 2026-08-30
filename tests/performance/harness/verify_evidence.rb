#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "pathname"
require_relative "evidence_contract"

ROOT = Pathname.new(__dir__).join("../../..").expand_path

mode = :evidence
if ARGV.first == "--suite"
  mode = :suite
  ARGV.shift
end

if ARGV.empty?
  warn "usage: ruby tests/performance/harness/verify_evidence.rb [--suite] ARTIFACT.json [...]"
  exit 2
end

verifier = Stead::PerformanceVerifier.new(root: ROOT)
results = ARGV.map do |path|
  mode == :suite ? verifier.verify_suite(path) : verifier.verify_evidence(path)
end

puts JSON.pretty_generate(
  contract: "PERF-001..PERF-006",
  schema_version: Stead::PerformanceEvidence::SCHEMA_VERSION,
  verification_mode: mode,
  results: results.map do |result|
    result.merge("status" => result["errors"].empty? ? "PASS" : "FAIL")
  end
)

exit(results.all? { |result| result["errors"].empty? } ? 0 : 1)
