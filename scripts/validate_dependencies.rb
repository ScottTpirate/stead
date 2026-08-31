#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "find"
require "fileutils"
require "json"
require "set"
require "time"
require "tmpdir"
require "uri"
require "yaml"

ROOT = File.expand_path("..", __dir__)
REGISTRY_PATH = File.join(ROOT, "docs/governance/dependency-approvals.yaml")
SCHEMA_PATH = File.join(ROOT, "docs/governance/dependency-approvals.schema.json")
PROVENANCE_PATH = File.join(ROOT, "docs/governance/devlane-provenance.yaml")
POSTGRESQL_EVIDENCE_PATH = File.join(ROOT, "docs/governance/dependency-evidence/stead-p1-015-postgresql.yaml")
NOTICES_PATH = File.join(ROOT, "THIRD_PARTY_NOTICES.md")
LOCK_PATH = File.join(ROOT, "package-lock.json")
GO_MOD_PATH = File.join(ROOT, "go.mod")
GO_SUM_PATH = File.join(ROOT, "go.sum")

REQUIRED_PINS = {
  "devlane-source" => ["7719dcadf91f881b5aefe8b74012ffcfbba0bc17", "7719dcadf91f881b5aefe8b74012ffcfbba0bc17"],
  "actions/checkout" => ["v7.0.1", "3d3c42e5aac5ba805825da76410c181273ba90b1"],
  "node-v26.8.1-linux-x64.tar.xz" => ["26.8.1", "3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d"],
  "go1.27.0.linux-amd64.tar.gz" => ["1.27.0", "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685"]
}.freeze

DISALLOWED_NPM_LICENSE = /(?:^|\b)(?:AGPL|GPL|LGPL|SSPL|BUSL|BSL|Proprietary|UNLICENSED|NOASSERTION|Commons Clause)(?:\b|$)/i
DEFAULT_PERMISSIVE_NPM_LICENSES = Set.new(%w[0BSD Apache-2.0 BSD-2-Clause BSD-3-Clause ISC MIT]).freeze
PROHIBITED_DIRECT_PACKAGES = Set.new(["@asyncapi/cli", "ajv-cli"]).freeze
PROHIBITED_SETUP_ACTIONS = Set.new(["actions/setup-node", "actions/setup-go", "ruby/setup-ruby"]).freeze
FOUNDATION_ROLLBACK_TARGET = "git:e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31"
DEVLANE_CANDIDATE_NAME = "devlane-stead-primitives"
DEVLANE_PROVENANCE_SURFACE_SHA256 = "4b0b3d6d91263db16b6c59c59c606775fa92924543fd51cc88ae9a808aafc44e"
DEVLANE_REGISTRY_SURFACE_SHA256 = "bfe1046598dc8a4a400967a4848ed75d2aca98996a22aa91a1d4790c42704cc0"
DEVLANE_LICENSE_BLOB_SHA1 = "b39a03349aaf17ccb61bef17f9f0e88d86a746ca"
DEVLANE_LICENSE_CONTENT_SHA256 = "854e83f31c0027ba9ea80691fcc111c5cccc7ee75378462b1e4d2af99c2d269f"
DEVLANE_LICENSE_SIZE_BYTES = 1064
DEVLANE_PROPOSED_DESTINATION_PATHS = [
  "packages/design-system/src/tokens.css",
  "packages/design-system/src/primitives.tsx"
].freeze
DEVLANE_GOVERNED_DESTINATION_ROOTS = DEVLANE_PROPOSED_DESTINATION_PATHS.map { |path| File.dirname(path) }.uniq.freeze
DEVLANE_GOVERNED_STAGING_ROOTS = ["third_party/devlane"].freeze
DEVLANE_SOURCE_LOCATION_ALLOWLIST = {
  "staging_roots" => DEVLANE_GOVERNED_STAGING_ROOTS,
  "destination_files" => DEVLANE_PROPOSED_DESTINATION_PATHS,
  "alternate_locations_prohibited" => true
}.freeze
DEVLANE_PINNED_SOURCE_FINGERPRINTS = {
  13_613 => "870cd43b2af00ee047217ca72882343550fa0a862e0c86fb29771ae8aabcc7f2",
  2_077 => "7c5f4bb8d08a00dbafcf2e26023f2cbb238fea70b465a54b4fe349069983a0ae",
  1_328 => "e62355d412674de0fea7fde6a3ebf7aa2eeb57aa317fd2e2bf8bd61a6f14dd66",
  978 => "c709b3508c61ff8886c5859804d09a46b8d202b76ab68dda0ca31e3d07ff35bc",
  1_165 => "35eb3b4e8ce4562833c03099d28f86d8484dc63a487fd42f66493a418ebe46b4",
  249 => "8ba0dc9ca6e8a1243b433ea757b2aab3ef25d693a88fcb3560ca41601b2b066b"
}.freeze
DEVLANE_PENDING_BUILD_GRAPH_FILES = [
  {
    "path" => ".npmrc",
    "type" => "regular_file",
    "sha256" => "a0dcd9578d43df879467e9de60dfb9b469ed9674a3729e288e57291f6b35f6c4"
  },
  {
    "path" => "Makefile",
    "type" => "regular_file",
    "sha256" => "1f51fc6bc6a0ee2b557be94180a00063325539e59f9b0ed9feb539f08c864007"
  },
  {
    "path" => "package.json",
    "type" => "regular_file",
    "sha256" => "5c19ea5409af83c54752ad926e39c47dda86403af8e0bd8de12edc76313f196c"
  },
  {
    "path" => "package-lock.json",
    "type" => "regular_file",
    "sha256" => "c05ad356c65817e97299903378e5bdcd36d2c926ffbf7b4aa750ef0c5695a917"
  },
  {
    "path" => "scripts/run_pinned_node.sh",
    "type" => "regular_file",
    "sha256" => "01a384b7c510aa54af6c3d2ca621325c895442a3c98250c87b204bf71c22271c"
  },
  {
    "path" => "tsconfig.base.json",
    "type" => "regular_file",
    "sha256" => "cc6a84094fde40708451f89eaec157c135f82bcaf4b8e535e839c656aa973997"
  },
  {
    "path" => "apps/web/index.html",
    "type" => "regular_file",
    "sha256" => "e0ce791634b186b5837900e399c3e60afa0ad6873fa78a8c45cc5e6fec8a88a3"
  },
  {
    "path" => "apps/web/package.json",
    "type" => "regular_file",
    "sha256" => "e8d7898c77d0fee45de869c6de8a325ba0a4e5ebe11db09e75f3b87eebce6dd4"
  },
  {
    "path" => "apps/web/tsconfig.json",
    "type" => "regular_file",
    "sha256" => "c17de10c1dd6dbd5ab2bcf60ce70b54f72edf7d8f1a1b95db2317bcb76cecf3e"
  },
  {
    "path" => "apps/web/vitest.config.ts",
    "type" => "regular_file",
    "sha256" => "c664adc17411cf22a3c17354bcc8273f71ba572dcc4e8dcdb484c36f995e1eba"
  },
  {
    "path" => "apps/web/src/Foundation.test.tsx",
    "type" => "regular_file",
    "sha256" => "0ad7bab3f5b4b9989063fcbc8a6c05d920cace478220ef108877b2852d45973a"
  },
  {
    "path" => "apps/web/src/Foundation.tsx",
    "type" => "regular_file",
    "sha256" => "975c58412e9e70d5b40b5913760709dcf419c38c789509101e092e5a82387e47"
  },
  {
    "path" => "apps/web/src/main.tsx",
    "type" => "regular_file",
    "sha256" => "4a0d5b9a03ae7fe7b5fe91793d451336c9f37a72b6012d905cdae0f15870cb99"
  },
  {
    "path" => "apps/web/src/styles.css",
    "type" => "regular_file",
    "sha256" => "5ced421fe16d22804cbd5bb2722f9ec98acec73bd544d2b342b2fa25cee3db12"
  }
].freeze
DEVLANE_PENDING_VERIFIED_OUTPUT_FILES = [
  {
    "path" => "apps/web/dist/.vite/manifest.json",
    "type" => "regular_file",
    "sha256" => "3fbf96e89bfeafff2e6a60fae5537bd7f434a09a9d7ade866fa9c50a9a7cf825"
  },
  {
    "path" => "apps/web/dist/assets/index-B2D1I_TZ.css",
    "type" => "regular_file",
    "sha256" => "89c28a1d169409bd304263b71660f26506d617582a49abf0fd8721556ceb0fef"
  },
  {
    "path" => "apps/web/dist/assets/index-C25eOy4C.js",
    "type" => "regular_file",
    "sha256" => "d523f43d46b2f22af76db4d471846beb35a46bb71c4a4aac45100bd710b53d6b"
  },
  {
    "path" => "apps/web/dist/index.html",
    "type" => "regular_file",
    "sha256" => "ce0fa618e75b64d07ad6c72f1a0889caaf9dc56148ccc27ef5e8c3bfb5d9e504"
  }
].freeze
DEVLANE_PENDING_BUILD_GRAPH = {
  "state" => "CLOSED_UNTIL_APPROVED_IMPORT",
  "frontend_root" => "apps/web",
  "generated_roots" => [
    "apps/web/node_modules"
  ],
  "verified_optional_output" => {
    "root" => "apps/web/dist",
    "files" => DEVLANE_PENDING_VERIFIED_OUTPUT_FILES
  },
  "files" => DEVLANE_PENDING_BUILD_GRAPH_FILES,
  "rule" => (
    "While source distribution or import remains unapproved, every frontend source, " \
    "test, configuration, package, and build-control input must remain a regular in-tree " \
    "file at the recorded digest; no additional frontend entry or symlink may enter the " \
    "build graph. When dist exists it must match the exact clean-build output manifest; " \
    "node_modules must be recreated from the exact locked package graph and may not carry " \
    "authored source."
  )
}.freeze
DEVLANE_PENDING_FRONTEND_FILES = DEVLANE_PENDING_BUILD_GRAPH_FILES
  .filter_map { |entry| entry["path"] if entry["path"].start_with?("apps/web/") }
  .to_set
  .freeze
DEVLANE_PENDING_OUTPUT_FILES = DEVLANE_PENDING_VERIFIED_OUTPUT_FILES
  .map { |entry| entry["path"] }
  .to_set
  .freeze
DEVLANE_LICENSE_TEXT = <<~'LICENSE'.freeze
  MIT License

  Copyright (c) 2026 Devlane

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
LICENSE
DEVLANE_NOTICE_SECTION = <<~MARKDOWN.chomp.freeze
  ## NOTICE-DEVLANE-MIT — Devlane

  Pinned source: <https://github.com/Devlaner/devlane> at commit
  `7719dcadf91f881b5aefe8b74012ffcfbba0bc17`.
  Verified upstream `LICENSE` blob: `b39a03349aaf17ccb61bef17f9f0e88d86a746ca`;
  SHA-256: `854e83f31c0027ba9ea80691fcc111c5cccc7ee75378462b1e4d2af99c2d269f`;
  size: 1,064 bytes.

  No Devlane source or asset has been imported yet. This notice is checked in now as a
  provenance regression fixture. It must remain with every future distributed copy or
  substantial portion of Devlane-derived material, together with an accurate modification
  statement.

  #{DEVLANE_LICENSE_TEXT.chomp}
MARKDOWN
EXPECTED_DEVLANE_PENDING_DECISION = {
  "category" => "ALLOW-PERMISSIVE",
  "status" => "REVIEWED_PENDING_INDEPENDENT_APPROVAL",
  "independent_approval_required" => true,
  "approvers" => [],
  "approved_at" => nil
}.freeze
EXPECTED_DEVLANE_PENDING_PROVENANCE_APPROVAL = {
  "status" => "REVIEWED_PENDING_INDEPENDENT_APPROVAL",
  "approved_source_distribution" => false,
  "approvers" => [],
  "approved_at" => nil
}.freeze
EXACT_GO_VERSION = /\Av\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z/
GO_H1_DIGEST = /\Ah1:[A-Za-z0-9+\/]{43}=\z/
PROHIBITED_GO_DIRECTIVES = Set.new(%w[exclude godebug replace retract tool toolchain]).freeze
REJECTED_PGX_NOTICE_IDS = %w[
  NOTICE-PGX-MIT
  NOTICE-PGPASSFILE-MIT
  NOTICE-PGSERVICEFILE-MIT
  NOTICE-PUDDLE-MIT
  NOTICE-GO-X-SYNC-BSD-3-CLAUSE
  NOTICE-GO-X-TEXT-BSD-3-CLAUSE
].freeze
PGX_NOTICE_QUARANTINE_MARKER = "STEAD-NOTICE-QUARANTINE:DEP-APP-GO-PGX-V5-5-10-0:REJECTED-NOT-RELEASE-INPUT"
PGX_NOTICE_QUARANTINE_BEGIN = "<!-- BEGIN #{PGX_NOTICE_QUARANTINE_MARKER} -->"
PGX_NOTICE_QUARANTINE_END = "<!-- END #{PGX_NOTICE_QUARANTINE_MARKER} -->"
PGX_NOTICE_QUARANTINE_HEADING = "## REJECTED / QUARANTINED — pgx v5.10.0 closure notices (not release input)"
PGX_NOTICE_QUARANTINE_FRAMING = <<~MARKDOWN.chomp.freeze
  These exact six notices are rejected intake evidence only; this block is not approved,
  distributed, or a release-notice input. Any reuse requires a new approval ID and independent approval.
MARKDOWN
PGX_NOTICE_QUARANTINE_BINDING = {
  "marker" => PGX_NOTICE_QUARANTINE_MARKER,
  "status" => "REJECTED_EVIDENCE_ONLY",
  "release_notice_input" => false,
  "begin_marker" => PGX_NOTICE_QUARANTINE_BEGIN,
  "section_heading" => PGX_NOTICE_QUARANTINE_HEADING,
  "framing" => PGX_NOTICE_QUARANTINE_FRAMING,
  "end_marker" => PGX_NOTICE_QUARANTINE_END,
  "notice_ids" => REJECTED_PGX_NOTICE_IDS
}.freeze
EXPECTED_PGXPOOL_CLOSURE = {
  "github.com/jackc/pgpassfile" => ["v1.0.0", "h1:/6Hmqy13Ss2zCq62VdNG8tM1wchn8zjSGOBJ6icpsIM=", "h1:CEx0iS5ambNFdcRtxPj5JhEz+xB6uRky5eyVu/W2HEg=", "99d8e8e28945ffceaf75b0299fcb2bb656b8a683", "MIT", "NOTICE-PGPASSFILE-MIT"],
  "github.com/jackc/pgservicefile" => ["v0.0.0-20240606120523-5a60cdf6a761", "h1:iCEnooe7UlwOQYpKFhBabPMi4aNAfoODPEFNiAnClxo=", "h1:5TJZWKEWniPve33vlWYSoGYefn3gLQRzjfDlhSJ9ZKM=", "5a60cdf6a76120dc3d5152b95f3b5fd8aa7cc9eb", "MIT", "NOTICE-PGSERVICEFILE-MIT"],
  "github.com/jackc/puddle/v2" => ["v2.2.2", "h1:PR8nw+E/1w0GLuRFSmiioY6UooMp6KJv0/61nB7icHo=", "h1:vriiEXHvEE654aYKXXjOvZM39qJ0q+azkZFrfEOc3H4=", "bd09d14bd4018b6d65a9d7770e2f3ddf8b00af1c", "MIT", "NOTICE-PUDDLE-MIT"],
  "golang.org/x/sync" => ["v0.17.0", "h1:l60nONMj9l5drqw6jlhIELNv9I0A4OFgRsG9k2oT9Ug=", "h1:9KTHXmSnoGruLpwFjVSX0lNNA75CykiMECbovNTZqGI=", "04914c200cb38d4ea960ee6a4c314a028c632991", "BSD-3-Clause", "NOTICE-GO-X-SYNC-BSD-3-CLAUSE"],
  "golang.org/x/text" => ["v0.29.0", "h1:1neNs90w9YzJ9BocxfsQNHKuAT4pkghyXc4nhZ6sJvk=", "h1:7MhJOA9CD2qZyOKYazxdYMF85OwPdEr9jTtBpO7ydH4=", "e69f31bf9cf2f46bd3325bc9bad37fe9001731c2", "BSD-3-Clause", "NOTICE-GO-X-TEXT-BSD-3-CLAUSE"]
}.freeze
EXPECTED_REJECTED_DECISIONS = {
  "github.com/jackc/pgx/v5" => {
    "category" => "ALLOW-PERMISSIVE",
    "status" => "REJECTED",
    "independent_approval_required" => true,
    "approvers" => [],
    "approved_at" => nil,
    "reason_codes" => ["REACHABLE_KNOWN_VULNERABILITY"],
    "evidence_refs" => [
      "dependency-evidence/stead-p1-015-postgresql.yaml#go_candidate",
      "github-pr-39-comment-5471438314",
      "github-issue-38-comment-5471438378"
    ]
  },
  "postgres" => {
    "category" => "UNKNOWN",
    "status" => "REJECTED",
    "independent_approval_required" => true,
    "approvers" => [],
    "approved_at" => nil,
    "reason_codes" => [
      "UNRESOLVED_CRITICAL_HIGH_FINDINGS",
      "INCOMPLETE_LICENSE_CLASSIFICATION",
      "MISSING_SIGNED_SUPPLY_CHAIN_EVIDENCE"
    ],
    "evidence_refs" => [
      "dependency-evidence/stead-p1-015-postgresql.yaml#oci_candidate",
      "github-pr-39-comment-5471438314",
      "github-issue-38-comment-5471438378"
    ]
  }
}.freeze
EXPECTED_POSTGRESQL_REJECTION_EVIDENCE = {
  ["candidate_state"] => "REJECTED_QUARANTINED_NOT_INTEGRATED",
  ["recorded_at"] => "2026-08-30T21:35:54Z",
  ["independent_review", "candidate_revision"] => "f929649e9c5896d579147b922fdd87659f26c2ff",
  ["independent_review", "completed_at"] => "2026-08-30T21:35:54Z",
  ["independent_review", "disposition"] => "REVISE_HOLD",
  ["independent_review", "release_eligible"] => false,
  ["independent_review", "evidence_references"] => ["github-pr-39-comment-5471438314", "github-issue-38-comment-5471438378"],
  ["go_candidate", "notice_id"] => "NOTICE-PGX-MIT",
  ["go_candidate", "notice_quarantine"] => PGX_NOTICE_QUARANTINE_BINDING,
  ["go_candidate", "vulnerability_scan", "status"] => "REJECTED_REACHABLE_VULNERABILITY",
  ["go_candidate", "vulnerability_scan", "completed_at"] => "2026-08-30T21:35:54Z",
  ["go_candidate", "vulnerability_scan", "tool"] => {
    "name" => "govulncheck", "version" => "v1.7.0", "go_version" => "go1.27.0",
    "database" => "https://vuln.go.dev", "database_updated_at" => "2026-08-28T14:47:45Z"
  },
  ["go_candidate", "vulnerability_scan", "result"] => {
    "advisory_id" => "GO-2026-5970", "cve_id" => "CVE-2026-56852",
    "vulnerable_module" => "golang.org/x/text", "vulnerable_version" => "v0.29.0",
    "fixed_version" => "v0.39.0", "reachable_path" => "github.com/jackc/pgx/v5 SCRAM authentication"
  },
  ["go_candidate", "vulnerability_scan", "evidence_digest"] => {
    "closure_go_mod_sha256" => "42d674c3b77defbc95c0b96a077302adc47f70b049520843df185b13cebada49",
    "closure_go_sum_sha256" => "2f18690ef7080bc7b609a33b4f779b44e197f6f6c5f405c34e51a8931579c8c0"
  },
  ["go_candidate", "provenance_review", "status"] => "REPRODUCED_NOT_APPROVED",
  ["go_candidate", "provenance_review", "result"] => "Exact tag commit, module and go.mod checksums, pgxpool closure, license files, and notice obligations reproduced.",
  ["go_candidate", "possible_successor", "status"] => "UNAPPROVED_INFORMATION_ONLY",
  ["go_candidate", "possible_successor", "selected_modules"] => [
    {
      "module" => "golang.org/x/text", "version" => "v0.39.0",
      "module_sum" => "h1:UbZz4pLOvn600D6Oh6GGEI6VAmndrEBLv8/6BEXzyus=",
      "go_mod_sum" => "h1:3UwRclnC2g0TU9x8PZiyfOajCd1zaUNHF9cvqcQZ+ZM="
    },
    {
      "module" => "golang.org/x/sync", "version" => "v0.21.0",
      "module_sum" => "h1:HLII4xRRTtCRkxYp4HNFF0Js/Og6q2i++KXbg0gHCwM=",
      "go_mod_sum" => "h1:9xrNwdLfx4jkKbNva9FpL6vEN7evnE43NNNJQ2LF3+0="
    }
  ],
  ["go_candidate", "possible_successor", "govulncheck_findings"] => 0,
  ["go_candidate", "possible_successor", "closure_go_mod_sha256"] => "925e120507c7b457b98f5dcb68a05f3044ab9883a608c591f6a9f7bdbb636ac4",
  ["go_candidate", "possible_successor", "closure_go_sum_sha256"] => "760a7e8525ac7caaf6fa69cbc51ae7661a0a942369b9412e1a2cd17655e51a33",
  ["go_candidate", "possible_successor", "required_next_step"] => "New immutable intake revision, exact closure/checksums/notices, compatibility tests, and fresh independent rescan.",
  ["oci_candidate", "created"] => "2026-08-25T00:42:19.848754437Z",
  ["oci_candidate", "source_revision"] => "9d15534160ade17f2b6c455a39ee967c49b1937d",
  ["oci_candidate", "vulnerability_scan", "status"] => "REJECTED_UNRESOLVED_CRITICAL_HIGH",
  ["oci_candidate", "vulnerability_scan", "completed_at"] => "2026-08-30T21:35:54Z",
  ["oci_candidate", "vulnerability_scan", "reviewed_disposition"] => "Both independent scanners retain unresolved Critical/High findings after the reviewed non-applicable results; RG-08 is not satisfied.",
  ["oci_candidate", "vulnerability_scan", "reports"] => [
    {
      "tool" => "trivy", "version" => "0.74.0", "database_version" => 2,
      "database_updated_at" => "2026-08-30T19:01:43.110912224Z",
      "report_created_at" => "2026-08-30T21:27:24.886430412Z",
      "report_sha256" => "928280778e02c072db6b3f05a4e8fee9b535b2a75eca668dfba689697e1be720",
      "raw_os_critical" => 15, "raw_os_high" => 45
    },
    {
      "tool" => "grype", "version" => "0.118.0", "database_schema" => "v6.1.9",
      "database_built_at" => "2026-08-30T06:27:52Z",
      "report_created_at" => "2026-08-30T21:29:44.933982995Z",
      "report_sha256" => "5307fb983fbe1d72971956244d538e4caec97d41e75a9f64304cc0bbbb010693",
      "raw_os_critical" => 26, "raw_os_high" => 49
    }
  ],
  ["oci_candidate", "package_license_inventory", "status"] => "REJECTED_INCOMPLETE_LICENSE_CLASSIFICATION",
  ["oci_candidate", "package_license_inventory", "tool"] => "syft",
  ["oci_candidate", "package_license_inventory", "version"] => "1.51.1",
  ["oci_candidate", "package_license_inventory", "report_sha256"] => "a5859ae8a27dac4117c518a4cc0a8433c6e336633143edb386a59c2eaba678e8",
  ["oci_candidate", "package_license_inventory", "published_spdx_license_concluded"] => "NOASSERTION",
  ["oci_candidate", "package_license_inventory", "published_spdx_noassertion_concluded_packages"] => 204,
  ["oci_candidate", "package_license_inventory", "scanner_custom_tokens"] => ["Custom-Unicode", "Custom-pg_dump", "Custom-regex"],
  ["oci_candidate", "package_license_inventory", "disposition"] => "Legal/policy normalization is incomplete; UNKNOWN remains rejected and quarantined.",
  ["oci_candidate", "published_supply_chain_statements", "status"] => "REPRODUCED_UNSIGNED_EVIDENCE_ONLY",
  ["oci_candidate", "published_supply_chain_statements", "attestation_manifest_digest"] => "sha256:4ba017d475bffe5bb91d50107c339b64a43853b264a2426ceddfa47557939ea3",
  ["oci_candidate", "published_supply_chain_statements", "subject_manifest_digest"] => "sha256:1938c16e9d2f10a6a3623b344b64ae8d45f407f2c5f34f0979468bb689b9227a",
  ["oci_candidate", "published_supply_chain_statements", "spdx"] => {
    "predicate_type" => "https://spdx.dev/Document", "version" => "SPDX-2.3",
    "layer_digest" => "sha256:90162b18863727e5883dc9c5fcae8c65b6ff353e7e9caa03292e77626d386d47"
  },
  ["oci_candidate", "published_supply_chain_statements", "slsa"] => {
    "predicate_type" => "https://slsa.dev/provenance/v0.2",
    "layer_digest" => "sha256:81926168df652b2566d246259a832e999ed94d3c134671eb1adb6e07a292f05e",
    "source_revision" => "9d15534160ade17f2b6c455a39ee967c49b1937d"
  },
  ["oci_candidate", "published_supply_chain_statements", "assurance_limit"] => "Published statements are digest-bound provenance evidence only; no SLSA level or approval is claimed.",
  ["oci_candidate", "signature_attestation_review", "status"] => "REJECTED_NO_COSIGN_SIGNATURE_OR_SIGNED_ATTESTATION",
  ["oci_candidate", "signature_attestation_review", "tool"] => "cosign",
  ["oci_candidate", "signature_attestation_review", "version"] => "3.1.3",
  ["oci_candidate", "signature_attestation_review", "checked_digests"] => [
    "sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825",
    "sha256:1938c16e9d2f10a6a3623b344b64ae8d45f407f2c5f34f0979468bb689b9227a"
  ],
  ["oci_candidate", "signature_attestation_review", "result"] => "No Cosign signature or signed Cosign attestation was found for either digest."
}.freeze

def allowed_lock_license?(license)
  license.is_a?(String) && DEFAULT_PERMISSIVE_NPM_LICENSES.include?(license)
end

if ARGV.first == "--test-lock-license"
  candidate = ARGV[1]
  abort "missing license fixture" if candidate.nil?

  exit(allowed_lock_license?(candidate) ? 0 : 1)
end

if ARGV.first == "--test-rollback"
  candidate = ARGV[1]
  abort "missing rollback fixture" if candidate.nil?

  exit(candidate == FOUNDATION_ROLLBACK_TARGET ? 0 : 1)
end

def strict_yaml_node_errors(node, path = "$")
  case node
  when Psych::Nodes::Mapping
    errors = []
    seen_keys = Set.new
    node.children.each_slice(2) do |key_node, value_node|
      unless key_node.is_a?(Psych::Nodes::Scalar)
        errors << "#{path}: mapping keys must be scalars"
        next
      end

      key = key_node.value
      errors << "#{path}: YAML merge keys are prohibited" if key == "<<"
      errors << "#{path}: duplicate mapping key #{key.inspect}" unless seen_keys.add?(key)
      errors.concat(strict_yaml_node_errors(value_node, "#{path}.#{key}"))
    end
    errors
  when Psych::Nodes::Sequence
    node.children.each_with_index.flat_map do |entry, index|
      strict_yaml_node_errors(entry, "#{path}[#{index}]")
    end
  when Psych::Nodes::Alias
    ["#{path}: YAML aliases are prohibited"]
  else
    []
  end
end

def strict_yaml_structure_errors(source, filename: "fixture.yaml")
  stream = Psych.parse_stream(source, filename: filename)
  documents = stream.children
  return ["#{filename}: YAML must contain exactly one document"] unless documents.length == 1

  root = documents.first.root
  return ["#{filename}: YAML document must not be empty"] if root.nil?

  strict_yaml_node_errors(root)
rescue Psych::Exception => e
  ["#{filename}: YAML parse error: #{e.message}"]
end

def load_yaml(path)
  relative = path.delete_prefix(ROOT + "/")
  source = File.read(path)
  structure_errors = strict_yaml_structure_errors(source, filename: relative)
  abort structure_errors.join("\n") unless structure_errors.empty?

  YAML.safe_load(source, permitted_classes: [], permitted_symbols: [], aliases: false, filename: relative)
rescue Psych::Exception => e
  abort "#{relative}: YAML error: #{e.message}"
end

def resolve_ref(root_schema, reference)
  raise "unsupported schema reference #{reference}" unless reference.start_with?("#/")

  reference.delete_prefix("#/").split("/").reduce(root_schema) do |cursor, token|
    cursor.fetch(token.gsub("~1", "/").gsub("~0", "~"))
  end
end

def schema_errors(value, schema, root_schema, path = "$")
  schema = resolve_ref(root_schema, schema.fetch("$ref")) if schema.key?("$ref")
  errors = []

  if schema.key?("oneOf")
    branches = schema.fetch("oneOf").map { |candidate| schema_errors(value, candidate, root_schema, path) }
    return ["#{path}: must match exactly one schema alternative"] unless branches.count(&:empty?) == 1

    return []
  end

  errors << "#{path}: expected #{schema["const"].inspect}, got #{value.inspect}" if schema.key?("const") && value != schema["const"]
  errors << "#{path}: value #{value.inspect} is outside enum" if schema.key?("enum") && !schema["enum"].include?(value)

  type_matches = case schema["type"]
                 when nil then true
                 when "object" then value.is_a?(Hash)
                 when "array" then value.is_a?(Array)
                 when "string" then value.is_a?(String)
                 when "null" then value.nil?
                 else false
                 end
  unless type_matches
    errors << "#{path}: expected #{schema["type"]}, got #{value.class}"
    return errors
  end

  if value.is_a?(Hash)
    Array(schema["required"]).each do |key|
      errors << "#{path}: missing required property #{key}" unless value.key?(key)
    end
    properties = schema.fetch("properties", {})
    if schema["additionalProperties"] == false
      (value.keys - properties.keys).each { |key| errors << "#{path}: unknown property #{key}" }
    end
    value.each do |key, child|
      next unless properties.key?(key)

      errors.concat(schema_errors(child, properties.fetch(key), root_schema, "#{path}.#{key}"))
    end
  elsif value.is_a?(Array)
    errors << "#{path}: requires at least #{schema["minItems"]} items" if schema["minItems"] && value.length < schema["minItems"]
    if schema["uniqueItems"]
      normalized = value.map { |item| JSON.generate(item) }
      errors << "#{path}: array items must be unique" unless normalized.uniq.length == normalized.length
    end
    value.each_with_index do |child, index|
      errors.concat(schema_errors(child, schema.fetch("items"), root_schema, "#{path}[#{index}]")) if schema["items"]
    end
  elsif value.is_a?(String)
    errors << "#{path}: string is too short" if schema["minLength"] && value.length < schema["minLength"]
    errors << "#{path}: does not match #{schema["pattern"]}" if schema["pattern"] && !Regexp.new(schema["pattern"]).match?(value)
    case schema["format"]
    when "uri"
      begin
        uri = URI.parse(value)
        errors << "#{path}: URI must use https and include a host" unless uri.is_a?(URI::HTTPS) && uri.host
      rescue URI::InvalidURIError
        errors << "#{path}: invalid URI"
      end
    when "date-time"
      begin
        Time.iso8601(value)
      rescue ArgumentError
        errors << "#{path}: invalid RFC3339 date-time"
      end
    end
  end

  errors
end

def direct_npm_dependencies(lockfile, errors)
  manifests = [["", JSON.parse(File.read(File.join(ROOT, "package.json")))]]
  Array(manifests.first.last["workspaces"]).each do |workspace|
    if workspace.include?("*")
      errors << "package.json: workspace globs are not allowed in the locked foundation"
      next
    end
    path = File.join(ROOT, workspace, "package.json")
    errors << "package.json: missing workspace manifest #{workspace}/package.json" and next unless File.file?(path)

    manifests << [workspace, JSON.parse(File.read(path))]
  end

  dependencies = []
  manifests.each do |workspace, manifest|
    %w[dependencies devDependencies optionalDependencies].each do |group|
      manifest.fetch(group, {}).each do |name, version|
        if PROHIBITED_DIRECT_PACKAGES.include?(name)
          errors << "#{workspace.empty? ? "package.json" : "#{workspace}/package.json"}: prohibited direct package #{name}"
        end
        unless version.match?(/\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\z/)
          errors << "#{workspace.empty? ? "package.json" : "#{workspace}/package.json"}: #{name} must use an exact version, got #{version.inspect}"
        end

        lock_manifest = lockfile.fetch("packages", {}).fetch(workspace, {})
        locked_spec = lock_manifest.fetch(group, {})[name]
        errors << "package-lock.json: #{workspace}:#{group}:#{name} does not match manifest version #{version}" unless locked_spec == version

        candidate_paths = []
        candidate_paths << "#{workspace}/node_modules/#{name}" unless workspace.empty?
        candidate_paths << "node_modules/#{name}"
        lock_path = candidate_paths.find { |candidate| lockfile.fetch("packages", {}).key?(candidate) }
        if lock_path.nil?
          errors << "package-lock.json: no installed package record for #{workspace}:#{name}"
          next
        end
        dependencies << { "workspace" => workspace, "name" => name, "version" => version, "lock" => lockfile["packages"][lock_path] }
      end
    end
  end
  dependencies
rescue JSON::ParserError => e
  errors << "npm manifest/lock JSON error: #{e.message}"
  []
end

def go_requirements(source, errors, label = "go.mod")
  requirements = []
  require_block = false

  source.each_line.with_index(1) do |raw_line, line_number|
    line = raw_line.strip
    next if line.empty? || line.start_with?("//")

    directive = line[/\A([A-Za-z]+)\b/, 1]
    if PROHIBITED_GO_DIRECTIVES.include?(directive)
      errors << "#{label}:#{line_number}: #{directive} directives are prohibited; approve the exact source through the dependency registry"
      next
    end

    if line.match?(/\Arequire\s*\(\s*\z/)
      errors << "#{label}:#{line_number}: nested require block" if require_block
      require_block = true
      next
    end
    if require_block && line == ")"
      require_block = false
      next
    end

    declaration = if require_block
                    line
                  elsif (match = line.match(/\Arequire\s+(.+)\z/))
                    match[1]
                  end
    next unless declaration

    requirement, comment = declaration.split(%r{\s+//\s*}, 2)
    indirect = comment&.strip == "indirect"
    if comment && !indirect
      errors << "#{label}:#{line_number}: require annotation must be exactly // indirect"
    end

    module_name, version, extra = requirement.split(/\s+/, 3)
    if module_name.nil? || version.nil? || extra
      errors << "#{label}:#{line_number}: malformed require declaration"
      next
    end
    unless version.match?(EXACT_GO_VERSION)
      errors << "#{label}:#{line_number}: #{module_name} must use an exact Go module version, got #{version.inspect}"
    end
    requirements << { "name" => module_name, "version" => version, "indirect" => indirect }
  end

  errors << "#{label}: unterminated require block" if require_block
  names = requirements.map { |entry| entry["name"] }
  errors << "#{label}: required module paths must be unique" unless names.uniq.length == names.length
  requirements
end

def go_sum_entries(source, errors, label = "go.sum")
  entries = {}
  source.each_line.with_index(1) do |raw_line, line_number|
    line = raw_line.strip
    next if line.empty?

    module_name, version, digest, extra = line.split(/\s+/, 4)
    if module_name.nil? || version.nil? || digest.nil? || extra
      errors << "#{label}:#{line_number}: malformed checksum entry"
      next
    end
    errors << "#{label}:#{line_number}: checksum must use Go h1 format" unless digest.match?(GO_H1_DIGEST)
    key = [module_name, version]
    errors << "#{label}:#{line_number}: duplicate checksum entry for #{module_name} #{version}" if entries.key?(key)
    entries[key] = digest
  end
  entries
end

def validate_go_dependencies(mod_source, sum_source, components, errors, allowed_indirect: {}, mod_label: "go.mod", sum_label: "go.sum")
  requirements = go_requirements(mod_source, errors, mod_label)
  dependencies = requirements.reject { |entry| entry["indirect"] }
  sums = go_sum_entries(sum_source, errors, sum_label)

  dependencies.each do |entry|
    name = entry["name"]
    version = entry["version"]
    record = components[name]
    if record.nil? || record.dig("component", "kind") != "go_module" || record.dig("component", "ecosystem") != "go"
      errors << "dependency registry: direct Go module #{name}@#{version} has no go_module candidate record"
      next
    end

    errors << "#{name}: registry version differs from go.mod" unless record.dig("component", "version") == version
    errors << "#{name}: direct Go module is not approved for use" unless record.dig("decision", "status") == "APPROVED"
    module_sum = sums[[name, version]]
    go_mod_sum = sums[[name, "#{version}/go.mod"]]
    errors << "#{sum_label}: missing module checksum for #{name} #{version}" if module_sum.nil?
    errors << "#{sum_label}: missing go.mod checksum for #{name} #{version}" if go_mod_sum.nil?
    if module_sum && record.dig("component", "digest", "value") != module_sum
      errors << "#{name}: registry module checksum differs from #{sum_label}"
    end
    if go_mod_sum && record.dig("component", "module_file_digest", "value") != go_mod_sum
      errors << "#{name}: registry go.mod checksum differs from #{sum_label}"
    end
  end
  indirect = requirements.select { |entry| entry["indirect"] }
  indirect.each do |entry|
    expected = allowed_indirect[entry["name"]]
    if expected.nil?
      errors << "dependency evidence: indirect Go module #{entry["name"]}@#{entry["version"]} is outside every reviewed runtime closure"
      next
    end
    expected_version, expected_sum, expected_go_mod_sum = expected
    errors << "#{entry["name"]}: indirect version differs from reviewed closure" unless entry["version"] == expected_version
    module_sum = sums[[entry["name"], entry["version"]]]
    go_mod_sum = sums[[entry["name"], "#{entry["version"]}/go.mod"]]
    errors << "#{sum_label}: missing module checksum for #{entry["name"]} #{entry["version"]}" if module_sum.nil?
    errors << "#{sum_label}: missing go.mod checksum for #{entry["name"]} #{entry["version"]}" if go_mod_sum.nil?
    errors << "#{entry["name"]}: module checksum differs from reviewed closure" if module_sum && module_sum != expected_sum
    errors << "#{entry["name"]}: go.mod checksum differs from reviewed closure" if go_mod_sum && go_mod_sum != expected_go_mod_sum
  end

  active_names = requirements.map { |entry| entry["name"] }.to_set
  expected_names = allowed_indirect.keys.to_set
  if active_names.include?("github.com/jackc/pgx/v5")
    errors << "go.mod: github.com/jackc/pgx/v5 must be a direct dependency" unless dependencies.any? { |entry| entry["name"] == "github.com/jackc/pgx/v5" }
    missing = expected_names - active_names
    errors << "go.mod: pgxpool reviewed runtime closure is incomplete: #{missing.to_a.sort.join(', ')}" unless missing.empty?
  elsif !(active_names & expected_names).empty?
    errors << "go.mod: pgxpool transitive modules may not be active without direct github.com/jackc/pgx/v5"
  end

  { "direct" => dependencies, "requirements" => requirements }
end

def oci_workflow_references(source, errors, label)
  references = []
  source.each_line.with_index(1) do |raw_line, line_number|
    value = if (match = raw_line.match(/^\s*image:\s*["']?([^\s"'#]+)["']?/))
              match[1]
            elsif (match = raw_line.match(/^\s*container:\s*["']?([^\s"'#]+)["']?/))
              match[1]
            elsif (match = raw_line.match(/^\s*uses:\s*["']?docker:\/\/([^\s"'#]+)["']?/))
              match[1]
            end
    next unless value

    match = value.match(/\A(.+?)(?::([^\/@]+))?@(sha256:[0-9a-f]{64})\z/)
    unless match
      errors << "#{label}:#{line_number}: OCI image #{value.inspect} is not pinned to an immutable SHA-256 digest"
      next
    end
    references << { "name" => match[1], "version" => match[2], "digest" => match[3], "line" => line_number }
  end
  references
end

def validate_oci_workflow_images(workflow_sources, components, errors)
  references = workflow_sources.flat_map do |label, source|
    oci_workflow_references(source, errors, label)
  end
  references.each do |reference|
    name = reference["name"]
    record = components[name]
    unless record && record.dig("component", "kind") == "oci_image" && record.dig("component", "ecosystem") == "oci"
      errors << "dependency registry: workflow OCI image #{name} has no oci_image candidate record"
      next
    end
    if reference["version"] && record.dig("component", "version") != reference["version"]
      errors << "#{name}: registry version differs from workflow image tag"
    end
    errors << "#{name}: workflow image digest differs from approval registry" unless record.dig("component", "digest", "value") == reference["digest"]
    errors << "#{name}: workflow OCI image is not approved for use" unless record.dig("decision", "status") == "APPROVED"
  end
  references
end

def release_approval_errors(active_names, components, release_eligible_statuses)
  active_names.filter_map do |name|
    record = components[name]
    next unless record
    next if release_eligible_statuses.include?(record.dig("decision", "status"))

    "#{name}: active dependency is not independently approved for release"
  end
end

def decision_state_errors(record)
  name = record.dig("component", "name")
  decision = record.fetch("decision", {})
  status = decision["status"]
  approvers = Array(decision["approvers"])
  approved_at = decision["approved_at"]
  reason_codes = Array(decision["reason_codes"])
  evidence_refs = Array(decision["evidence_refs"])
  errors = []

  if decision["category"] == "UNKNOWN" && status != "REJECTED"
    errors << "#{name}: UNKNOWN license category must remain rejected and quarantined"
  end

  case status
  when "REVIEWED_PENDING_INDEPENDENT_APPROVAL"
    errors << "#{name}: pending candidate must not name approvers" unless approvers.empty?
    errors << "#{name}: pending candidate must not have approved_at" unless approved_at.nil?
    errors << "#{name}: pending candidate must not carry rejection reason codes" unless reason_codes.empty?
    errors << "#{name}: pending candidate must not carry rejection evidence references" unless evidence_refs.empty?
  when "REJECTED"
    errors << "#{name}: rejected candidate must not name approvers" unless approvers.empty?
    errors << "#{name}: rejected candidate must not have approved_at" unless approved_at.nil?
    errors << "#{name}: rejected candidate requires stable reason codes" if reason_codes.empty?
    errors << "#{name}: rejected candidate requires stable evidence references" if evidence_refs.empty?
  when "APPROVED"
    errors << "#{name}: approval requires at least two recorded independent identities" if approvers.length < 2
    errors << "#{name}: approval requires approved_at" if approved_at.nil?
    errors << "#{name}: approved candidate must not retain rejection reason codes" unless reason_codes.empty?
    errors << "#{name}: approved candidate must not retain rejection evidence references" unless evidence_refs.empty?
  end

  errors
end

def exact_rejected_candidate_errors(components)
  errors = EXPECTED_REJECTED_DECISIONS.filter_map do |name, expected|
    record = components[name]
    if record.nil?
      "dependency registry: missing rejected evidence record #{name}"
    elsif record["decision"] != expected
      "#{name}: rejected decision or its immutable reason/evidence binding differs from the reviewed disposition"
    end
  end
  postgres_record = components["postgres"]
  if postgres_record && postgres_record.dig("component", "license_expression") != "NOASSERTION"
    errors << "postgres: rejected image license must remain NOASSERTION"
  end
  pgx_record = components["github.com/jackc/pgx/v5"]
  if pgx_record
    obligations = pgx_record.fetch("obligations", {})
    unless obligations["notices"] == REJECTED_PGX_NOTICE_IDS
      errors << "github.com/jackc/pgx/v5: rejected notice obligations must remain the exact six reviewed IDs"
    end
    unless obligations["notice_quarantine"] == PGX_NOTICE_QUARANTINE_BINDING
      errors << "github.com/jackc/pgx/v5: rejected notice quarantine binding differs from the reviewed fail-closed framing"
    end
  end
  errors
end

def nested_value(value, path)
  path.reduce(value) { |cursor, key| cursor.is_a?(Hash) ? cursor[key] : nil }
end

def pgxpool_closure_errors(evidence)
  closure = Array(evidence.dig("go_candidate", "pgxpool_module_closure"))
  actual = closure.to_h do |entry|
    [
      entry["module"],
      [entry["version"], entry["module_sum"], entry["go_mod_sum"], entry["upstream_commit"], entry["license_expression"], entry["notice_id"]]
    ]
  end
  return [] if closure.length == EXPECTED_PGXPOOL_CLOSURE.length && actual == EXPECTED_PGXPOOL_CLOSURE

  ["dependency-evidence/stead-p1-015-postgresql.yaml: pgxpool module closure and notice linkage differ from the reviewed intake"]
end

def postgresql_rejection_evidence_errors(evidence)
  errors = EXPECTED_POSTGRESQL_REJECTION_EVIDENCE.filter_map do |path, expected|
    actual = nested_value(evidence, path)
    next if actual == expected

    "dependency-evidence/stead-p1-015-postgresql.yaml: #{path.join('.')} must preserve rejected finding #{expected.inspect}"
  end
  errors.concat(pgxpool_closure_errors(evidence))
end

def notice_quarantine_errors(source)
  errors = []
  begin_count = source.scan(Regexp.new(Regexp.escape(PGX_NOTICE_QUARANTINE_BEGIN))).length
  end_count = source.scan(Regexp.new(Regexp.escape(PGX_NOTICE_QUARANTINE_END))).length
  errors << "THIRD_PARTY_NOTICES.md: rejected notice quarantine begin marker must occur exactly once" unless begin_count == 1
  errors << "THIRD_PARTY_NOTICES.md: rejected notice quarantine end marker must occur exactly once" unless end_count == 1
  return errors unless begin_count == 1 && end_count == 1

  begin_index = source.index(PGX_NOTICE_QUARANTINE_BEGIN)
  end_index = source.index(PGX_NOTICE_QUARANTINE_END)
  unless begin_index < end_index
    errors << "THIRD_PARTY_NOTICES.md: rejected notice quarantine markers are reversed"
    return errors
  end

  section = source[(begin_index + PGX_NOTICE_QUARANTINE_BEGIN.length)...end_index]
  expected_opening = "\n\n#{PGX_NOTICE_QUARANTINE_HEADING}\n\n#{PGX_NOTICE_QUARANTINE_FRAMING}\n\n"
  unless section.start_with?(expected_opening)
    errors << "THIRD_PARTY_NOTICES.md: rejected notice quarantine heading/framing differs from the exact evidence-only contract"
  end

  section_notice_ids = section.scan(/^## (NOTICE-[A-Z0-9-]+)(?:[ \t]|$)/).flatten
  unless section_notice_ids == REJECTED_PGX_NOTICE_IDS
    errors << "THIRD_PARTY_NOTICES.md: rejected quarantine must contain exactly the six reviewed notice IDs in closure order"
  end
  REJECTED_PGX_NOTICE_IDS.each do |notice_id|
    occurrence_count = source.scan(/^## #{Regexp.escape(notice_id)}(?:[ \t]|$)/).length
    unless occurrence_count == 1
      errors << "THIRD_PARTY_NOTICES.md: #{notice_id} must occur exactly once inside the rejected quarantine"
    end
  end

  outside = source[0...begin_index] + source[(end_index + PGX_NOTICE_QUARANTINE_END.length)..]
  REJECTED_PGX_NOTICE_IDS.each do |notice_id|
    if outside.match?(/^## #{Regexp.escape(notice_id)}(?:[ \t]|$)/)
      errors << "THIRD_PARTY_NOTICES.md: #{notice_id} appears outside the rejected quarantine"
    end
  end
  errors
end

def notice_entry_range(source, notice_id)
  heading = /^## #{Regexp.escape(notice_id)}(?:[ \t].*)?$/
  start_index = source.index(heading)
  return nil unless start_index

  next_notice = source.index(/^## NOTICE-[A-Z0-9-]+(?:[ \t].*)?$/, start_index + 1)
  quarantine_end = source.index(PGX_NOTICE_QUARANTINE_END, start_index + 1)
  end_index = [next_notice, quarantine_end].compact.min
  end_index ? (start_index...end_index) : nil
end

def delete_nested_key!(value, path)
  parent = path[0...-1].reduce(value) { |cursor, key| cursor.fetch(key) }
  parent.delete(path.last)
end

def canonical_json_value(value)
  case value
  when Hash
    value.keys.sort.to_h { |key| [key, canonical_json_value(value.fetch(key))] }
  when Array
    value.map { |entry| canonical_json_value(entry) }
  else
    value
  end
end

def canonical_sha256(value)
  Digest::SHA256.hexdigest(JSON.generate(canonical_json_value(value)))
end

def git_blob_sha1(content)
  Digest::SHA1.hexdigest("blob #{content.bytesize}\0#{content}")
end

def devlane_license_binding_errors(provenance)
  errors = []
  unless provenance.is_a?(Hash)
    return ["devlane-provenance.yaml: document must be a mapping"]
  end

  license = provenance.dig("upstream", "license")
  unless license.is_a?(Hash)
    return ["devlane-provenance.yaml: upstream.license must be a mapping"]
  end

  expected = {
    "path" => "LICENSE",
    "blob" => DEVLANE_LICENSE_BLOB_SHA1,
    "sha256" => DEVLANE_LICENSE_CONTENT_SHA256,
    "size_bytes" => DEVLANE_LICENSE_SIZE_BYTES,
    "expression" => "MIT",
    "notice" => "NOTICE-DEVLANE-MIT"
  }
  unless license == expected
    errors << "devlane-provenance.yaml: upstream MIT license identity/content binding differs from the verified blob"
  end
  unless DEVLANE_LICENSE_TEXT.bytesize == DEVLANE_LICENSE_SIZE_BYTES &&
         Digest::SHA256.hexdigest(DEVLANE_LICENSE_TEXT) == DEVLANE_LICENSE_CONTENT_SHA256 &&
         git_blob_sha1(DEVLANE_LICENSE_TEXT) == DEVLANE_LICENSE_BLOB_SHA1
    errors << "dependency validator: embedded Devlane MIT license does not reproduce the verified blob/content binding"
  end
  errors
end

def devlane_notice_errors(source, provenance)
  errors = devlane_license_binding_errors(provenance)
  heading = /^## NOTICE-DEVLANE-MIT — Devlane$/
  heading_count = source.scan(heading).length
  unless heading_count == 1
    errors << "THIRD_PARTY_NOTICES.md: NOTICE-DEVLANE-MIT heading must occur exactly once"
    return errors
  end

  section_start = source.index(heading)
  section_end = source.index(PGX_NOTICE_QUARANTINE_BEGIN, section_start)
  if section_end.nil?
    errors << "THIRD_PARTY_NOTICES.md: NOTICE-DEVLANE-MIT must precede the rejected-notice quarantine boundary"
    return errors
  end

  actual = source[section_start...section_end]
  expected = "#{DEVLANE_NOTICE_SECTION}\n\n"
  unless actual == expected
    errors << "THIRD_PARTY_NOTICES.md: NOTICE-DEVLANE-MIT body must exactly preserve the verified MIT license, copyright, retention, and modification terms"
  end
  errors
end

def path_entry_exists?(path)
  File.lstat(path)
  true
rescue Errno::ENOENT, Errno::ENOTDIR
  false
end

def devlane_pending_build_graph_file_errors(root, entry)
  relative = entry.fetch("path")
  expected_sha256 = entry.fetch("sha256")
  errors = []
  cursor = File.expand_path(root)

  relative.split("/")[0...-1].each do |component|
    cursor = File.join(cursor, component)
    stat = File.lstat(cursor)
    if stat.symlink? || !stat.directory?
      return ["BUILD_GRAPH_PARENT_TYPE #{relative}: #{cursor.delete_prefix("#{File.expand_path(root)}/")} is #{stat.ftype}, expected directory"]
    end
  end

  absolute = File.join(root, relative)
  stat = File.lstat(absolute)
  unless stat.file? && !stat.symlink?
    return ["BUILD_GRAPH_FILE_TYPE #{relative}: #{stat.ftype}, expected regular_file"]
  end

  actual_sha256 = Digest::SHA256.file(absolute).hexdigest
  unless actual_sha256 == expected_sha256
    errors << "BUILD_GRAPH_DIGEST #{relative}: expected #{expected_sha256}, got #{actual_sha256}"
  end
  errors
rescue Errno::ENOENT, Errno::ENOTDIR
  ["BUILD_GRAPH_MISSING #{relative}: expected regular_file"]
rescue SystemCallError => e
  ["BUILD_GRAPH_READ #{relative}: #{e.class}"]
end

def devlane_pending_verified_output_errors(root)
  output = DEVLANE_PENDING_BUILD_GRAPH.fetch("verified_optional_output")
  relative_root = output.fetch("root")
  absolute_root = File.join(root, relative_root)
  return [] unless path_entry_exists?(absolute_root)

  stat = File.lstat(absolute_root)
  unless stat.directory? && !stat.symlink?
    return ["BUILD_GRAPH_OUTPUT_ROOT_TYPE #{relative_root}: #{stat.ftype}, expected directory"]
  end

  errors = output.fetch("files").flat_map do |entry|
    devlane_pending_build_graph_file_errors(root, entry)
  end
  expanded_root = File.expand_path(root)
  Find.find(absolute_root) do |path|
    next if path == absolute_root

    relative = path.delete_prefix("#{expanded_root}/")
    begin
      entry_stat = File.lstat(path)
      next if entry_stat.directory? && !entry_stat.symlink?
      next if entry_stat.file? && DEVLANE_PENDING_OUTPUT_FILES.include?(relative)

      errors << "BUILD_GRAPH_OUTPUT_UNEXPECTED #{relative}: #{entry_stat.ftype}"
    rescue SystemCallError => e
      errors << "BUILD_GRAPH_OUTPUT_SCAN #{relative}: #{e.class}"
    end
  end
  errors.uniq
rescue SystemCallError => e
  ["BUILD_GRAPH_OUTPUT_SCAN #{relative_root}: #{e.class}"]
end

def devlane_pending_build_graph_errors(root = ROOT)
  errors = DEVLANE_PENDING_BUILD_GRAPH_FILES.flat_map do |entry|
    devlane_pending_build_graph_file_errors(root, entry)
  end
  errors.concat(devlane_pending_verified_output_errors(root))
  expanded_root = File.expand_path(root)
  frontend_relative = DEVLANE_PENDING_BUILD_GRAPH.fetch("frontend_root")
  frontend_root = File.join(expanded_root, frontend_relative)
  frontend_stat = File.lstat(frontend_root)
  unless frontend_stat.directory? && !frontend_stat.symlink?
    errors << "BUILD_GRAPH_ROOT_TYPE #{frontend_relative}: #{frontend_stat.ftype}, expected directory"
    return errors
  end

  generated_roots = DEVLANE_PENDING_BUILD_GRAPH.fetch("generated_roots").to_set
  verified_output_root = DEVLANE_PENDING_BUILD_GRAPH.dig("verified_optional_output", "root")
  Find.find(frontend_root) do |path|
    next if path == frontend_root

    relative = path.delete_prefix("#{expanded_root}/")
    begin
      stat = File.lstat(path)
      if relative == verified_output_root
        Find.prune if stat.directory? && !stat.symlink?
        next
      end
      if generated_roots.include?(relative)
        if stat.directory? && !stat.symlink?
          Find.prune
        else
          errors << "BUILD_GRAPH_GENERATED_ROOT_TYPE #{relative}: #{stat.ftype}, expected directory"
        end
        next
      end

      next if stat.directory? && !stat.symlink?
      next if stat.file? && DEVLANE_PENDING_FRONTEND_FILES.include?(relative)

      errors << "BUILD_GRAPH_UNEXPECTED #{relative}: #{stat.ftype}"
    rescue SystemCallError => e
      errors << "BUILD_GRAPH_SCAN #{relative}: #{e.class}"
    end
  end
  errors.uniq
rescue Errno::ENOENT, Errno::ENOTDIR
  errors << "BUILD_GRAPH_MISSING #{frontend_relative}: expected directory"
  errors.uniq
rescue SystemCallError => e
  errors << "BUILD_GRAPH_SCAN #{frontend_relative}: #{e.class}"
  errors.uniq
end

def devlane_repository_material_state(root = ROOT)
  present_destinations = DEVLANE_PROPOSED_DESTINATION_PATHS.select do |relative|
    path_entry_exists?(File.join(root, relative))
  end

  destination_entries = []
  DEVLANE_GOVERNED_DESTINATION_ROOTS.each do |relative_root|
    absolute_root = File.join(root, relative_root)
    next unless path_entry_exists?(absolute_root)

    unless File.directory?(absolute_root) && !File.symlink?(absolute_root)
      destination_entries << relative_root
      next
    end
    Find.find(absolute_root) do |path|
      next if path == absolute_root

      destination_entries << path.delete_prefix("#{root}/")
    end
  end

  staging_entries = []
  DEVLANE_GOVERNED_STAGING_ROOTS.each do |relative_root|
    absolute_root = File.join(root, relative_root)
    next unless path_entry_exists?(absolute_root)

    unless File.directory?(absolute_root) && !File.symlink?(absolute_root)
      staging_entries << relative_root
      next
    end
    Find.find(absolute_root) do |path|
      next if path == absolute_root

      staging_entries << path.delete_prefix("#{root}/")
    end
  end

  pinned_source_copies = []
  inventory_errors = []
  expanded_root = File.expand_path(root)
  Find.find(expanded_root) do |path|
    relative = path.delete_prefix("#{expanded_root}/")
    next if path == expanded_root

    begin
      stat = File.lstat(path)
      if relative == ".git"
        Find.prune if stat.directory?
        next
      end
      next unless stat.file?

      expected_sha256 = DEVLANE_PINNED_SOURCE_FINGERPRINTS[stat.size]
      next unless expected_sha256

      pinned_source_copies << relative if Digest::SHA256.file(path).hexdigest == expected_sha256
    rescue SystemCallError => e
      inventory_errors << "#{relative}: #{e.class}"
    end
  end

  {
    present_destinations: present_destinations,
    destination_entries: destination_entries,
    staging_entries: staging_entries,
    pinned_source_copies: pinned_source_copies,
    inventory_errors: inventory_errors,
    pending_build_graph_errors: devlane_pending_build_graph_errors(root)
  }
rescue SystemCallError => e
  {
    present_destinations: present_destinations || [],
    destination_entries: destination_entries || [],
    staging_entries: staging_entries || [],
    pinned_source_copies: pinned_source_copies || [],
    inventory_errors: ["repository material scan failed: #{e.class}"],
    pending_build_graph_errors: ["BUILD_GRAPH_SCAN repository: #{e.class}"]
  }
end

def devlane_allowlisted_source_path?(path)
  DEVLANE_PROPOSED_DESTINATION_PATHS.include?(path) || DEVLANE_GOVERNED_STAGING_ROOTS.any? do |root|
    path == root || path.start_with?("#{root}/")
  end
end

def devlane_pending_material_errors(provenance, components, material_state)
  decision_status = nested_value(components, [DEVLANE_CANDIDATE_NAME, "decision", "status"])
  distribution_approved = nested_value(provenance, ["proposed_import", "approved_source_distribution"])
  imported = nested_value(provenance, ["import", "imported"])
  barrier_active = decision_status != "APPROVED" || distribution_approved != true || imported != true
  return [] unless barrier_active

  errors = Array(material_state[:inventory_errors]).map do |error|
    "Devlane pending-source inventory could not be verified: #{error}"
  end
  Array(material_state[:pending_build_graph_errors]).each do |error|
    errors << "Devlane pending build graph: #{error}"
  end
  Array(material_state[:present_destinations]).each do |path|
    errors << "Devlane pending-source gate: proposed destination #{path} must be absent before approval, distribution, and import are all recorded"
  end
  Array(material_state[:destination_entries]).each do |path|
    errors << "Devlane pending-source gate: governed destination root must contain no source before approval/import; found #{path}"
  end
  Array(material_state[:staging_entries]).each do |path|
    errors << "Devlane pending-source gate: governed staging root must be empty; found #{path}"
  end
  Array(material_state[:pinned_source_copies]).each do |path|
    if devlane_allowlisted_source_path?(path)
      errors << "Devlane pending-source gate: byte-identical pinned source is present before approval/import at #{path}"
    else
      errors << "Devlane pending-source gate: byte-identical pinned source at #{path} is outside the closed import-location allowlist"
    end
  end
  errors
end

def devlane_security_gate_errors(provenance, components, notices, material_state, release_mode:)
  raise ArgumentError, "release_mode must be boolean" unless [true, false].include?(release_mode)

  (
    devlane_candidate_errors(provenance, components) +
    devlane_pending_material_errors(provenance, components, material_state) +
    devlane_notice_errors(notices, provenance)
  ).uniq
end

def devlane_candidate_errors(provenance, components)
  errors = []
  unless provenance.is_a?(Hash)
    return ["devlane-provenance.yaml: document must be a mapping"]
  end

  import = provenance["proposed_import"]
  unless import.is_a?(Hash)
    return ["devlane-provenance.yaml: proposed_import must be a mapping"]
  end

  record = components[DEVLANE_CANDIDATE_NAME]
  unless record.is_a?(Hash)
    return ["dependency registry: missing Devlane primitive import candidate"]
  end

  approval_state = EXPECTED_DEVLANE_PENDING_PROVENANCE_APPROVAL.keys.to_h do |field|
    [field, import[field]]
  end
  unless approval_state == EXPECTED_DEVLANE_PENDING_PROVENANCE_APPROVAL
    errors << "devlane-provenance.yaml: proposed import must remain at the exact pending approval state until a reviewed successor revision is recorded"
  end

  unless record["decision"] == EXPECTED_DEVLANE_PENDING_DECISION
    errors << "#{DEVLANE_CANDIDATE_NAME}: decision must remain at the exact pending state until a reviewed successor revision is recorded"
  end

  unless provenance.dig("import", "governed_source_location_allowlist") == DEVLANE_SOURCE_LOCATION_ALLOWLIST
    errors << "devlane-provenance.yaml: governed source locations must remain the exact closed staging/destination allowlist"
  end
  unless provenance.dig("import", "pending_build_graph") == DEVLANE_PENDING_BUILD_GRAPH
    errors << "devlane-provenance.yaml: pending frontend source/module/build graph must remain exact and closed"
  end

  errors.concat(devlane_license_binding_errors(provenance))
  recorded_fingerprints = Array(import["source_files"]).filter_map do |entry|
    [entry["size_bytes"], entry["sha256"]] if entry.is_a?(Hash)
  end.to_h
  unless recorded_fingerprints == DEVLANE_PINNED_SOURCE_FINGERPRINTS
    errors << "devlane-provenance.yaml: pinned source size/SHA-256 inventory differs from the exact repository-copy fingerprints"
  end

  provenance_surface = Marshal.load(Marshal.dump(provenance))
  EXPECTED_DEVLANE_PENDING_PROVENANCE_APPROVAL.each_key do |field|
    provenance_surface.fetch("proposed_import").delete(field)
  end
  unless canonical_sha256(provenance_surface) == DEVLANE_PROVENANCE_SURFACE_SHA256
    errors << "devlane-provenance.yaml: immutable candidate surface differs from the reviewed proposal"
  end

  registry_surface = Marshal.load(Marshal.dump(record))
  %w[status approvers approved_at].each { |field| registry_surface.fetch("decision", {}).delete(field) }
  unless canonical_sha256(registry_surface) == DEVLANE_REGISTRY_SURFACE_SHA256
    errors << "#{DEVLANE_CANDIDATE_NAME}: immutable registry surface differs from the reviewed proposal"
  end

  errors
end

def with_devlane_pending_build_graph_fixture
  Dir.mktmpdir("stead-devlane-pending-graph-") do |fixture_root|
    DEVLANE_PENDING_BUILD_GRAPH_FILES.each do |entry|
      relative = entry.fetch("path")
      destination = File.join(fixture_root, relative)
      FileUtils.mkdir_p(File.dirname(destination))
      FileUtils.cp(File.join(ROOT, relative), destination)
    end
    yield fixture_root
  end
end

def run_validator_self_tests
  guard_count = 7
  pending_go = {
    "component" => {
      "name" => "example.com/db", "kind" => "go_module", "ecosystem" => "go", "version" => "v1.2.3",
      "digest" => { "algorithm" => "go-h1", "value" => "h1:#{'a' * 43}=" },
      "module_file_digest" => { "algorithm" => "go-h1", "value" => "h1:#{'b' * 43}=" }
    },
    "decision" => { "status" => "REVIEWED_PENDING_INDEPENDENT_APPROVAL" }
  }
  pending_oci = {
    "component" => {
      "name" => "postgres", "kind" => "oci_image", "ecosystem" => "oci", "version" => "16-bookworm",
      "digest" => { "algorithm" => "sha256", "value" => "sha256:#{'a' * 64}" }
    },
    "decision" => { "status" => "REVIEWED_PENDING_INDEPENDENT_APPROVAL" }
  }
  components = { "example.com/db" => pending_go, "postgres" => pending_oci }
  failures = []

  missing_errors = []
  validate_go_dependencies("module fixture\nrequire example.com/db v1.2.3\n", "", components, missing_errors, mod_label: "missing.mod", sum_label: "missing.sum")
  failures << "missing Go sum mutation was accepted" unless missing_errors.any? { |error| error.include?("missing module checksum") } && missing_errors.any? { |error| error.include?("missing go.mod checksum") }

  wrong_errors = []
  wrong_sum = "example.com/db v1.2.3 h1:#{'c' * 43}=\nexample.com/db v1.2.3/go.mod h1:#{'d' * 43}=\n"
  validate_go_dependencies("module fixture\nrequire example.com/db v1.2.3\n", wrong_sum, components, wrong_errors, mod_label: "wrong.mod", sum_label: "wrong.sum")
  failures << "wrong Go sum mutation was accepted" unless wrong_errors.any? { |error| error.include?("registry module checksum differs") } && wrong_errors.any? { |error| error.include?("registry go.mod checksum differs") }

  approval_errors = release_approval_errors(Set.new(["example.com/db"]), components, ["APPROVED"])
  failures << "unapproved active Go module mutation was accepted" unless approval_errors.any? { |error| error.include?("not independently approved") }

  replacement_errors = []
  go_requirements("module fixture\nreplace example.com/db => ./unreviewed\n", replacement_errors, "replace.mod")
  failures << "Go replace mutation was accepted" unless replacement_errors.any? { |error| error.include?("replace directives are prohibited") }

  indirect_errors = []
  validate_go_dependencies(
    "module fixture\nrequire example.com/transitive v1.0.0 // indirect\n",
    "example.com/transitive v1.0.0 h1:#{'e' * 43}=\nexample.com/transitive v1.0.0/go.mod h1:#{'f' * 43}=\n",
    components,
    indirect_errors,
    mod_label: "indirect.mod",
    sum_label: "indirect.sum"
  )
  failures << "unreviewed indirect Go module mutation was accepted" unless indirect_errors.any? { |error| error.include?("outside every reviewed runtime closure") }

  unpinned_errors = []
  validate_oci_workflow_images({ "unpinned.yml" => "services:\n  db:\n    image: postgres:16-bookworm\n" }, components, unpinned_errors)
  failures << "unpinned OCI image mutation was accepted" unless unpinned_errors.any? { |error| error.include?("not pinned") }

  wrong_oci_errors = []
  validate_oci_workflow_images({ "wrong.yml" => "container:\n  image: postgres:16-bookworm@sha256:#{'b' * 64}\n" }, components, wrong_oci_errors)
  failures << "wrong OCI digest mutation was accepted" unless wrong_oci_errors.any? { |error| error.include?("digest differs") }

  rejected_go = Marshal.load(Marshal.dump(pending_go))
  rejected_go["component"]["name"] = "example.com/rejected-db"
  rejected_go["decision"] = {
    "status" => "REJECTED", "approvers" => [], "approved_at" => nil,
    "reason_codes" => ["REACHABLE_KNOWN_VULNERABILITY"], "evidence_refs" => ["evidence/rejected-db"]
  }
  rejected_oci = Marshal.load(Marshal.dump(pending_oci))
  rejected_oci["component"]["name"] = "rejected-postgres"
  rejected_oci["decision"] = {
    "status" => "REJECTED", "approvers" => [], "approved_at" => nil,
    "reason_codes" => ["UNRESOLVED_CRITICAL_HIGH_FINDINGS"], "evidence_refs" => ["evidence/rejected-postgres"]
  }
  rejected_components = {
    "example.com/rejected-db" => rejected_go,
    "rejected-postgres" => rejected_oci
  }
  rejected_go_activation_errors = []
  rejected_go_sum = "example.com/rejected-db v1.2.3 h1:#{'a' * 43}=\nexample.com/rejected-db v1.2.3/go.mod h1:#{'b' * 43}=\n"
  validate_go_dependencies(
    "module fixture\nrequire example.com/rejected-db v1.2.3\n",
    rejected_go_sum,
    rejected_components,
    rejected_go_activation_errors,
    mod_label: "rejected.mod",
    sum_label: "rejected.sum"
  )
  failures << "rejected Go module activation mutation was accepted" unless rejected_go_activation_errors.any? { |error| error.include?("not approved for use") }

  rejected_oci_activation_errors = []
  rejected_oci_source = "services:\n  db:\n    image: rejected-postgres:16-bookworm@sha256:#{'a' * 64}\n"
  validate_oci_workflow_images({ "rejected.yml" => rejected_oci_source }, rejected_components, rejected_oci_activation_errors)
  failures << "rejected OCI image activation mutation was accepted" unless rejected_oci_activation_errors.any? { |error| error.include?("not approved for use") }
  guard_count += 2

  rejected_release_errors = release_approval_errors(Set.new(rejected_components.keys), rejected_components, ["APPROVED"])
  failures << "rejected Go module mutation became release eligible" unless rejected_release_errors.any? { |error| error.start_with?("example.com/rejected-db:") }
  failures << "rejected OCI image mutation became release eligible" unless rejected_release_errors.any? { |error| error.start_with?("rejected-postgres:") }
  guard_count += 2

  rejected_with_approval = Marshal.load(Marshal.dump(rejected_go))
  rejected_with_approval["decision"]["approvers"] = ["self-approval"]
  rejected_with_approval["decision"]["approved_at"] = "2026-08-30T21:35:54Z"
  approval_metadata_errors = decision_state_errors(rejected_with_approval)
  unless approval_metadata_errors.any? { |error| error.include?("must not name approvers") } &&
         approval_metadata_errors.any? { |error| error.include?("must not have approved_at") }
    failures << "rejected candidate approval metadata mutation was accepted"
  end
  guard_count += 1

  registry_fixture = load_yaml(REGISTRY_PATH)
  registry_components = registry_fixture.fetch("records").to_h { |record| [record.dig("component", "name"), record] }
  provenance_fixture = load_yaml(PROVENANCE_PATH)
  provenance_source = File.read(PROVENANCE_PATH)
  registry_source = File.read(REGISTRY_PATH)
  provenance_inline_merge = provenance_source.sub(
    "proposed_import:\n",
    "proposed_import:\n  <<: {status: APPROVED, approved_source_distribution: true, approvers: [attacker-one, attacker-two], approved_at: \"2026-08-30T23:59:59Z\", scope_version: attacker-expanded}\n"
  )
  provenance_sequence_merge = provenance_source.sub(
    "proposed_import:\n",
    "proposed_import:\n  <<: [{status: APPROVED}, {scope_version: attacker-expanded}]\n"
  )
  registry_inline_merge = registry_source.sub(
    "    decision: { category: ALLOW-PERMISSIVE, status: REVIEWED_PENDING_INDEPENDENT_APPROVAL, independent_approval_required: true, approvers: [], approved_at: null }\n",
    "    decision:\n      <<: {status: APPROVED, approvers: [attacker-one, attacker-two], approved_at: \"2026-08-30T23:59:59Z\"}\n      category: ALLOW-PERMISSIVE\n      status: REVIEWED_PENDING_INDEPENDENT_APPROVAL\n      independent_approval_required: true\n      approvers: []\n      approved_at: null\n"
  )
  raw_yaml_mutations = {
    "provenance duplicate approval status" => provenance_source.sub(
      "  status: REVIEWED_PENDING_INDEPENDENT_APPROVAL\n",
      "  status: APPROVED\n  status: REVIEWED_PENDING_INDEPENDENT_APPROVAL\n"
    ),
    "provenance duplicate scope" => provenance_source.sub(
      "  scope_version: stead-primitives-v1\n",
      "  scope_version: expanded-scope\n  scope_version: stead-primitives-v1\n"
    ),
    "registry duplicate approval ID" => registry_source.sub(
      "  - approval_id: DEP-APP-DEVLANE-STEAD-PRIMITIVES-7719DCAD\n",
      "  - approval_id: DEP-APP-MALICIOUS\n    approval_id: DEP-APP-DEVLANE-STEAD-PRIMITIVES-7719DCAD\n"
    ),
    "provenance trailing document" => "#{provenance_source}\n---\nstatus: APPROVED\napproved_source_distribution: true\n",
    "registry trailing document" => "#{registry_source}\n---\ndecision:\n  status: APPROVED\n  approvers: [arbitrary-one, arbitrary-two]\n",
    "provenance inline mapping merge" => provenance_inline_merge,
    "provenance inline sequence merge" => provenance_sequence_merge,
    "registry inline mapping merge" => registry_inline_merge
  }
  raw_yaml_mutation_survivors = raw_yaml_mutations.filter_map do |label, mutated_source|
    guard_count += 1
    label if strict_yaml_structure_errors(mutated_source, filename: "#{label}.yaml").empty?
  end
  unless raw_yaml_mutation_survivors.empty?
    failures << "strict YAML parser mutation survivors: #{raw_yaml_mutation_survivors.join(', ')}"
  end

  coupled_merge_survives =
    strict_yaml_structure_errors(provenance_inline_merge, filename: "coupled provenance merge.yaml").empty? &&
    strict_yaml_structure_errors(registry_inline_merge, filename: "coupled registry merge.yaml").empty?
  failures << "coupled provenance and registry YAML merge-key mutation survived" if coupled_merge_survives
  guard_count += 1

  reordered_mapping_a = { "second" => { "beta" => 2, "alpha" => 1 }, "first" => true }
  reordered_mapping_b = { "first" => true, "second" => { "alpha" => 1, "beta" => 2 } }
  unless canonical_sha256(reordered_mapping_a) == canonical_sha256(reordered_mapping_b)
    failures << "canonical candidate digest changed under mapping-key reorder"
  end
  guard_count += 1

  baseline_devlane_errors = devlane_candidate_errors(provenance_fixture, registry_components)
  unless baseline_devlane_errors.empty?
    failures << "Devlane self-test fixture does not match the exact pending candidate: #{baseline_devlane_errors.join('; ')}"
  end

  devlane_mutations = {
    "fabricated approval metadata" => lambda do |provenance_copy, components_copy|
      decision = components_copy.fetch(DEVLANE_CANDIDATE_NAME).fetch("decision")
      decision["status"] = "APPROVED"
      decision["approvers"] = ["arbitrary-reviewer-one", "arbitrary-reviewer-two"]
      decision["approved_at"] = "2026-08-30T23:59:59Z"
      import = provenance_copy.fetch("proposed_import")
      import["status"] = "APPROVED"
      import["approvers"] = decision["approvers"]
      import["approved_at"] = decision["approved_at"]
      import["approved_source_distribution"] = true
    end,
    "source URL" => lambda do |_provenance_copy, components_copy|
      components_copy.fetch(DEVLANE_CANDIDATE_NAME).fetch("component")["source_url"] = "https://example.invalid/fork"
    end,
    "source version" => lambda do |_provenance_copy, components_copy|
      components_copy.fetch(DEVLANE_CANDIDATE_NAME).fetch("component")["version"] = "unreviewed-version"
    end,
    "source digest" => lambda do |_provenance_copy, components_copy|
      components_copy.fetch(DEVLANE_CANDIDATE_NAME).dig("component", "digest")["value"] = "0" * 40
    end,
    "scope version" => lambda do |provenance_copy, _components_copy|
      provenance_copy.fetch("proposed_import")["scope_version"] = "expanded-scope"
    end,
    "excluded dependencies emptied" => lambda do |provenance_copy, _components_copy|
      provenance_copy.fetch("proposed_import")["excluded_source_dependencies"] = []
    end,
    "excluded areas emptied" => lambda do |provenance_copy, _components_copy|
      provenance_copy.fetch("proposed_import")["excluded_source_areas"] = []
    end,
    "review obligations emptied" => lambda do |provenance_copy, _components_copy|
      provenance_copy.fetch("proposed_import")["review_obligations"] = []
    end,
    "notice obligations emptied" => lambda do |_provenance_copy, components_copy|
      components_copy.fetch(DEVLANE_CANDIDATE_NAME).fetch("obligations")["notices"] = []
    end,
    "modification widened" => lambda do |provenance_copy, _components_copy|
      provenance_copy.dig("proposed_import", "source_files", 0)["modification"] = "Import all source behavior unchanged."
    end,
    "non-mapping source appended" => lambda do |provenance_copy, _components_copy|
      provenance_copy.dig("proposed_import", "source_files") << "unreviewed-source"
    end,
    "top-level field appended" => lambda do |provenance_copy, _components_copy|
      provenance_copy["approval_override"] = true
    end,
    "registry constraint deleted" => lambda do |_provenance_copy, components_copy|
      components_copy.fetch(DEVLANE_CANDIDATE_NAME).fetch("security").delete("permissions_and_network")
    end,
    "distribution flag changed alone" => lambda do |provenance_copy, _components_copy|
      provenance_copy.fetch("proposed_import")["approved_source_distribution"] = true
    end,
    "pending build graph deleted" => lambda do |provenance_copy, _components_copy|
      provenance_copy.fetch("import").delete("pending_build_graph")
    end,
    "pending build graph digest changed" => lambda do |provenance_copy, _components_copy|
      provenance_copy.dig("import", "pending_build_graph", "files", 0)["sha256"] = "0" * 64
    end,
    "pending build graph path appended" => lambda do |provenance_copy, _components_copy|
      provenance_copy.dig("import", "pending_build_graph", "files") << {
        "path" => "apps/web/src/unreviewed.tsx",
        "type" => "regular_file",
        "sha256" => "0" * 64
      }
    end,
    "pending build graph generated root widened" => lambda do |provenance_copy, _components_copy|
      provenance_copy.dig("import", "pending_build_graph", "generated_roots") << "apps/web/src"
    end
  }
  devlane_mutation_survivors = []
  devlane_mutations.each do |label, mutation|
    mutated_provenance = Marshal.load(Marshal.dump(provenance_fixture))
    mutated_components = Marshal.load(Marshal.dump(registry_components))
    mutation.call(mutated_provenance, mutated_components)
    if devlane_candidate_errors(mutated_provenance, mutated_components).empty?
      devlane_mutation_survivors << label
    end
    guard_count += 1
  end
  unless devlane_mutation_survivors.empty?
    failures << "Devlane candidate mutation survivors: #{devlane_mutation_survivors.join(', ')}"
  end

  notices_fixture = File.read(NOTICES_PATH)
  empty_material_state = {
    present_destinations: [],
    destination_entries: [],
    staging_entries: [],
    pinned_source_copies: [],
    inventory_errors: [],
    pending_build_graph_errors: []
  }
  { "normal" => false, "release" => true }.each do |mode_label, release_mode|
    DEVLANE_PROPOSED_DESTINATION_PATHS.each do |destination|
      material_state = empty_material_state.merge(present_destinations: [destination])
      mutation_errors = devlane_security_gate_errors(
        provenance_fixture,
        registry_components,
        notices_fixture,
        material_state,
        release_mode: release_mode
      )
      unless mutation_errors.any? { |error| error.include?("proposed destination #{destination} must be absent") }
        failures << "#{mode_label} Devlane gate accepted pre-approval destination presence at #{destination}"
      end
      guard_count += 1
    end

    staging_path = "#{DEVLANE_GOVERNED_STAGING_ROOTS.fetch(0)}/copied-source.tsx"
    staging_errors = devlane_security_gate_errors(
      provenance_fixture,
      registry_components,
      notices_fixture,
      empty_material_state.merge(staging_entries: [staging_path]),
      release_mode: release_mode
    )
    unless staging_errors.any? { |error| error.include?("governed staging root must be empty") }
      failures << "#{mode_label} Devlane gate accepted content under a governed staging root"
    end
    guard_count += 1

    alternate_path = "unreviewed-import/devlane/Button.tsx"
    copied_source_errors = devlane_security_gate_errors(
      provenance_fixture,
      registry_components,
      notices_fixture,
      empty_material_state.merge(pinned_source_copies: [alternate_path]),
      release_mode: release_mode
    )
    unless copied_source_errors.any? { |error| error.include?("outside the closed import-location allowlist") }
      failures << "#{mode_label} Devlane gate accepted a byte-identical pinned source copy at an alternate location"
    end
    guard_count += 1

    alternate_destination = "#{DEVLANE_GOVERNED_DESTINATION_ROOTS.fetch(0)}/alternate-primitives.tsx"
    destination_errors = devlane_security_gate_errors(
      provenance_fixture,
      registry_components,
      notices_fixture,
      empty_material_state.merge(destination_entries: [alternate_destination]),
      release_mode: release_mode
    )
    unless destination_errors.any? { |error| error.include?("governed destination root must contain no source") }
      failures << "#{mode_label} Devlane gate accepted an alternate file under the governed destination root"
    end
    guard_count += 1
  end

  with_devlane_pending_build_graph_fixture do |fixture_root|
    FileUtils.mkdir_p(File.join(fixture_root, "apps/web/node_modules/example"))
    File.binwrite(File.join(fixture_root, "apps/web/node_modules/example/index.js"), "dependency")
    graph_errors = devlane_repository_material_state(fixture_root).fetch(:pending_build_graph_errors)
    failures << "exact pending build graph fixture did not validate: #{graph_errors.join('; ')}" unless graph_errors.empty?
    guard_count += 1
  end

  pending_material_mutations = {
    "rendered adapted Button" => {
      expected: [
        "BUILD_GRAPH_DIGEST apps/web/src/Foundation.tsx",
        "BUILD_GRAPH_UNEXPECTED apps/web/src/DevlaneButton.tsx"
      ],
      mutate: lambda do |fixture_root|
        button_path = File.join(fixture_root, "apps/web/src/DevlaneButton.tsx")
        File.binwrite(
          button_path,
          <<~TSX
            import { forwardRef, type ButtonHTMLAttributes } from "react";
            export const DevlaneButton = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement>>(
              ({ children, ...props }, ref) => <button ref={ref} {...props}>{children}</button>,
            );
          TSX
        )
        foundation_path = File.join(fixture_root, "apps/web/src/Foundation.tsx")
        source = File.binread(foundation_path)
        File.binwrite(
          foundation_path,
          "import { DevlaneButton } from \"./DevlaneButton\";\n" +
            source.sub("</main>", "  <DevlaneButton>Hidden pre-approval import</DevlaneButton>\n    </main>")
        )
      end
    },
    "alternate source symlink imported by CSS" => {
      expected: [
        "BUILD_GRAPH_DIGEST apps/web/src/styles.css",
        "BUILD_GRAPH_UNEXPECTED apps/web/src/devlane-tokens.css: link"
      ],
      mutate: lambda do |fixture_root|
        upstream_fixture = File.join(fixture_root, "pinned-devlane-tokens.css")
        File.binwrite(upstream_fixture, "/* exact pinned source fixture boundary */\n")
        File.symlink(upstream_fixture, File.join(fixture_root, "apps/web/src/devlane-tokens.css"))
        styles_path = File.join(fixture_root, "apps/web/src/styles.css")
        File.binwrite(styles_path, "@import \"./devlane-tokens.css\";\n" + File.binread(styles_path))
      end
    },
    "approved graph file replaced by symlink" => {
      expected: ["BUILD_GRAPH_FILE_TYPE apps/web/src/Foundation.tsx: link"],
      mutate: lambda do |fixture_root|
        foundation_path = File.join(fixture_root, "apps/web/src/Foundation.tsx")
        replacement = File.join(fixture_root, "foundation-target.tsx")
        FileUtils.mv(foundation_path, replacement)
        File.symlink(replacement, foundation_path)
      end
    },
    "frontend source directory replaced by symlink" => {
      expected: [
        "BUILD_GRAPH_PARENT_TYPE apps/web/src/Foundation.tsx",
        "BUILD_GRAPH_UNEXPECTED apps/web/src: link"
      ],
      mutate: lambda do |fixture_root|
        source_path = File.join(fixture_root, "apps/web/src")
        replacement = File.join(fixture_root, "escaped-src")
        FileUtils.mv(source_path, replacement)
        File.symlink(replacement, source_path)
      end
    },
    "unreviewed Vite configuration" => {
      expected: ["BUILD_GRAPH_UNEXPECTED apps/web/vite.config.ts"],
      mutate: lambda do |fixture_root|
        File.binwrite(File.join(fixture_root, "apps/web/vite.config.ts"), "export default {};\n")
      end
    },
    "unreviewed public asset" => {
      expected: ["BUILD_GRAPH_UNEXPECTED apps/web/public/devlane.svg"],
      mutate: lambda do |fixture_root|
        FileUtils.mkdir_p(File.join(fixture_root, "apps/web/public"))
        File.binwrite(File.join(fixture_root, "apps/web/public/devlane.svg"), "<svg/>\n")
      end
    },
    "additional frontend test module" => {
      expected: ["BUILD_GRAPH_UNEXPECTED apps/web/src/hidden.test.tsx"],
      mutate: lambda do |fixture_root|
        File.binwrite(File.join(fixture_root, "apps/web/src/hidden.test.tsx"), "throw new Error(\"unreviewed test\");\n")
      end
    },
    "additional hard-linked frontend module" => {
      expected: ["BUILD_GRAPH_UNEXPECTED apps/web/src/HiddenFoundation.tsx"],
      mutate: lambda do |fixture_root|
        File.link(
          File.join(fixture_root, "apps/web/src/Foundation.tsx"),
          File.join(fixture_root, "apps/web/src/HiddenFoundation.tsx")
        )
      end
    },
    "alternate governed destination file" => {
      expected: ["governed destination root must contain no source"],
      mutate: lambda do |fixture_root|
        destination = File.join(fixture_root, "packages/design-system/src/alternate-primitives.tsx")
        FileUtils.mkdir_p(File.dirname(destination))
        File.binwrite(destination, "export const hidden = true;\n")
      end
    },
    "build control content changed" => {
      expected: ["BUILD_GRAPH_DIGEST package.json"],
      mutate: lambda do |fixture_root|
        package_path = File.join(fixture_root, "package.json")
        File.binwrite(package_path, File.binread(package_path) + "\n")
      end
    },
    "unreviewed build output file" => {
      expected: ["BUILD_GRAPH_OUTPUT_UNEXPECTED apps/web/dist/assets/hidden.js"],
      mutate: lambda do |fixture_root|
        output = File.join(fixture_root, "apps/web/dist/assets/hidden.js")
        FileUtils.mkdir_p(File.dirname(output))
        File.binwrite(output, "unreviewed output\n")
      end
    },
    "verified output root replaced by symlink" => {
      expected: ["BUILD_GRAPH_OUTPUT_ROOT_TYPE apps/web/dist: link"],
      mutate: lambda do |fixture_root|
        external_output = File.join(fixture_root, "external-dist")
        FileUtils.mkdir_p(external_output)
        File.symlink(external_output, File.join(fixture_root, "apps/web/dist"))
      end
    }
  }
  { "normal" => false, "release" => true }.each do |mode_label, release_mode|
    pending_material_mutations.each do |mutation_label, scenario|
      with_devlane_pending_build_graph_fixture do |fixture_root|
        scenario.fetch(:mutate).call(fixture_root)
        material_state = devlane_repository_material_state(fixture_root)
        mutation_errors = devlane_security_gate_errors(
          provenance_fixture,
          registry_components,
          notices_fixture,
          material_state,
          release_mode: release_mode
        )
        missing = scenario.fetch(:expected).reject do |fragment|
          mutation_errors.any? { |error| error.include?(fragment) }
        end
        unless missing.empty?
          failures << "#{mode_label} Devlane pending graph accepted #{mutation_label}; missing #{missing.join(', ')}"
        end
      end
      guard_count += 1
    end
  end

  devlane_notice_mutations = {
    "one-byte copyright corruption" => notices_fixture.sub("Copyright (c) 2026 Devlane", "Copyright (c) 2027 Devlane"),
    "deleted MIT retention clause" => notices_fixture.sub(
      "The above copyright notice and this permission notice shall be included in all\n" \
      "copies or substantial portions of the Software.\n",
      ""
    ),
    "substituted license clause" => notices_fixture.sub(
      "Permission is hereby granted, free of charge, to any person obtaining a copy",
      "Permission is granted only after separate written authorization"
    )
  }
  { "normal" => false, "release" => true }.each do |mode_label, release_mode|
    devlane_notice_mutations.each do |mutation_label, mutated_notices|
      mutation_errors = devlane_security_gate_errors(
        provenance_fixture,
        registry_components,
        mutated_notices,
        empty_material_state,
        release_mode: release_mode
      )
      unless mutation_errors.any? { |error| error.include?("NOTICE-DEVLANE-MIT body must exactly preserve") }
        failures << "#{mode_label} Devlane gate accepted #{mutation_label}"
      end
      guard_count += 1
    end
  end

  decision_mutation_survivors = []
  EXPECTED_REJECTED_DECISIONS.each do |name, expected_decision|
    expected_decision.each_key do |field|
      mutated_components = Marshal.load(Marshal.dump(registry_components))
      mutated_components.fetch(name).fetch("decision").delete(field)
      decision_mutation_survivors << "#{name}.decision.#{field}" if exact_rejected_candidate_errors(mutated_components).empty?
      guard_count += 1
    end
  end
  failures << "exact rejected-decision mutation survivors: #{decision_mutation_survivors.join(', ')}" unless decision_mutation_survivors.empty?

  softened_decision_mutations = [
    ["github.com/jackc/pgx/v5", "status", "APPROVED"],
    ["github.com/jackc/pgx/v5", "reason_codes", ["RISK_ACCEPTED"]],
    ["postgres", "category", "REVIEW-NONRUNTIME"],
    ["postgres", "reason_codes", ["SCAN_REVIEWED"]]
  ]
  softened_decision_survivors = []
  softened_decision_mutations.each do |name, field, replacement|
    mutated_components = Marshal.load(Marshal.dump(registry_components))
    mutated_components.fetch(name).fetch("decision")[field] = replacement
    softened_decision_survivors << "#{name}.decision.#{field}" if exact_rejected_candidate_errors(mutated_components).empty?
    guard_count += 1
  end
  failures << "rejected decision softening mutation survivors: #{softened_decision_survivors.join(', ')}" unless softened_decision_survivors.empty?

  notice_obligation_mutations = {
    "notices empty" => lambda { |record| record.fetch("obligations")["notices"] = [] },
    "notices removed" => lambda { |record| record.fetch("obligations").delete("notices") },
    "notice ID changed" => lambda { |record| record.fetch("obligations").fetch("notices")[0] = "NOTICE-APPROVED-STYLE" },
    "quarantine binding removed" => lambda { |record| record.fetch("obligations").delete("notice_quarantine") },
    "quarantine marker changed" => lambda do |record|
      record.fetch("obligations").fetch("notice_quarantine")["marker"] = "APPROVED-NOTICE-INPUT"
    end
  }
  notice_obligation_survivors = []
  notice_obligation_mutations.each do |label, mutation|
    mutated_components = Marshal.load(Marshal.dump(registry_components))
    mutation.call(mutated_components.fetch("github.com/jackc/pgx/v5"))
    notice_obligation_survivors << label if exact_rejected_candidate_errors(mutated_components).empty?
    guard_count += 1
  end
  unless notice_obligation_survivors.empty?
    failures << "rejected notice-obligation mutation survivors: #{notice_obligation_survivors.join(', ')}"
  end

  softened_license_components = Marshal.load(Marshal.dump(registry_components))
  softened_license_components.fetch("postgres").fetch("component")["license_expression"] = "MIT"
  if exact_rejected_candidate_errors(softened_license_components).empty?
    failures << "rejected OCI license softening mutation was accepted"
  end
  guard_count += 1

  evidence_fixture = load_yaml(POSTGRESQL_EVIDENCE_PATH)
  evidence_mutation_survivors = []
  EXPECTED_POSTGRESQL_REJECTION_EVIDENCE.each_key do |path|
    mutated_evidence = Marshal.load(Marshal.dump(evidence_fixture))
    delete_nested_key!(mutated_evidence, path)
    evidence_mutation_survivors << path.join(".") if postgresql_rejection_evidence_errors(mutated_evidence).empty?
    guard_count += 1
  end
  failures << "rejected evidence deletion mutation survivors: #{evidence_mutation_survivors.join(', ')}" unless evidence_mutation_survivors.empty?

  softened_evidence_mutations = {
    ["independent_review", "release_eligible"] => true,
    ["go_candidate", "notice_id"] => "NOTICE-PGPASSFILE-MIT",
    ["go_candidate", "vulnerability_scan", "status"] => "PASS",
    ["go_candidate", "possible_successor", "status"] => "APPROVED",
    ["oci_candidate", "vulnerability_scan", "status"] => "PASS",
    ["oci_candidate", "signature_attestation_review", "status"] => "VERIFIED"
  }
  softened_evidence_survivors = []
  softened_evidence_mutations.each do |path, replacement|
    mutated_evidence = Marshal.load(Marshal.dump(evidence_fixture))
    parent = path[0...-1].reduce(mutated_evidence) { |cursor, key| cursor.fetch(key) }
    parent[path.last] = replacement
    softened_evidence_survivors << path.join(".") if postgresql_rejection_evidence_errors(mutated_evidence).empty?
    guard_count += 1
  end
  failures << "rejected evidence softening mutation survivors: #{softened_evidence_survivors.join(', ')}" unless softened_evidence_survivors.empty?

  closure_notice_survivors = []
  closure = evidence_fixture.fetch("go_candidate").fetch("pgxpool_module_closure")
  closure.each_index do |index|
    module_name = closure.fetch(index).fetch("module")

    removed = Marshal.load(Marshal.dump(evidence_fixture))
    removed.dig("go_candidate", "pgxpool_module_closure", index).delete("notice_id")
    if postgresql_rejection_evidence_errors(removed).empty?
      closure_notice_survivors << "#{module_name}.notice_id removed"
    end
    guard_count += 1

    changed = Marshal.load(Marshal.dump(evidence_fixture))
    changed.dig("go_candidate", "pgxpool_module_closure", index)["notice_id"] = "NOTICE-APPROVED-STYLE"
    if postgresql_rejection_evidence_errors(changed).empty?
      closure_notice_survivors << "#{module_name}.notice_id changed"
    end
    guard_count += 1

    relinked = Marshal.load(Marshal.dump(evidence_fixture))
    next_index = (index + 1) % closure.length
    relinked.dig("go_candidate", "pgxpool_module_closure", index)["notice_id"] = closure.fetch(next_index).fetch("notice_id")
    if postgresql_rejection_evidence_errors(relinked).empty?
      closure_notice_survivors << "#{module_name}.notice_id relinked"
    end
    guard_count += 1
  end
  unless closure_notice_survivors.empty?
    failures << "pgxpool closure notice-link mutation survivors: #{closure_notice_survivors.join(', ')}"
  end

  evidence_quarantine_mutations = {
    "marker removed" => lambda { |binding| binding.delete("marker") },
    "marker approved-style relabel" => lambda { |binding| binding["marker"] = "APPROVED-NOTICE-INPUT" },
    "section heading removed" => lambda { |binding| binding.delete("section_heading") },
    "framing removed" => lambda { |binding| binding.delete("framing") },
    "release input softened" => lambda { |binding| binding["release_notice_input"] = true }
  }
  evidence_quarantine_survivors = []
  evidence_quarantine_mutations.each do |label, mutation|
    mutated_evidence = Marshal.load(Marshal.dump(evidence_fixture))
    mutation.call(mutated_evidence.dig("go_candidate", "notice_quarantine"))
    if postgresql_rejection_evidence_errors(mutated_evidence).empty?
      evidence_quarantine_survivors << label
    end
    guard_count += 1
  end
  unless evidence_quarantine_survivors.empty?
    failures << "evidence notice-quarantine mutation survivors: #{evidence_quarantine_survivors.join(', ')}"
  end

  source_mutations = {
    "begin marker removed" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_BEGIN, ""),
    "end marker removed" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_END, ""),
    "section heading removed" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_HEADING, ""),
    "framing removed" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_FRAMING, ""),
    "approved-style section relabel" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_HEADING, "## APPROVED — pgx v5.10.0 closure notices")
  }
  section_removed = notices_fixture.dup
  section_start = section_removed.index(PGX_NOTICE_QUARANTINE_BEGIN)
  section_end = section_removed.index(PGX_NOTICE_QUARANTINE_END) + PGX_NOTICE_QUARANTINE_END.length
  section_removed.slice!(section_start...section_end)
  source_mutations["quarantine section removed"] = section_removed

  REJECTED_PGX_NOTICE_IDS.each do |notice_id|
    range = notice_entry_range(notices_fixture, notice_id)
    if range.nil?
      failures << "self-test fixture cannot locate #{notice_id}"
      next
    end
    entry = notices_fixture[range]

    missing = notices_fixture.dup
    missing.slice!(range)
    source_mutations["#{notice_id} missing"] = missing

    duplicate = notices_fixture.dup
    duplicate.insert(range.end, entry)
    source_mutations["#{notice_id} duplicated"] = duplicate

    moved = notices_fixture.dup
    moved.slice!(range)
    moved.insert(moved.index(PGX_NOTICE_QUARANTINE_BEGIN), "#{entry}\n")
    source_mutations["#{notice_id} moved outside quarantine"] = moved
  end

  notice_source_survivors = source_mutations.filter_map do |label, mutated_source|
    guard_count += 1
    label if notice_quarantine_errors(mutated_source).empty?
  end
  unless notice_source_survivors.empty?
    failures << "THIRD_PARTY_NOTICES quarantine mutation survivors: #{notice_source_survivors.join(', ')}"
  end

  unless failures.empty?
    warn "dependency validator self-tests failed:"
    failures.each { |failure| warn "- #{failure}" }
    exit 1
  end
  puts "dependency validator self-tests passed: #{guard_count}/#{guard_count} mutation guards"
end

if ARGV.first == "--self-test"
  run_validator_self_tests
  exit 0
end

release_mode = ARGV.include?("--release")
registry = load_yaml(REGISTRY_PATH)
schema = JSON.parse(File.read(SCHEMA_PATH))
errors = schema_errors(registry, schema, schema)
records = registry.fetch("records", [])

ids = records.map { |record| record["approval_id"] }
errors << "dependency registry: approval_id values must be unique" unless ids.uniq.length == ids.length

components = records.to_h { |record| [record.dig("component", "name"), record] }
errors << "dependency registry: component names must be unique" unless components.length == records.length

records.each do |record|
  name = record.dig("component", "name")
  digest = record.dig("component", "digest", "value")
  algorithm = record.dig("component", "digest", "algorithm")
  rollback_version = record.dig("change", "rollback_version")

  case algorithm
  when "git-sha1"
    errors << "#{name}: invalid immutable Git commit" unless digest&.match?(/\A[0-9a-f]{40}\z/)
  when "sha256"
    errors << "#{name}: invalid SHA-256" unless digest&.match?(/\A(?:sha256:)?[0-9a-f]{64}\z/)
  when "sha512-sri"
    errors << "#{name}: invalid SHA-512 SRI" unless digest&.match?(/\Asha512-[A-Za-z0-9+\/=]+\z/)
  when "go-h1"
    errors << "#{name}: invalid Go h1 checksum" unless digest&.match?(GO_H1_DIGEST)
  end

  kind = record.dig("component", "kind")
  ecosystem = record.dig("component", "ecosystem")
  license_expression = record.dig("component", "license_expression")
  if license_expression&.match?(/\bNOASSERTION\b/i)
    errors << "#{name}: NOASSERTION license requires UNKNOWN category" unless record.dig("decision", "category") == "UNKNOWN"
    errors << "#{name}: NOASSERTION license must remain rejected" unless record.dig("decision", "status") == "REJECTED"
  end
  if kind == "go_module"
    errors << "#{name}: go_module must use the go ecosystem" unless ecosystem == "go"
    errors << "#{name}: go_module artifact checksum must use go-h1" unless algorithm == "go-h1"
    errors << "#{name}: go_module requires an exact Go version" unless record.dig("component", "version")&.match?(EXACT_GO_VERSION)
    module_file_digest = record.dig("component", "module_file_digest")
    unless module_file_digest&.dig("algorithm") == "go-h1" && module_file_digest&.dig("value")&.match?(GO_H1_DIGEST)
      errors << "#{name}: go_module requires an exact go-h1 module_file_digest"
    end
  elsif ecosystem == "go"
    errors << "#{name}: go ecosystem record must use go_module kind"
  end
  if kind == "oci_image"
    errors << "#{name}: oci_image must use the oci ecosystem" unless ecosystem == "oci"
    errors << "#{name}: oci_image digest must use sha256" unless algorithm == "sha256"
  elsif ecosystem == "oci"
    errors << "#{name}: oci ecosystem record must use oci_image kind"
  end

  errors.concat(decision_state_errors(record))

  errors << "#{name}: rollback target must be the immutable Phase 0 baseline" unless rollback_version == FOUNDATION_ROLLBACK_TARGET
end
errors.concat(exact_rejected_candidate_errors(components))

REQUIRED_PINS.each do |name, (version, digest)|
  record = components[name]
  if record.nil?
    errors << "dependency registry: missing required candidate #{name}"
    next
  end
  errors << "#{name}: expected version #{version}" unless record.dig("component", "version") == version
  errors << "#{name}: immutable digest does not match the reviewed candidate" unless record.dig("component", "digest", "value") == digest
end

provenance = load_yaml(PROVENANCE_PATH)
notices = File.read(NOTICES_PATH)
errors.concat(
  devlane_security_gate_errors(
    provenance,
    components,
    notices,
    devlane_repository_material_state,
    release_mode: release_mode
  )
)
expected_provenance = {
  ["status"] => "PINNED_SOURCE_NOT_IMPORTED",
  ["upstream", "repository"] => "https://github.com/Devlaner/devlane",
  ["upstream", "commit"] => "7719dcadf91f881b5aefe8b74012ffcfbba0bc17",
  ["upstream", "tree"] => "a568d1d11bab6012ffce1345193dcb537fa43556",
  ["upstream", "license", "blob"] => DEVLANE_LICENSE_BLOB_SHA1,
  ["upstream", "license", "sha256"] => DEVLANE_LICENSE_CONTENT_SHA256,
  ["upstream", "license", "size_bytes"] => DEVLANE_LICENSE_SIZE_BYTES,
  ["upstream", "license", "expression"] => "MIT",
  ["import", "imported"] => false
}
expected_provenance.each do |path, expected|
  actual = path.reduce(provenance) { |cursor, key| cursor.is_a?(Hash) ? cursor[key] : nil }
  errors << "devlane-provenance.yaml: #{path.join(".")} must equal #{expected.inspect}" unless actual == expected
end
errors << "devlane-provenance.yaml: imported_paths must be empty before import" unless provenance.dig("import", "imported_paths") == []
errors << "devlane-provenance.yaml: destination_paths must be empty before import" unless provenance.dig("import", "destination_paths") == []

devlane_import = provenance["proposed_import"]
expected_devlane_sources = {
  "apps/web/src/styles/tokens.css" => {
    "git_blob" => "36901af0c10553a8ad6d0860a58435912b274239",
    "sha256" => "870cd43b2af00ee047217ca72882343550fa0a862e0c86fb29771ae8aabcc7f2",
    "size_bytes" => 13_613,
    "destination_path" => "packages/design-system/src/tokens.css"
  },
  "apps/web/src/components/ui/Button.tsx" => {
    "git_blob" => "d0297e53de76f4a13d2b1b351cd33134824b842c",
    "sha256" => "7c5f4bb8d08a00dbafcf2e26023f2cbb238fea70b465a54b4fe349069983a0ae",
    "size_bytes" => 2_077,
    "destination_path" => "packages/design-system/src/primitives.tsx"
  },
  "apps/web/src/components/ui/Card.tsx" => {
    "git_blob" => "ff8e971a0e8f9030b2168bf02d6117a8ad544c7b",
    "sha256" => "e62355d412674de0fea7fde6a3ebf7aa2eeb57aa317fd2e2bf8bd61a6f14dd66",
    "size_bytes" => 1_328,
    "destination_path" => "packages/design-system/src/primitives.tsx"
  },
  "apps/web/src/components/ui/Badge.tsx" => {
    "git_blob" => "f4187e997315105f6b5337b4fd7a319b08caa315",
    "sha256" => "c709b3508c61ff8886c5859804d09a46b8d202b76ab68dda0ca31e3d07ff35bc",
    "size_bytes" => 978,
    "destination_path" => "packages/design-system/src/primitives.tsx"
  },
  "apps/web/src/components/ui/Input.tsx" => {
    "git_blob" => "22977a8cbfb24f155594564e076e86858c7cdb4e",
    "sha256" => "35eb3b4e8ce4562833c03099d28f86d8484dc63a487fd42f66493a418ebe46b4",
    "size_bytes" => 1_165,
    "destination_path" => "packages/design-system/src/primitives.tsx"
  },
  "apps/web/src/components/ui/Skeleton.tsx" => {
    "git_blob" => "cb274b88ee26d7c834cbc1e0a052e6f18f41fc8f",
    "sha256" => "8ba0dc9ca6e8a1243b433ea757b2aab3ef25d693a88fcb3560ca41601b2b066b",
    "size_bytes" => 249,
    "destination_path" => "packages/design-system/src/primitives.tsx"
  }
}.freeze

if !devlane_import.is_a?(Hash)
  errors << "devlane-provenance.yaml: proposed_import must be a mapping"
else
  import_record = components["devlane-stead-primitives"]
  errors << "dependency registry: missing Devlane primitive import candidate" unless import_record
  expected_import_fields = {
    "approval_id" => "DEP-APP-DEVLANE-STEAD-PRIMITIVES-7719DCAD",
    "scope_version" => "stead-primitives-v1",
    "proposed_destination_paths" => DEVLANE_PROPOSED_DESTINATION_PATHS
  }
  expected_import_fields.each do |field, expected|
    errors << "devlane-provenance.yaml: proposed_import.#{field} must equal #{expected.inspect}" unless devlane_import[field] == expected
  end

  source_files = Array(devlane_import["source_files"])
  source_paths = source_files.filter_map { |entry| entry["source_path"] if entry.is_a?(Hash) }
  errors << "devlane-provenance.yaml: proposed source paths must be unique" unless source_paths.uniq.length == source_paths.length
  errors << "devlane-provenance.yaml: exact proposed source set mismatch" unless source_paths.to_set == expected_devlane_sources.keys.to_set
  source_files.each do |entry|
    next unless entry.is_a?(Hash) && expected_devlane_sources.key?(entry["source_path"])

    expected_devlane_sources.fetch(entry["source_path"]).each do |field, expected|
      errors << "devlane-provenance.yaml: #{entry['source_path']}.#{field} must equal #{expected.inspect}" unless entry[field] == expected
    end
    errors << "devlane-provenance.yaml: #{entry['source_path']} requires a modification statement" unless entry["modification"].is_a?(String) && !entry["modification"].strip.empty?
  end

  if import_record
    decision = import_record.fetch("decision", {})
    errors << "devlane-provenance.yaml: proposed import status must match dependency decision" unless devlane_import["status"] == decision["status"]
    errors << "devlane-provenance.yaml: proposed import approvers must match dependency decision" unless devlane_import["approvers"] == decision["approvers"]
    errors << "devlane-provenance.yaml: proposed import approval time must match dependency decision" unless devlane_import["approved_at"] == decision["approved_at"]
    distribution_approved = decision["status"] == "APPROVED"
    errors << "devlane-provenance.yaml: approved_source_distribution must follow the exact decision status" unless devlane_import["approved_source_distribution"] == distribution_approved
  end
end

postgresql_evidence = load_yaml(POSTGRESQL_EVIDENCE_PATH)
expected_postgresql_evidence = {
  ["issue_id"] => "STEAD-P1-015",
  ["candidate_state"] => "REJECTED_QUARANTINED_NOT_INTEGRATED",
  ["go_candidate", "approval_id"] => "DEP-APP-GO-PGX-V5-5-10-0",
  ["go_candidate", "module"] => "github.com/jackc/pgx/v5",
  ["go_candidate", "version"] => "v5.10.0",
  ["go_candidate", "module_sum"] => "h1:VhSvgU2jSli8o3AqIEOTJr7rZwAEUVo4E4XhR94Zfr0=",
  ["go_candidate", "go_mod_sum"] => "h1:mal1tBGAFfLHvZzaYh77YS/eC6IX9OWbRV1QIIM0Jn4=",
  ["go_candidate", "upstream", "tag_commit"] => "7293fb11125be0373a92f716683f2d494f6fd4b0",
  ["oci_candidate", "approval_id"] => "DEP-APP-OCI-POSTGRES-16-BOOKWORM-BB3E1A57",
  ["oci_candidate", "reference"] => "postgres:16-bookworm",
  ["oci_candidate", "index_digest"] => "sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825",
  ["oci_candidate", "selected_platform", "manifest_digest"] => "sha256:1938c16e9d2f10a6a3623b344b64ae8d45f407f2c5f34f0979468bb689b9227a",
  ["oci_candidate", "selected_platform", "config_digest"] => "sha256:5f71c21b69a7977b82247582e2e731ed76bdebaadb7dd7945ed76bcc9ed06632",
  ["oci_candidate", "postgres_package_version"] => "16.15-1.pgdg12+2",
  ["oci_candidate", "created"] => "2026-08-25T00:42:19.848754437Z"
}
expected_postgresql_evidence.each do |path, expected|
  actual = path.reduce(postgresql_evidence) { |cursor, key| cursor.is_a?(Hash) ? cursor[key] : nil }
  errors << "dependency-evidence/stead-p1-015-postgresql.yaml: #{path.join(".")} must equal #{expected.inspect}" unless actual == expected
end

errors.concat(postgresql_rejection_evidence_errors(postgresql_evidence))

pgx_record = components["github.com/jackc/pgx/v5"]
if pgx_record
  errors << "github.com/jackc/pgx/v5: registry artifact checksum differs from intake evidence" unless pgx_record.dig("component", "digest", "value") == postgresql_evidence.dig("go_candidate", "module_sum")
  errors << "github.com/jackc/pgx/v5: registry go.mod checksum differs from intake evidence" unless pgx_record.dig("component", "module_file_digest", "value") == postgresql_evidence.dig("go_candidate", "go_mod_sum")
end
postgres_record = components["postgres"]
if postgres_record
  errors << "postgres: registry index digest differs from intake evidence" unless postgres_record.dig("component", "digest", "value") == postgresql_evidence.dig("oci_candidate", "index_digest")
end
lockfile = JSON.parse(File.read(LOCK_PATH))
errors << "package-lock.json: lockfileVersion must be 3" unless lockfile["lockfileVersion"] == 3
direct_dependencies = direct_npm_dependencies(lockfile, errors)
direct_names = direct_dependencies.map { |entry| entry["name"] }.to_set

direct_dependencies.each do |entry|
  name = entry["name"]
  locked = entry["lock"]
  record = components[name]
  if record.nil? || record.dig("component", "kind") != "npm_package"
    errors << "dependency registry: direct npm dependency #{name}@#{entry["version"]} has no candidate record"
    next
  end
  errors << "#{name}: registry version differs from manifest" unless record.dig("component", "version") == entry["version"]
  errors << "#{name}: registry source URL differs from lockfile" unless record.dig("component", "source_url") == locked["resolved"]
  errors << "#{name}: registry SRI differs from lockfile" unless record.dig("component", "digest", "value") == locked["integrity"]
  errors << "#{name}: registry license differs from lockfile" unless record.dig("component", "license_expression") == locked["license"]
end

registered_npm = records.select { |record| record.dig("component", "kind") == "npm_package" }.map { |record| record.dig("component", "name") }.to_set
(registered_npm - direct_names).each { |name| errors << "dependency registry: stale/non-direct npm candidate #{name}" }

go_mod_source = File.read(GO_MOD_PATH)
go_sum_source = File.file?(GO_SUM_PATH) ? File.read(GO_SUM_PATH) : ""
errors << "go.work: workspace overrides are prohibited in release input" if File.file?(File.join(ROOT, "go.work"))
errors << "vendor: vendored Go source requires separate provenance and approval" if File.directory?(File.join(ROOT, "vendor"))
allowed_pgxpool_indirect = EXPECTED_PGXPOOL_CLOSURE.transform_values { |values| values.first(3) }
go_validation = validate_go_dependencies(
  go_mod_source,
  go_sum_source,
  components,
  errors,
  allowed_indirect: allowed_pgxpool_indirect
)
direct_go = go_validation["direct"]
direct_go_names = direct_go.map { |entry| entry["name"] }.to_set

review_licenses = Set.new
lockfile.fetch("packages", {}).each do |path, package|
  next unless path.include?("node_modules/")
  next if package["link"] || package["name"]&.start_with?("@stead/")

  license = package["license"]
  if license.nil? || license.empty?
    errors << "package-lock.json: #{path} has no license metadata"
  elsif license.match?(DISALLOWED_NPM_LICENSE)
    errors << "package-lock.json: #{path} has disallowed/unknown license #{license}"
  elsif !allowed_lock_license?(license)
    review_licenses << license
    errors << "package-lock.json: #{path} has non-allowlisted license #{license}; add a scoped approved exception or remove it"
  end
end

active_record_names = direct_names | direct_go_names
workflow_paths = Dir.glob(File.join(ROOT, ".github/workflows/*.{yml,yaml}"))
workflow_paths.each do |workflow_path|
  File.read(workflow_path).scan(/\buses:\s*["']?([^\s"'#]+)/).flatten.each do |reference|
    next if reference.start_with?("./")
    if (match = reference.match(/\A([^@]+)@([0-9a-f]{40})\z/))
      name = match[1]
      errors << "#{workflow_path.delete_prefix(ROOT + "/")}: prohibited setup action #{name}; execute reviewed toolchain artifacts directly" if PROHIBITED_SETUP_ACTIONS.include?(name)
      active_record_names << name
      record = components[name]
      errors << "#{workflow_path.delete_prefix(ROOT + "/")}: unregistered action #{name}" and next unless record
      errors << "#{workflow_path.delete_prefix(ROOT + "/")}: #{name} pin differs from approval registry" unless record.dig("component", "digest", "value") == match[2]
    else
      errors << "#{workflow_path.delete_prefix(ROOT + "/")}: action reference #{reference.inspect} is not pinned to a 40-character commit"
    end
  end
end

workflow_sources = workflow_paths.to_h { |path| [path.delete_prefix(ROOT + "/"), File.read(path)] }
oci_references = validate_oci_workflow_images(workflow_sources, components, errors)
active_record_names.merge(oci_references.map { |reference| reference["name"] })

ci_path = File.join(ROOT, ".github/workflows/ci.yml")
if !File.file?(ci_path)
  errors << ".github/workflows/ci.yml: required foundation workflow is missing"
else
  ci = File.read(ci_path)
  {
    "contents: read" => "least-privilege contents permission",
    "persist-credentials: false" => "non-persistent checkout credential boundary",
    "scripts/run_pinned_node.sh npm ci" => "checksum-bound Node toolchain",
    "Ruby 3.2 or newer is required" => "host Ruby compatibility floor",
    "fetch-depth: 0" => "annotated baseline tag history",
    "fetch-tags: true" => "annotated baseline tag availability",
    "npm ci --ignore-scripts --no-audit --no-fund" => "lock-only npm installation",
    "make foundation-check" => "foundation gate",
    "DO_NOT_TRACK: \"1\"" => "default do-not-track signal",
    "NPM_CONFIG_IGNORE_SCRIPTS: \"true\"" => "default lifecycle-script disablement",
    "OTEL_SDK_DISABLED: \"true\"" => "default telemetry disablement",
    "REDOCLY_TELEMETRY: \"off\"" => "Redocly telemetry disablement"
  }.each do |snippet, purpose|
    errors << ".github/workflows/ci.yml: missing #{purpose}" unless ci.include?(snippet)
  end
  errors << ".github/workflows/ci.yml: pull_request_target is prohibited" if ci.match?(/\bpull_request_target\s*:/)
  errors << ".github/workflows/ci.yml: workflow may not request write or id-token permission" if ci.match?(/^\s+(?:contents|actions|checks|deployments|id-token|packages|pull-requests|security-events|statuses):\s*write\s*$/)
  errors << ".github/workflows/ci.yml: foundation workflow may not reference repository secrets" if ci.include?("secrets.")
  errors << ".github/workflows/ci.yml: floating runner label ubuntu-latest is prohibited" if ci.include?("ubuntu-latest")
end

go_runner = File.read(File.join(ROOT, "scripts/run_pinned_go.sh"))
errors << "scripts/run_pinned_go.sh: Go version pin is missing" unless go_runner.include?("go1.27.0")
errors << "scripts/run_pinned_go.sh: official Go archive digest is missing" unless go_runner.include?("675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685")
errors << "scripts/run_pinned_go.sh: extracted Go binary digest is missing" unless go_runner.include?("1db869c560a193573a71be466a34e0d4abb7792d78165c6102cdda069276a3a8")
errors << "scripts/run_pinned_go.sh: container fallback is not approved" if go_runner.match?(/\bdocker\s+run\b|golang@sha256/)
errors << "scripts/run_pinned_go.sh: host Go fast path is prohibited" if go_runner.include?("command -v go")

node_runner = File.read(File.join(ROOT, "scripts/run_pinned_node.sh"))
errors << "scripts/run_pinned_node.sh: Node version pin is missing" unless node_runner.include?("v26.8.1")
errors << "scripts/run_pinned_node.sh: official Node archive digest is missing" unless node_runner.include?("3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d")
errors << "scripts/run_pinned_node.sh: extracted Node binary digest is missing" unless node_runner.include?("19235a9b678f84729464c52623f92de130a165452747c6826d3fdc13df3abcc3")
errors << "scripts/run_pinned_node.sh: host Node fast path is prohibited" if node_runner.include?("command -v node")

openfga_runner = File.read(File.join(ROOT, "scripts/validate_openfga.sh"))
errors << "scripts/validate_openfga.sh: repository-owned model evaluator is missing" unless openfga_runner.include?("validate_openfga_model.mjs")
errors << "scripts/validate_openfga.sh: external OpenFGA CLI execution is prohibited until a vulnerability-clean exact release is approved" if openfga_runner.match?(/\bfga\s+model\s+test\b|openfga\/cli\/releases/)

errors.concat(notice_quarantine_errors(notices))
required_notices = records.select { |record| record.dig("decision", "status") == "APPROVED" }
                          .flat_map { |record| Array(record.dig("obligations", "notices")) }
                          .uniq
required_notices.each do |notice_id|
  errors << "THIRD_PARTY_NOTICES.md: missing #{notice_id}" unless notices.include?(notice_id)
end
errors << "THIRD_PARTY_NOTICES.md: missing pinned Devlane commit" unless notices.include?("7719dcadf91f881b5aefe8b74012ffcfbba0bc17")
if lockfile.fetch("packages", {}).key?("node_modules/scheduler")
  errors << "THIRD_PARTY_NOTICES.md: distributed React scheduler notice/version is missing" unless notices.include?("`scheduler` 0.27.0")
end

if release_mode
  workflow_source = workflow_paths.map { |path| File.read(path) }.join("\n")
  active_record_names << "node-v26.8.1-linux-x64.tar.xz" if workflow_source.include?("node-version: 26.8.1")
  makefile_source = File.read(File.join(ROOT, "Makefile"))
  if makefile_source.include?("scripts/run_pinned_go.sh")
    active_record_names << "go1.27.0.linux-amd64.tar.gz"
  end
  if makefile_source.include?("scripts/run_pinned_node.sh")
    active_record_names << "node-v26.8.1-linux-x64.tar.xz"
  end
  errors.concat(release_approval_errors(active_record_names, components, registry["release_eligible_statuses"]))
end

unless errors.empty?
  warn "dependency validation failed (#{errors.length} error#{errors.length == 1 ? "" : "s"}):"
  errors.each { |error| warn "- #{error}" }
  exit 1
end

pending = records.count { |record| record.dig("decision", "status") == "REVIEWED_PENDING_INDEPENDENT_APPROVAL" }
rejected = records.count { |record| record.dig("decision", "status") == "REJECTED" }
puts "dependency registry valid: #{records.length} exact candidate records; #{direct_dependencies.length} direct npm dependencies; #{direct_go.length} direct Go modules; #{oci_references.length} workflow OCI images; #{pending} pending independent approval; #{rejected} rejected/quarantined"
puts "transitive license review required before approval: #{review_licenses.to_a.sort.join(", ")}" unless review_licenses.empty?
puts "release eligibility verified for #{active_record_names.length} active dependencies" if release_mode
