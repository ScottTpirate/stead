#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require "digest"

root = File.expand_path("..", __dir__)
relative_directive = "docs/architecture/MASTER_BUILD_DIRECTIVE.md"
directive_path = File.join(root, relative_directive)
inventory_path = File.join(root, "specs/traceability/directive-inventory.yaml")
bytes = File.binread(directive_path)
text = bytes.dup.force_encoding(Encoding::UTF_8)
abort "directive is not valid UTF-8" unless text.valid_encoding?

ids = text.scan(/^## ([A-Z]+-\d{3})(?=\s|$)/).flatten
abort "duplicate directive requirement headings" unless ids.uniq.length == ids.length

inventory = {
  "schema_version" => "1.0",
  "directive" => {
    "path" => relative_directive,
    "version" => text[/^\*\*Version:\*\*\s*([^\s<]+)/, 1],
    "sha256" => Digest::SHA256.hexdigest(bytes),
    "named_requirement_count" => ids.length
  },
  "requirement_ids" => ids.sort
}

File.write(inventory_path, inventory.to_yaml(line_width: -1), encoding: "UTF-8")
