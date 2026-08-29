#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

schema_cache="${STEAD_SCHEMA_NPM_CACHE:-/tmp/stead-schema-npm-cache}"
export npm_config_cache="$schema_cache"

ajv_compile() {
  npx --yes \
    --package=ajv-cli@5.0.0 \
    --package=ajv-formats@3.0.1 \
    ajv compile --spec=draft2020 --strict=false -c ajv-formats "$@"
}

owgp="specs/work-graph-profile/owgp-v0.1.schema.json"
actor="packages/event-schemas/common/actor-context/actor-context-v0.1.schema.json"

ajv_compile -s "$owgp"
ajv_compile -r "$owgp" -s "$actor"
ajv_compile -r "$owgp" -r "$actor" -s packages/event-schemas/platform/platform-event-v0.1.schema.json
ajv_compile -r "$owgp" -s policies/opa/input-v0.1.schema.json
ajv_compile -s policies/opa/output-v0.1.schema.json
ajv_compile -r "$owgp" -s specs/migration/migration-job-v0.1.schema.json
ajv_compile -s policies/security-label-profiles/profile-v0.1.schema.json
ajv_compile -s policies/deployment-domains/domain-profile-v0.1.schema.json

printf '%s\n' 'Standalone JSON Schema validation passed: 8/8 canonical schemas resolve by $id.'
