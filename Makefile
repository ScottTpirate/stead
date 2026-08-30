.PHONY: foundation-check go-check contract-check performance-foundation-check

foundation-check: go-check contract-check performance-foundation-check
	scripts/run_pinned_node.sh npm run typecheck
	scripts/run_pinned_node.sh npm run test:unit --workspace=@stead/web
	scripts/run_pinned_node.sh npm run build
	scripts/run_pinned_node.sh npm run validate:web-bundle
	scripts/run_pinned_node.sh npm run validate:schemas
	scripts/run_pinned_node.sh npm run validate:asyncapi
	scripts/run_pinned_node.sh npm run validate:openapi
	scripts/run_pinned_node.sh npm audit --audit-level=high
	ruby scripts/validate_dependencies.rb --release
	ruby tests/contract/architecture/foundation_contract_test.rb

go-check:
	@unformatted="$$(scripts/run_pinned_go.sh gofmt -l apps internal)"; \
	  test -z "$$unformatted" || { printf '%s\n' "$$unformatted"; exit 1; }
	scripts/run_pinned_go.sh go vet ./...
	scripts/run_pinned_go.sh go test ./...
	scripts/run_pinned_go.sh go build ./...

contract-check:
	ruby scripts/validate_phase0.rb
	ruby scripts/validate_contracts.rb
	ruby scripts/validate_adr_records.rb
	scripts/run_pinned_node.sh node scripts/validate_owgp_examples.js
	scripts/validate_openfga.sh

performance-foundation-check:
	ruby tests/performance/harness/performance_foundation_test.rb
	ruby tests/performance/harness/verify_evidence.rb packages/test-fixtures/harness/performance/standard-request-boundary-valid.json
	scripts/run_pinned_node.sh node tests/performance/harness/performance_schema_test.mjs
