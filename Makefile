.PHONY: foundation-check go-check contract-check

foundation-check: go-check contract-check
	scripts/run_pinned_node.sh node --test scripts/checkpoint_a_smoke.test.mjs scripts/checkpoint_a_denial.test.mjs scripts/checkpoint_a_browser.test.mjs scripts/checkpoint_a_tls.test.mjs scripts/checkpoint_a_followon.test.mjs scripts/checkpoint_a_discovery.test.mjs
	scripts/run_pinned_node.sh npm run typecheck
	scripts/run_pinned_node.sh npm run test:unit --workspace=@stead/web
	scripts/run_pinned_node.sh npm run test --workspace=@stead/web
	scripts/run_pinned_node.sh npm run build
	scripts/run_pinned_node.sh npm run validate:web-bundle
	scripts/run_pinned_node.sh npm run validate:bundle-evidence --workspace=@stead/web
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
	scripts/run_pinned_node.sh node scripts/validate_provider_reconciliation.mjs
	scripts/run_pinned_node.sh node --test tests/contract/gitea/provider_reconciliation_contract.test.mjs
	scripts/run_pinned_node.sh node scripts/validate_owgp_examples.js
	scripts/validate_openfga.sh

.PHONY: dev dev-prepare dev-down dev-status dev-smoke dev-check

dev:
	scripts/run_pinned_node.sh node scripts/dev_stack.mjs up

dev-prepare:
	scripts/run_pinned_node.sh node scripts/dev_stack.mjs prepare

dev-down:
	scripts/run_pinned_node.sh node scripts/dev_stack.mjs down

dev-status:
	scripts/run_pinned_node.sh node scripts/dev_stack.mjs status

dev-smoke:
	scripts/run_pinned_node.sh node scripts/dev_stack.mjs smoke

dev-check:
	scripts/run_pinned_node.sh node --test scripts/dev_stack.test.mjs
	scripts/run_pinned_go.sh go test -race ./apps/worker

.PHONY: checkpoint-a-browser
# Exact installed tools only; never download or reuse compatibility acceptance.
# The shell clears inherited preload/proxy/debug variables before starting Node.
checkpoint-a-browser:
	@test -n "$$STEAD_BROWSER_REVIEW" && ulimit -S -c 0 && ulimit -H -c 0 && \
	  exec /usr/bin/env -i PATH=/usr/bin LANG=C.UTF-8 TZ=UTC \
	  /tmp/stead-node-toolchain-26.8.1/toolchain/node-v26.8.1-linux-x64/bin/node \
	  scripts/checkpoint_a_browser.mjs --review "$$STEAD_BROWSER_REVIEW"

.PHONY: checkpoint-a-tls
# Separate admission: no browser journey, setup/session input, or application marker.
checkpoint-a-tls:
	@test -n "$$STEAD_TLS_REVIEW" && ulimit -S -c 0 && ulimit -H -c 0 && \
	  exec /usr/bin/env -i PATH=/usr/bin LANG=C.UTF-8 TZ=UTC \
	  /tmp/stead-node-toolchain-26.8.1/toolchain/node-v26.8.1-linux-x64/bin/node \
	  scripts/checkpoint_a_tls.mjs --review "$$STEAD_TLS_REVIEW"
