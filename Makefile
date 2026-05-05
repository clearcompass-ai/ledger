# Attesta Ledger — make targets
#
# Wave 1 v3 §CI1 introduces the audit-v775 target. Other targets
# below are conventional helpers for build / test / lint cadence.
#
# All targets use POSIX sh and are intended to run in CI without
# relying on developer tooling. The audit target works whether the
# SDK is vendored (vendor/github.com/clearcompass-ai/attesta/)
# or resolved from the Go module cache (go env GOMODCACHE).

GO          ?= go
SDK_MODULE  := github.com/clearcompass-ai/attesta

.PHONY: build test test-short audit-v775 vet tidy clean help \
        dev-up dev-down dev-logs dev-status dev-rebuild dev-preflight \
        integration-up integration-down integration-logs integration-status

DEV_COMPOSE := docker compose -f deployment/local/docker-compose.dev.yml
INT_COMPOSE := docker compose -f deployment/local/docker-compose.integration.yml

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Compile every package
	$(GO) build ./...

test: ## Run all tests (integration tests skip without ATTESTA_TEST_DSN)
	$(GO) test ./...

test-short: ## Run only unit tests (skip integration via -short)
	$(GO) test -short ./...

vet: ## go vet across all packages
	$(GO) vet ./...

tidy: ## go mod tidy + verify
	$(GO) mod tidy
	$(GO) mod verify

clean: ## Remove build artifacts
	rm -rf ./bin ./coverage.out

# ─────────────────────────────────────────────────────────────────────
# Wave 1 v3 §CI1 — SDK mutation-gate audit
# ─────────────────────────────────────────────────────────────────────

# audit-v775 ensures NO muEnable* gate has been flipped to false in
# the SDK that this ledger depends on. The discipline lives at
# ADR-005 §6: every muEnable constant is a load-bearing security
# gate, and any value other than `true` in committed code is a
# regression.
#
# Resolution order:
#   1. If ./vendor/<sdk> exists, scan there (ledger is vendoring).
#   2. Otherwise, ask `go list -m` for the module cache directory
#      and scan there (default Go module mode).
#
# Either path produces an absolute directory we can grep. A non-zero
# exit status on `grep` means matches were found, which is the
# failure condition we want to surface to CI.
audit-v775: ## Wave 1 §CI1 — fail if SDK ships any muEnable*=false
	@set -e; \
	VENDOR_DIR="vendor/$(SDK_MODULE)"; \
	if [ -d "$$VENDOR_DIR" ]; then \
		SDK_PATH="$$VENDOR_DIR"; \
	else \
		SDK_PATH=$$($(GO) list -m -f '{{.Dir}}' $(SDK_MODULE)); \
	fi; \
	if [ -z "$$SDK_PATH" ] || [ ! -d "$$SDK_PATH" ]; then \
		echo "audit-v775: cannot locate SDK source at $$SDK_PATH"; \
		exit 2; \
	fi; \
	echo "audit-v775: scanning $$SDK_PATH"; \
	if grep -rn 'muEnable.*=\s*false' --include='*.go' "$$SDK_PATH"; then \
		echo ""; \
		echo "FAIL: SDK ships disabled mutation gates (above)."; \
		echo "Every muEnable* constant must be true in committed code."; \
		echo "See ADR-005 §6 for the mutation-audit discipline."; \
		exit 1; \
	fi; \
	echo "audit-v775: PASS — no disabled mutation gates"

# ─── Dev topology (REAL GCS) ────────────────────────────────────────────
#
# Two ledgers (Davidson trial on :8080, COA on :8081) backed by a
# shared Postgres and REAL Google Cloud Storage (the developer's own
# GCS buckets). Powers the judicial-network walkthrough.
#
# Required developer setup BEFORE `make dev-up`:
#   gcloud auth application-default login
#   export LEDGER_DEV_BUCKET_DAVIDSON=<your-davidson-bucket>
#   export LEDGER_DEV_BUCKET_COA=<your-coa-bucket>
# See deployment/local/README.dev.md for full prerequisites.

dev-preflight: ## Validate dev-up prerequisites (gcloud ADC + bucket env)
	@if [ ! -f "$$HOME/.config/gcloud/application_default_credentials.json" ]; then \
	  echo "FAIL: missing $$HOME/.config/gcloud/application_default_credentials.json"; \
	  echo "      run: gcloud auth application-default login"; \
	  exit 1; \
	fi
	@if [ -z "$$LEDGER_DEV_BUCKET_DAVIDSON" ]; then \
	  echo "FAIL: LEDGER_DEV_BUCKET_DAVIDSON is unset"; \
	  echo "      see deployment/local/README.dev.md"; \
	  exit 1; \
	fi
	@if [ -z "$$LEDGER_DEV_BUCKET_COA" ]; then \
	  echo "FAIL: LEDGER_DEV_BUCKET_COA is unset"; \
	  echo "      see deployment/local/README.dev.md"; \
	  exit 1; \
	fi
	@echo "preflight ok: ADC found, bucket env vars set"

dev-up: dev-preflight ## Boot dev topology against REAL GCS (Davidson :8080 + COA :8081)
	$(DEV_COMPOSE) up -d --build
	@echo "waiting for both ledgers to report healthy..."
	@for i in $$(seq 1 60); do \
	  d=$$(curl -fsS http://localhost:8080/healthz 2>/dev/null || echo ""); \
	  c=$$(curl -fsS http://localhost:8081/healthz 2>/dev/null || echo ""); \
	  [ "$$d" = "ok" ] && [ "$$c" = "ok" ] && \
	    echo "ready: davidson=:8080  coa=:8081  gcs=storage.googleapis.com" && exit 0; \
	  sleep 2; \
	done; \
	echo "ledgers did not report healthy in time; run 'make dev-logs'"; exit 1

dev-down: ## Tear down dev topology AND delete volumes (full reset; GCS buckets unchanged)
	$(DEV_COMPOSE) down -v

dev-logs: ## Tail logs from both ledgers
	$(DEV_COMPOSE) logs -f ledger-davidson ledger-coa

dev-status: ## Show service status
	$(DEV_COMPOSE) ps

dev-rebuild: ## Rebuild ledger image and restart both services
	$(DEV_COMPOSE) build ledger-davidson
	$(DEV_COMPOSE) up -d ledger-davidson ledger-coa

# ─── Integration topology (fake-gcs-server, offline) ────────────────────
#
# Same ledger + database shape but the GCS dependency is satisfied
# by fake-gcs-server (in-process, anonymous, deterministic). Used for
# CI integration tests + offline / air-gapped local runs. Use the
# real-GCS topology (above) for daily development.

integration-up: ## Boot integration topology (fake-gcs-server, offline)
	$(INT_COMPOSE) up -d --build
	@echo "waiting for both ledgers to report healthy..."
	@for i in $$(seq 1 60); do \
	  d=$$(curl -fsS http://localhost:8080/healthz 2>/dev/null || echo ""); \
	  c=$$(curl -fsS http://localhost:8081/healthz 2>/dev/null || echo ""); \
	  [ "$$d" = "ok" ] && [ "$$c" = "ok" ] && \
	    echo "ready: davidson=:8080  coa=:8081  fake-gcs=:4443" && exit 0; \
	  sleep 2; \
	done; \
	echo "ledgers did not report healthy in time; run 'make integration-logs'"; exit 1

integration-down: ## Tear down integration topology AND delete volumes
	$(INT_COMPOSE) down -v

integration-logs: ## Tail logs from both ledgers (integration topology)
	$(INT_COMPOSE) logs -f ledger-davidson ledger-coa

integration-status: ## Show service status (integration topology)
	$(INT_COMPOSE) ps
