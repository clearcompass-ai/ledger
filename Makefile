# Attesta Ledger — make targets
#
# Conventional helpers for build / test / lint cadence plus the
# SDK mutation-gate audit. All targets use POSIX sh and are
# intended to run in CI without relying on developer tooling. The
# audit target works whether the SDK is vendored
# (vendor/github.com/clearcompass-ai/attesta/) or resolved from the
# Go module cache (go env GOMODCACHE).

GO          ?= go
SDK_MODULE  := github.com/clearcompass-ai/attesta

.PHONY: build test test-short audit-sdk vet tidy clean help \
        dev-up dev-down dev-logs dev-status dev-rebuild dev-preflight \
        integration-up integration-down integration-logs integration-status \
        integration-gcs-tile \
        release-build verify-deps lint sbom test-race

DEV_COMPOSE := docker compose -f scripts/local/docker-compose.dev.yml
INT_COMPOSE := docker compose -f scripts/local/docker-compose.integration.yml

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
# SDK mutation-gate audit
# ─────────────────────────────────────────────────────────────────────

# audit-sdk ensures NO muEnable* gate has been flipped to false in
# the SDK that this ledger depends on. Every muEnable constant is a
# load-bearing security gate, and any value other than `true` in
# committed code is a regression.
#
# Resolution order:
#   1. If ./vendor/<sdk> exists, scan there (ledger is vendoring).
#   2. Otherwise, ask `go list -m` for the module cache directory
#      and scan there (default Go module mode).
#
# Either path produces an absolute directory we can grep. A non-zero
# exit status on `grep` means matches were found, which is the
# failure condition we want to surface to CI.
audit-sdk: ## Fail if SDK ships any muEnable*=false
	@set -e; \
	VENDOR_DIR="vendor/$(SDK_MODULE)"; \
	if [ -d "$$VENDOR_DIR" ]; then \
		SDK_PATH="$$VENDOR_DIR"; \
	else \
		SDK_PATH=$$($(GO) list -m -f '{{.Dir}}' $(SDK_MODULE)); \
	fi; \
	if [ -z "$$SDK_PATH" ] || [ ! -d "$$SDK_PATH" ]; then \
		echo "audit-sdk: cannot locate SDK source at $$SDK_PATH"; \
		exit 2; \
	fi; \
	echo "audit-sdk: scanning $$SDK_PATH"; \
	HITS=$$(grep -rn '^[[:space:]]*muEnable.*=[[:space:]]*false' \
	    --include='*.go' --exclude='*_test.go' "$$SDK_PATH" || true); \
	if [ -n "$$HITS" ]; then \
		echo "$$HITS"; \
		echo ""; \
		echo "FAIL: SDK ships disabled mutation gates (above)."; \
		echo "Every muEnable* constant must be true in committed code."; \
		exit 1; \
	fi; \
	echo "audit-sdk: PASS — no disabled mutation gates"

# ─── Dev topology (REAL GCS) ────────────────────────────────────────────
#
# Two ledger nodes (node-a on :8080, node-b on :8081) backed by a
# shared Postgres and REAL Google Cloud Storage (the developer's own
# GCS buckets). Domain-agnostic: every log DID, database name, and
# bucket name is supplied via env vars at deployment time. Domain-
# specific demos (judicial-network, supply-chain, etc.) live in
# their own repos and consume this generic topology.
#
# Required developer setup BEFORE `make dev-up`:
#   gcloud auth application-default login
#   export LEDGER_DEV_BUCKET_NODE_A=<your-node-a-bucket>
#   export LEDGER_DEV_BUCKET_NODE_B=<your-node-b-bucket>
#   export LEDGER_DEV_NODE_A_LOG_DID=<did:web:...>  (e.g. did:web:node-a.example)
#   export LEDGER_DEV_NODE_B_LOG_DID=<did:web:...>
# See scripts/local/README.dev.md for full prerequisites.

dev-preflight: ## Validate dev-up prerequisites (gcloud ADC + bucket env + log-DID env)
	@if [ ! -f "$$HOME/.config/gcloud/application_default_credentials.json" ]; then \
	  echo "FAIL: missing $$HOME/.config/gcloud/application_default_credentials.json"; \
	  echo "      run: gcloud auth application-default login"; \
	  exit 1; \
	fi
	@for var in LEDGER_DEV_BUCKET_NODE_A LEDGER_DEV_BUCKET_NODE_B \
	            LEDGER_DEV_NODE_A_LOG_DID LEDGER_DEV_NODE_B_LOG_DID; do \
	  eval "val=\$$$$var"; \
	  if [ -z "$$val" ]; then \
	    echo "FAIL: $$var is unset"; \
	    echo "      see scripts/local/README.dev.md"; \
	    exit 1; \
	  fi; \
	done
	@echo "preflight ok: ADC found, bucket + log-DID env vars set"

dev-up: dev-preflight ## Boot dev topology against REAL GCS (node-a :8080 + node-b :8081)
	$(DEV_COMPOSE) up -d --build
	@echo "waiting for both ledger nodes to report healthy..."
	@for i in $$(seq 1 60); do \
	  a=$$(curl -fsS http://localhost:8080/healthz 2>/dev/null || echo ""); \
	  b=$$(curl -fsS http://localhost:8081/healthz 2>/dev/null || echo ""); \
	  [ "$$a" = "ok" ] && [ "$$b" = "ok" ] && \
	    echo "ready: node-a=:8080  node-b=:8081  gcs=storage.googleapis.com" && exit 0; \
	  sleep 2; \
	done; \
	echo "ledger nodes did not report healthy in time; run 'make dev-logs'"; exit 1

dev-down: ## Tear down dev topology AND delete volumes (full reset; GCS buckets unchanged)
	$(DEV_COMPOSE) down -v

dev-logs: ## Tail logs from both ledger nodes
	$(DEV_COMPOSE) logs -f ledger-node-a ledger-node-b

dev-status: ## Show service status
	$(DEV_COMPOSE) ps

dev-rebuild: ## Rebuild ledger image and restart both services
	$(DEV_COMPOSE) build ledger-node-a
	$(DEV_COMPOSE) up -d ledger-node-a ledger-node-b

# ─── Integration topology (fake-gcs-server, offline) ────────────────────
#
# Same ledger + database shape but the GCS dependency is satisfied
# by fake-gcs-server (in-process, anonymous, deterministic). Used for
# integration tests + offline / air-gapped local runs. Use the
# real-GCS topology (above) for daily development.

integration-up: ## Boot integration topology (fake-gcs-server, offline)
	$(INT_COMPOSE) up -d --build
	@echo "waiting for both ledger nodes to report healthy..."
	@for i in $$(seq 1 60); do \
	  a=$$(curl -fsS http://localhost:8080/healthz 2>/dev/null || echo ""); \
	  b=$$(curl -fsS http://localhost:8081/healthz 2>/dev/null || echo ""); \
	  [ "$$a" = "ok" ] && [ "$$b" = "ok" ] && \
	    echo "ready: node-a=:8080  node-b=:8081  fake-gcs=:4443" && exit 0; \
	  sleep 2; \
	done; \
	echo "ledger nodes did not report healthy in time; run 'make integration-logs'"; exit 1

integration-down: ## Tear down integration topology AND delete volumes
	$(INT_COMPOSE) down -v

integration-logs: ## Tail logs from both ledger nodes (integration topology)
	$(INT_COMPOSE) logs -f ledger-node-a ledger-node-b

integration-status: ## Show service status (integration topology)
	$(INT_COMPOSE) ps

# ─── GCS tile-serving integration (REAL GCS only) ──────────────────────
#
# Real-GCS tests for bytestore.GCSTiles (the c2sp.org/tlog-tiles read
# backend behind /checkpoint and /tile/...). Build-tag-isolated so a
# default `go test ./...` never invokes them — these tests upload
# 16-MiB+ payloads and exercise concurrent reads at 1000-way fan-out.
#
# Required env:
#   ATTESTA_TEST_GCS_BUCKET=<your-test-bucket>
#   GOOGLE_APPLICATION_CREDENTIALS=<path-to-sa-key.json>
#
# Costs: <$0.10 per run (mostly egress on the concurrent-read fan-out).
# t.Cleanup deletes every object under each test's prefix at end.

integration-gcs-tile: ## Run REAL-GCS tile-serving integration tests (requires bucket + ADC)
	@if [ -z "$$ATTESTA_TEST_GCS_BUCKET" ]; then \
	  echo "FAIL: ATTESTA_TEST_GCS_BUCKET unset — set to a real bucket your ADC can write"; \
	  exit 1; \
	fi
	@if [ -z "$$GOOGLE_APPLICATION_CREDENTIALS" ] && \
	    [ ! -f "$$HOME/.config/gcloud/application_default_credentials.json" ]; then \
	  echo "FAIL: no ADC found — run 'gcloud auth application-default login'"; \
	  echo "      or export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json"; \
	  exit 1; \
	fi
	$(GO) test -tags=gcs_integration ./bytestore/ \
	    -run TestGCSTilesIntegration -v -count=1 -timeout 10m

# ─────────────────────────────────────────────────────────────────────
# K — Build / version / supply-chain
#
# Pragmatic, transparency-log-shaped supply-chain story. Mirrors the
# practices used by Tessera (transparency-dev), Sigstore, and Let's
# Encrypt Boulder:
#
#   K1 — version embedding via -ldflags ($BUILD_VERSION/COMMIT/TIME)
#   K2 — reproducible builds via -trimpath + -ldflags="-s -w -buildid="
#   K3 — `make verify-deps`: go mod verify (CI-gated)
#   K4 — `make lint`: golangci-lint + govulncheck + staticcheck
#   K5 — `make sbom`: cyclonedx-gomod CycloneDX 1.5 JSON
#   K6 — container image cosign signing — DEFERRED until a release
#        pipeline + image registry exist; documented in operations.md
# ─────────────────────────────────────────────────────────────────────

# Version + commit + build-time variables. Computed once per make
# invocation. Override by setting BUILD_VERSION / BUILD_COMMIT /
# BUILD_TIME from the calling shell (e.g., a release CI job).
BUILD_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_TIME    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS_VERSION := \
  -X main.Version=$(BUILD_VERSION) \
  -X main.Commit=$(BUILD_COMMIT) \
  -X main.BuildTime=$(BUILD_TIME)

# K2 — reproducible-build flags. -s strips symbol table; -w strips
# DWARF; -buildid="" zeroes the build-id. Combined with -trimpath
# and a fixed BUILD_TIME, two builds from the same commit + same
# Go toolchain produce byte-identical binaries.
LDFLAGS_REPRODUCIBLE := -s -w -buildid=

# K1 — release-build target. Produces ./bin/ledger with version
# strings injected. Use BUILD_VERSION=v1.2.3 for tagged releases:
#
#   BUILD_VERSION=v1.2.3 make release-build
#
# For byte-reproducible builds, also pass a fixed BUILD_TIME (e.g.,
# the commit's author date):
#
#   BUILD_VERSION=v1.2.3 \
#     BUILD_TIME=$$(git show -s --format=%cI HEAD) \
#     make release-build
release-build: ## Build ./bin/ledger with version + reproducible flags
	@mkdir -p ./bin
	$(GO) build \
	    -trimpath \
	    -buildvcs=true \
	    -ldflags="$(LDFLAGS_VERSION) $(LDFLAGS_REPRODUCIBLE)" \
	    -o ./bin/ledger \
	    ./cmd/ledger
	@echo "release-build: ./bin/ledger"
	@echo "  version=$(BUILD_VERSION)"
	@echo "  commit=$(BUILD_COMMIT)"
	@echo "  build_time=$(BUILD_TIME)"

# K3 — verify checked-in module sums against the upstream registry.
# Trivial; this is the supply-chain integrity floor every Go project
# inherits free with go.sum in source control.
verify-deps: ## go mod verify + go mod download check
	$(GO) mod verify
	$(GO) mod download -x ./...

# K4 — `make lint`. Three orthogonal checks:
#
#   - golangci-lint: meta-linter (govet, staticcheck, ineffassign,
#     errcheck, etc. — see .golangci.yml for the enabled set).
#   - govulncheck: scans for known CVEs in transitive deps.
#   - go vet: stdlib's own vet pass (also runs as part of golangci-
#     lint but `go vet` directly catches build-tag-gated files).
#
# Run locally before pushing; CI runs the same suite via
# .github/workflows/lint.yml. Fails with a non-zero exit on any hit.
lint: ## golangci-lint + govulncheck + go vet
	@command -v golangci-lint >/dev/null 2>&1 || { \
	  echo "FAIL: golangci-lint not on PATH"; \
	  echo "      install: https://golangci-lint.run/welcome/install/#local-installation"; \
	  exit 1; \
	}
	golangci-lint run ./...
	@command -v govulncheck >/dev/null 2>&1 || { \
	  echo "FAIL: govulncheck not on PATH"; \
	  echo "      install: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	  exit 1; \
	}
	govulncheck ./...
	$(GO) vet ./...

# K5 — `make sbom` produces a CycloneDX 1.5 JSON SBOM at
# ./bin/sbom.cdx.json. Uses cyclonedx-gomod (pure Go, no Docker
# dep — laptop-runnable). Operators publish this alongside the
# binary at release tags so consumers can audit transitive deps.
#
# Install: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
sbom: ## Generate CycloneDX SBOM at ./bin/sbom.cdx.json
	@command -v cyclonedx-gomod >/dev/null 2>&1 || { \
	  echo "FAIL: cyclonedx-gomod not on PATH"; \
	  echo "      install: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest"; \
	  exit 1; \
	}
	@mkdir -p ./bin
	cyclonedx-gomod app -json -licenses -output ./bin/sbom.cdx.json -main ./cmd/ledger .
	@echo "sbom: ./bin/sbom.cdx.json"

# Race detector across the merge-gate-critical packages. Mirrors
# what CI runs in .github/workflows/go-test.yml. Faster than
# `go test -race ./...` while still covering the hot path.
test-race: ## Race detector on critical packages (merge gate)
	$(GO) test -race -count=1 -short \
	    ./api/ ./api/middleware/ ./apitypes/ \
	    ./gossipnet/ ./gossipstore/ \
	    ./sequencer/ ./shipper/ ./store/ \
	    ./tessera/ ./bytestore/ ./wal/ ./lifecycle/ \
	    ./cmd/ledger/
