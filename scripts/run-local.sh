#!/bin/bash
# scripts/run-local.sh
#
# Local-dev orchestrator. Brings up Postgres + fake-gcs, sets every
# env var the ledger needs, and runs the ledger binary against
# them. Designed to make the full local-dev loop a single command:
#
#   ./scripts/run-local.sh
#
# In another terminal:
#
#   # Mode A
#   go run ./cmd/seed-session -dsn "$LEDGER_DATABASE_URL" \
#       -token tok-dev -credits 100
#   go run ./cmd/submit-stamp -token tok-dev \
#       -log-did "$LEDGER_LOG_DID"
#
#   # Mode B (no setup)
#   go run ./cmd/submit-stamp -log-did "$LEDGER_LOG_DID"
#
# What this script wires:
#
#   * Postgres + fake-gcs via scripts/local/docker-compose.testharness.yml.
#   * .run/{wal,tessera,antispam} as ephemeral on-disk volumes
#     (gitignored). Re-running keeps state across restarts; pass
#     `clean` as the first arg to wipe them.
#   * Self-witness K=1 loopback: LEDGER_WITNESS_ENDPOINTS points
#     at the ledger itself with QUORUM_K=1. The cosign endpoint
#     is mounted (ephemeral witness key generated on boot) so the
#     same code paths run locally as in a production K=N witness
#     deployment — no test-mode flag.
#   * Ephemeral signing keys (ledger entry signer, witness
#     signer, Tessera checkpoint signer) — local-dev only; every
#     restart produces fresh DIDs.
#
# Override anything via env before invoking. Defaults match the
# integration docker-compose ports (Postgres on 5544, fake-gcs on
# 4443) and the ledger's default :8080.
#
# Tear down infra:  ./scripts/run-local.sh down

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.testharness.yml"
RUN_DIR="${REPO_ROOT}/.run"

case "${1:-}" in
    down)
        docker compose -f "${COMPOSE_FILE}" down -v
        exit 0
        ;;
    clean)
        echo "== wiping ${RUN_DIR} =="
        rm -rf "${RUN_DIR}"
        ;;
esac

cd "${REPO_ROOT}"

# ── Infra ─────────────────────────────────────────────────────────
echo "== bringing up postgres + fake-gcs + bucket-init =="
docker compose -f "${COMPOSE_FILE}" up -d postgres fake-gcs bucket-init

# Wait for Postgres readiness via psql connection probe.
echo "== waiting for postgres =="
for i in $(seq 1 30); do
    if docker exec attesta_test_postgres pg_isready -U attesta -d attesta_test >/dev/null 2>&1; then
        echo "postgres ready (attempt ${i})"
        break
    fi
    sleep 1
done

# Wait for fake-gcs healthcheck to flip green.
echo "== waiting for fake-gcs =="
for i in $(seq 1 30); do
    health="$(docker inspect --format='{{.State.Health.Status}}' attesta_test_gcs 2>/dev/null || true)"
    if [ "${health}" = "healthy" ]; then
        echo "fake-gcs ready (attempt ${i})"
        break
    fi
    sleep 1
done

# Wait for bucket-init to finish (it exits 0 on bucket creation).
for i in $(seq 1 30); do
    status="$(docker inspect --format='{{.State.Status}}' attesta_test_bucket_init 2>/dev/null || true)"
    exitcode="$(docker inspect --format='{{.State.ExitCode}}' attesta_test_bucket_init 2>/dev/null || echo -1)"
    if [ "${status}" = "exited" ] && [ "${exitcode}" = "0" ]; then
        echo "bucket ready (attempt ${i})"
        break
    fi
    sleep 1
done

# ── Local volumes ─────────────────────────────────────────────────
mkdir -p "${RUN_DIR}/wal" "${RUN_DIR}/tessera" "${RUN_DIR}/antispam"

# ── Ledger env ─────────────────────────────────────────────────
# Postgres
export LEDGER_DATABASE_URL="${LEDGER_DATABASE_URL:-postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable}"

# Identity
export LEDGER_LOG_DID="${LEDGER_LOG_DID:-did:attesta:ledger:local}"

# Storage volumes
export LEDGER_WAL_PATH="${LEDGER_WAL_PATH:-${RUN_DIR}/wal}"
export LEDGER_TESSERA_STORAGE_DIR="${LEDGER_TESSERA_STORAGE_DIR:-${RUN_DIR}/tessera}"
export LEDGER_TESSERA_ANTISPAM_PATH="${LEDGER_TESSERA_ANTISPAM_PATH:-${RUN_DIR}/antispam}"

# Bytestore — fake-gcs locally; the bucket bucket-init created.
export LEDGER_BYTE_STORE_BACKEND="${LEDGER_BYTE_STORE_BACKEND:-gcs}"
export LEDGER_BYTE_STORE_GCS_BUCKET="${LEDGER_BYTE_STORE_GCS_BUCKET:-attesta-tiles}"
export LEDGER_BYTE_STORE_GCS_ENDPOINT="${LEDGER_BYTE_STORE_GCS_ENDPOINT:-http://localhost:4443/storage/v1/}"
export LEDGER_BYTE_STORE_GCS_ANONYMOUS="${LEDGER_BYTE_STORE_GCS_ANONYMOUS:-true}"

# HTTP listen — the witness self-loop below assumes this matches
# LEDGER_WITNESS_ENDPOINTS.
export LEDGER_ADDR="${LEDGER_ADDR:-:8080}"

# Self-witness K=1 loopback: ledger becomes its own witness.
# Same HeadSync → /v1/cosign → CosignHandler → tree_head_sigs path
# as a production K=N deployment. Witness key is ephemeral.
export LEDGER_WITNESS_ENDPOINTS="${LEDGER_WITNESS_ENDPOINTS:-http://localhost:8080}"
export LEDGER_WITNESS_QUORUM_K="${LEDGER_WITNESS_QUORUM_K:-1}"
# LEDGER_WITNESS_KEY_FILE intentionally unset → ephemeral. Set
# this if you want a stable witness identity across restarts.

# Ledger entry signer — ephemeral did:key. cfg.LedgerDID is
# overridden to match. Set LEDGER_SIGNER_KEY_FILE for a stable
# DID across restarts.

# ── Observability (D1-D7) ─────────────────────────────────────────
# Metrics ON by default (D1). Tracing endpoint defaults to
# "stdout" so spans land in the ledger's stderr alongside Info
# logs — no second process needed for laptop dev.
#
# To get UIs, start the observability profile in a second shell:
#
#   docker compose -f scripts/local/docker-compose.testharness.yml \
#       --profile observability up -d
#   # Prometheus UI: http://localhost:9090
#   # Jaeger UI:     http://localhost:16686
#
# Then re-run with LEDGER_OTLP_TRACES_ENDPOINT pointed at Jaeger:
#   LEDGER_OTLP_TRACES_ENDPOINT=http://localhost:4318 ./scripts/run-local.sh
export LEDGER_METRICS_ENABLE="${LEDGER_METRICS_ENABLE:-true}"
export LEDGER_METRICS_ENVIRONMENT="${LEDGER_METRICS_ENVIRONMENT:-laptop-dev}"
export LEDGER_OTLP_TRACES_ENDPOINT="${LEDGER_OTLP_TRACES_ENDPOINT:-stdout}"
# pprof on loopback only (A4) — diagnostic, never public.
export LEDGER_PPROF_ADDR="${LEDGER_PPROF_ADDR:-127.0.0.1:6060}"

echo "== env ready =="
echo "  LEDGER_DATABASE_URL=${LEDGER_DATABASE_URL}"
echo "  LEDGER_LOG_DID=${LEDGER_LOG_DID}"
echo "  LEDGER_ADDR=${LEDGER_ADDR}"
echo "  LEDGER_BYTE_STORE_BACKEND=${LEDGER_BYTE_STORE_BACKEND} (bucket=${LEDGER_BYTE_STORE_GCS_BUCKET})"
echo "  LEDGER_WAL_PATH=${LEDGER_WAL_PATH}"
echo "  LEDGER_WITNESS_ENDPOINTS=${LEDGER_WITNESS_ENDPOINTS} (quorum_k=${LEDGER_WITNESS_QUORUM_K})"
echo "  LEDGER_METRICS_ENABLE=${LEDGER_METRICS_ENABLE}"
echo "  LEDGER_OTLP_TRACES_ENDPOINT=${LEDGER_OTLP_TRACES_ENDPOINT}"
echo "  LEDGER_PPROF_ADDR=${LEDGER_PPROF_ADDR}"
echo

# ── Run ───────────────────────────────────────────────────────────
echo "== starting ledger =="
exec go run ./cmd/ledger
