#!/bin/bash
# scripts/run-local.sh
#
# Local-dev orchestrator. Brings up Postgres + fake-gcs, sets every
# env var the operator needs, and runs the operator binary against
# them. Designed to make the full local-dev loop a single command:
#
#   ./scripts/run-local.sh
#
# In another terminal:
#
#   # Mode A
#   go run ./cmd/seed-session -dsn "$OPERATOR_DATABASE_URL" \
#       -token tok-dev -credits 100
#   go run ./cmd/submit-stamp -token tok-dev \
#       -log-did "$OPERATOR_LOG_DID"
#
#   # Mode B (no setup)
#   go run ./cmd/submit-stamp -log-did "$OPERATOR_LOG_DID"
#
# What this script wires:
#
#   * Postgres + fake-gcs via scripts/local/docker-compose.testharness.yml.
#   * .run/{wal,tessera,antispam} as ephemeral on-disk volumes
#     (gitignored). Re-running keeps state across restarts; pass
#     `clean` as the first arg to wipe them.
#   * Self-witness K=1 loopback: OPERATOR_WITNESS_ENDPOINTS points
#     at the operator itself with QUORUM_K=1. The cosign endpoint
#     is mounted (ephemeral witness key generated on boot) so the
#     same code paths run locally as in a production K=N witness
#     deployment — no test-mode flag.
#   * Ephemeral signing keys (operator entry signer, witness
#     signer, Tessera checkpoint signer) — local-dev only; every
#     restart produces fresh DIDs.
#
# Override anything via env before invoking. Defaults match the
# integration docker-compose ports (Postgres on 5544, fake-gcs on
# 4443) and the operator's default :8080.
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
    if docker exec ortholog_test_postgres pg_isready -U ortholog -d ortholog_test >/dev/null 2>&1; then
        echo "postgres ready (attempt ${i})"
        break
    fi
    sleep 1
done

# Wait for fake-gcs healthcheck to flip green.
echo "== waiting for fake-gcs =="
for i in $(seq 1 30); do
    health="$(docker inspect --format='{{.State.Health.Status}}' ortholog_test_gcs 2>/dev/null || true)"
    if [ "${health}" = "healthy" ]; then
        echo "fake-gcs ready (attempt ${i})"
        break
    fi
    sleep 1
done

# Wait for bucket-init to finish (it exits 0 on bucket creation).
for i in $(seq 1 30); do
    status="$(docker inspect --format='{{.State.Status}}' ortholog_test_bucket_init 2>/dev/null || true)"
    exitcode="$(docker inspect --format='{{.State.ExitCode}}' ortholog_test_bucket_init 2>/dev/null || echo -1)"
    if [ "${status}" = "exited" ] && [ "${exitcode}" = "0" ]; then
        echo "bucket ready (attempt ${i})"
        break
    fi
    sleep 1
done

# ── Local volumes ─────────────────────────────────────────────────
mkdir -p "${RUN_DIR}/wal" "${RUN_DIR}/tessera" "${RUN_DIR}/antispam"

# ── Operator env ─────────────────────────────────────────────────
# Postgres
export OPERATOR_DATABASE_URL="${OPERATOR_DATABASE_URL:-postgres://ortholog:ortholog@localhost:5544/ortholog_test?sslmode=disable}"

# Identity
export OPERATOR_LOG_DID="${OPERATOR_LOG_DID:-did:ortholog:operator:local}"

# Storage volumes
export OPERATOR_WAL_PATH="${OPERATOR_WAL_PATH:-${RUN_DIR}/wal}"
export OPERATOR_TESSERA_STORAGE_DIR="${OPERATOR_TESSERA_STORAGE_DIR:-${RUN_DIR}/tessera}"
export OPERATOR_TESSERA_ANTISPAM_PATH="${OPERATOR_TESSERA_ANTISPAM_PATH:-${RUN_DIR}/antispam}"

# Bytestore — fake-gcs locally; the bucket bucket-init created.
export OPERATOR_BYTE_STORE_BACKEND="${OPERATOR_BYTE_STORE_BACKEND:-gcs}"
export OPERATOR_BYTE_STORE_GCS_BUCKET="${OPERATOR_BYTE_STORE_GCS_BUCKET:-ortholog-tiles}"
export OPERATOR_BYTE_STORE_GCS_ENDPOINT="${OPERATOR_BYTE_STORE_GCS_ENDPOINT:-http://localhost:4443/storage/v1/}"
export OPERATOR_BYTE_STORE_GCS_ANONYMOUS="${OPERATOR_BYTE_STORE_GCS_ANONYMOUS:-true}"

# HTTP listen — the witness self-loop below assumes this matches
# OPERATOR_WITNESS_ENDPOINTS.
export OPERATOR_ADDR="${OPERATOR_ADDR:-:8080}"

# Self-witness K=1 loopback: operator becomes its own witness.
# Same HeadSync → /v1/cosign → CosignHandler → tree_head_sigs path
# as a production K=N deployment. Witness key is ephemeral.
export OPERATOR_WITNESS_ENDPOINTS="${OPERATOR_WITNESS_ENDPOINTS:-http://localhost:8080}"
export OPERATOR_WITNESS_QUORUM_K="${OPERATOR_WITNESS_QUORUM_K:-1}"
# OPERATOR_WITNESS_KEY_FILE intentionally unset → ephemeral. Set
# this if you want a stable witness identity across restarts.

# Operator entry signer — ephemeral did:key. cfg.OperatorDID is
# overridden to match. Set OPERATOR_SIGNER_KEY_FILE for a stable
# DID across restarts.

echo "== env ready =="
echo "  OPERATOR_DATABASE_URL=${OPERATOR_DATABASE_URL}"
echo "  OPERATOR_LOG_DID=${OPERATOR_LOG_DID}"
echo "  OPERATOR_ADDR=${OPERATOR_ADDR}"
echo "  OPERATOR_BYTE_STORE_BACKEND=${OPERATOR_BYTE_STORE_BACKEND} (bucket=${OPERATOR_BYTE_STORE_GCS_BUCKET})"
echo "  OPERATOR_WAL_PATH=${OPERATOR_WAL_PATH}"
echo "  OPERATOR_WITNESS_ENDPOINTS=${OPERATOR_WITNESS_ENDPOINTS} (quorum_k=${OPERATOR_WITNESS_QUORUM_K})"
echo

# ── Run ───────────────────────────────────────────────────────────
echo "== starting operator =="
exec go run ./cmd/operator
