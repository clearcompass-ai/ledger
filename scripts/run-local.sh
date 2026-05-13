#!/bin/bash
# scripts/run-local.sh
#
# Local-dev orchestrator. Brings up Postgres (Docker), generates
# witness keys + network bootstrap, starts N standalone-witness
# processes, then starts the Ledger pointing at them. K=N quorum.
#
# REAL GCS is REQUIRED — not fake-gcs-server. Local dev must
# exercise the same ADC + auth + retry + GCS-quirks code path
# that production uses.
#
# ARCHITECTURAL BOUNDARY:
#
#   The Ledger and the Witness are physically separate Go modules,
#   hosted in different repositories (the witness daemon lives at
#   github.com/clearcompass-ai/standalone-witness). The Ledger never
#   imports witness-daemon code; the witness daemon never imports
#   ledger code. This script orchestrates them as separate
#   processes — `go run` fetches the witness module independently.
#
# Prerequisites (one-time setup):
#
#   1. gcloud auth application-default login
#   2. gcloud storage buckets create gs://<your-bucket>
#   3. export LEDGER_BYTE_STORE_GCS_BUCKET=<your-bucket>
#
# Usage:
#
#   ./scripts/run-local.sh                    # 1 witness + 1 ledger (K=1 quorum)
#   ./scripts/run-local.sh --witnesses N      # N witnesses + 1 ledger (K=N quorum)
#   ./scripts/run-local.sh clean              # wipe .run/ then run
#   ./scripts/run-local.sh down               # tear down everything
#   ./scripts/run-local.sh integration        # run integration tests
#
# Multi-witness mode:
#
#   - 1 ledger writer on :8080 (LEDGER_ADDR).
#   - N witness daemons on :8081, :8082, ..., :808N.
#   - K-of-N quorum collected on every cosignature request.
#   - Witness key files in .run/witnesses/witness-{1..N}.pem.
#   - Bootstrap doc lists ALL N witness DIDs in genesis_witness_set.
#   - Tear down with `./scripts/run-local.sh down`.
#
# Integration mode:
#
#   - Brings up scripts/local/docker-compose.integration.yml
#     (2 ledger nodes, fake-gcs-server, dual Postgres DBs).
#   - Runs `go test -count=1 ./integration/`.
#
# Submit an entry from a second terminal:
#
#   go run ./cmd/submit-stamp -log-did "$LEDGER_LOG_DID"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.testharness.yml"
INT_COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.integration.yml"
RUN_DIR="${REPO_ROOT}/.run"
WITNESS_PIDS_FILE="${RUN_DIR}/witness-pids"

# ── Parse flags ────────────────────────────────────────────────────
WITNESS_COUNT=1
SUBCMD="run"
CLEAN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --witnesses)
            WITNESS_COUNT="${2:-}"
            if ! [[ "${WITNESS_COUNT}" =~ ^[0-9]+$ ]] || [ "${WITNESS_COUNT}" -lt 1 ]; then
                echo "FATAL: --witnesses requires a positive integer (got: ${WITNESS_COUNT})" >&2
                exit 2
            fi
            shift 2
            ;;
        down)
            SUBCMD="down"
            shift
            ;;
        clean)
            CLEAN=1
            shift
            ;;
        integration)
            SUBCMD="integration"
            shift
            ;;
        -h|--help)
            sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

# ── Tear-down: kill witnesses + down Docker ────────────────────────
if [ "${SUBCMD}" = "down" ]; then
    if [ -f "${WITNESS_PIDS_FILE}" ]; then
        echo "== stopping spawned witness daemons =="
        while read -r pid; do
            [ -z "${pid}" ] && continue
            if kill -0 "${pid}" 2>/dev/null; then
                kill "${pid}" 2>/dev/null || true
                echo "  stopped pid=${pid}"
            fi
        done < "${WITNESS_PIDS_FILE}"
        rm -f "${WITNESS_PIDS_FILE}"
    fi
    docker compose -f "${COMPOSE_FILE}" down -v
    if docker compose -f "${INT_COMPOSE_FILE}" ps -q 2>/dev/null | grep -q .; then
        echo "== integration topology also up — tearing down =="
        docker compose -f "${INT_COMPOSE_FILE}" down -v
    fi
    exit 0
fi

cd "${REPO_ROOT}"

# ── Integration: boot topology + run integration tests ─────────────
if [ "${SUBCMD}" = "integration" ]; then
    echo "== bringing up integration topology (fake-gcs, 2 ledger nodes) =="
    docker compose -f "${INT_COMPOSE_FILE}" up -d --build

    echo "== waiting for both ledger nodes to report healthy =="
    READY=0
    for i in $(seq 1 60); do
        a=$(curl -fsS http://localhost:8080/healthz 2>/dev/null || echo "")
        b=$(curl -fsS http://localhost:8081/healthz 2>/dev/null || echo "")
        if [ "${a}" = "ok" ] && [ "${b}" = "ok" ]; then
            echo "ready: node-a=:8080  node-b=:8081  fake-gcs=:4443 (attempt ${i})"
            READY=1
            break
        fi
        sleep 2
    done
    if [ "${READY}" -ne 1 ]; then
        echo "FATAL: ledger nodes did not report healthy in time" >&2
        echo "       check: docker compose -f ${INT_COMPOSE_FILE} logs" >&2
        exit 1
    fi

    echo
    echo "== running integration tests (./integration/) =="
    set +e
    go test -count=1 -v ./integration/
    TEST_RC=$?
    set -e

    echo
    if [ ${TEST_RC} -eq 0 ]; then
        echo "== integration tests PASSED =="
        echo "   topology still UP. Tear down with: ./scripts/run-local.sh down"
    else
        echo "== integration tests FAILED (exit=${TEST_RC}) =="
        echo "   topology left UP for log inspection."
    fi
    exit ${TEST_RC}
fi

# ── Default + multi-witness modes share the rest ───────────────────
if [ "${CLEAN}" = "1" ]; then
    echo "== wiping ${RUN_DIR} =="
    rm -rf "${RUN_DIR}"
fi

# ── Real-GCS preflight ────────────────────────────────────────────
if [ -z "${LEDGER_BYTE_STORE_GCS_BUCKET:-}" ]; then
    cat <<'ERR' >&2

== run-local.sh: missing LEDGER_BYTE_STORE_GCS_BUCKET ==

Local dev requires REAL GCS — fake-gcs-server is no longer
supported here because production uses real GCS auth + retry
behavior, and local dev must exercise the same code paths.

One-time setup:

  1. gcloud auth application-default login
  2. gcloud storage buckets create gs://<your-bucket>
  3. export LEDGER_BYTE_STORE_GCS_BUCKET=<your-bucket>

Then re-run ./scripts/run-local.sh.

For the offline / air-gapped fake-gcs harness used by integration
tests, run:  ./scripts/run-local.sh integration

ERR
    exit 1
fi

ADC_JSON="${HOME}/.config/gcloud/application_default_credentials.json"
if [ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ ! -f "${ADC_JSON}" ]; then
    cat <<'ERR' >&2

== run-local.sh: no Google Cloud ADC found ==

Run one of:

  gcloud auth application-default login
    (writes ~/.config/gcloud/application_default_credentials.json)

  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

Then re-run ./scripts/run-local.sh.

ERR
    exit 1
fi

# ── Infra (Postgres only) ─────────────────────────────────────────
echo "== bringing up postgres =="
docker compose -f "${COMPOSE_FILE}" up -d postgres

echo "== waiting for postgres =="
for i in $(seq 1 30); do
    if docker exec attesta_test_postgres pg_isready -U attesta -d attesta_test >/dev/null 2>&1; then
        echo "postgres ready (attempt ${i})"
        break
    fi
    sleep 1
done

# ── Local volumes ─────────────────────────────────────────────────
mkdir -p "${RUN_DIR}/wal" "${RUN_DIR}/tessera" "${RUN_DIR}/antispam" "${RUN_DIR}/logs"

# ── Generate witness keys + network bootstrap ─────────────────────
NETWORK_BOOTSTRAP_FILE="${RUN_DIR}/network-bootstrap.json"
echo "== generating ${WITNESS_COUNT} witness key(s) + network bootstrap =="
go run ./cmd/init-network \
    -out-dir="${RUN_DIR}" \
    -out-bootstrap="${NETWORK_BOOTSTRAP_FILE}" \
    -log-did="${LEDGER_LOG_DID:-did:attesta:ledger:local}" \
    -network-name="local-dev" \
    -witnesses="${WITNESS_COUNT}"

# ── Spawn standalone witness daemons ──────────────────────────────
# Each daemon is a SEPARATE go module hosted at
# github.com/clearcompass-ai/standalone-witness. The `go run`
# resolves that module's own pinned attesta version, fully
# isolated from the Ledger module's dependency graph.
#
# WITNESS_MODULE_VERSION pins the version fetched by `go run`.
# Override (e.g., to a tagged release) by exporting it before
# running this script.
WITNESS_MODULE="github.com/clearcompass-ai/standalone-witness"
WITNESS_MODULE_VERSION="${WITNESS_MODULE_VERSION:-latest}"
: > "${WITNESS_PIDS_FILE}"
ENDPOINTS=""
echo "== spawning ${WITNESS_COUNT} witness daemon(s) =="
for i in $(seq 1 "${WITNESS_COUNT}"); do
    port=$((8080 + i))
    wkey="${RUN_DIR}/witnesses/witness-${i}.pem"
    wlog="${RUN_DIR}/logs/witness-${i}.log"
    if [ ! -f "${wkey}" ]; then
        echo "FATAL: missing ${wkey} (init-network should have produced it)" >&2
        exit 1
    fi
    echo "  starting witness-${i} on :${port}  (log=${wlog})"
    ( GOWORK=off go run "${WITNESS_MODULE}@${WITNESS_MODULE_VERSION}" \
          -addr=":${port}" \
          -key-file="${wkey}" \
          -bootstrap="${NETWORK_BOOTSTRAP_FILE}" \
          > "${wlog}" 2>&1 ) &
    wpid=$!
    echo "${wpid}" >> "${WITNESS_PIDS_FILE}"
    if [ -n "${ENDPOINTS}" ]; then
        ENDPOINTS="${ENDPOINTS},http://localhost:${port}"
    else
        ENDPOINTS="http://localhost:${port}"
    fi
done

# Wait for each witness to report ready before starting the Ledger.
for i in $(seq 1 "${WITNESS_COUNT}"); do
    port=$((8080 + i))
    READY=0
    for attempt in $(seq 1 50); do
        if curl -fsS "http://localhost:${port}/healthz" >/dev/null 2>&1; then
            echo "  witness-${i} ready"
            READY=1
            break
        fi
        sleep 0.2
    done
    if [ "${READY}" -ne 1 ]; then
        echo "FATAL: witness-${i} did not report healthy. Log: ${RUN_DIR}/logs/witness-${i}.log" >&2
        exit 1
    fi
done

# Trap so Ctrl-C / signal exits tear the witnesses down too.
trap 'echo "== stopping spawned witnesses =="; \
      while read -r pid; do [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true; done < "'"${WITNESS_PIDS_FILE}"'"; \
      rm -f "'"${WITNESS_PIDS_FILE}"'"' EXIT INT TERM

# ── Ledger env ────────────────────────────────────────────────────
export LEDGER_DATABASE_URL="${LEDGER_DATABASE_URL:-postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable}"
export LEDGER_LOG_DID="${LEDGER_LOG_DID:-did:attesta:ledger:local}"
export LEDGER_WAL_PATH="${LEDGER_WAL_PATH:-${RUN_DIR}/wal}"
export LEDGER_TESSERA_STORAGE_DIR="${LEDGER_TESSERA_STORAGE_DIR:-${RUN_DIR}/tessera}"
export LEDGER_TESSERA_ANTISPAM_PATH="${LEDGER_TESSERA_ANTISPAM_PATH:-${RUN_DIR}/antispam}"

export LEDGER_BYTE_STORE_BACKEND="gcs"
export LEDGER_BYTE_STORE_GCS_BUCKET
unset LEDGER_BYTE_STORE_GCS_ENDPOINT
unset LEDGER_BYTE_STORE_GCS_ANONYMOUS

export LEDGER_ADDR="${LEDGER_ADDR:-:8080}"

# Witness wiring — Ledger acts purely as cosign CLIENT.
# The Ledger never holds a witness signing key; it never serves
# /v1/cosign. It only POSTs to the witness daemon URLs.
export LEDGER_WITNESS_ENDPOINTS="${LEDGER_WITNESS_ENDPOINTS:-${ENDPOINTS}}"
export LEDGER_WITNESS_QUORUM_K="${LEDGER_WITNESS_QUORUM_K:-${WITNESS_COUNT}}"
export LEDGER_NETWORK_BOOTSTRAP_FILE="${LEDGER_NETWORK_BOOTSTRAP_FILE:-${NETWORK_BOOTSTRAP_FILE}}"

export LEDGER_METRICS_ENABLE="${LEDGER_METRICS_ENABLE:-true}"
export LEDGER_METRICS_ENVIRONMENT="${LEDGER_METRICS_ENVIRONMENT:-laptop-dev}"
export LEDGER_OTLP_TRACES_ENDPOINT="${LEDGER_OTLP_TRACES_ENDPOINT:-stdout}"
export LEDGER_PPROF_ADDR="${LEDGER_PPROF_ADDR:-127.0.0.1:6060}"

echo "== env ready =="
echo "  LEDGER_DATABASE_URL=${LEDGER_DATABASE_URL}"
echo "  LEDGER_LOG_DID=${LEDGER_LOG_DID}"
echo "  LEDGER_ADDR=${LEDGER_ADDR}"
echo "  LEDGER_BYTE_STORE_BACKEND=${LEDGER_BYTE_STORE_BACKEND} (bucket=${LEDGER_BYTE_STORE_GCS_BUCKET})"
echo "  LEDGER_WITNESS_ENDPOINTS=${LEDGER_WITNESS_ENDPOINTS} (quorum_k=${LEDGER_WITNESS_QUORUM_K})"
echo "  LEDGER_NETWORK_BOOTSTRAP_FILE=${LEDGER_NETWORK_BOOTSTRAP_FILE}"
echo "  witness daemons: ${WITNESS_COUNT} (logs in ${RUN_DIR}/logs/)"
echo

# ── Run Ledger ────────────────────────────────────────────────────
echo "== starting ledger =="
exec go run ./cmd/ledger
