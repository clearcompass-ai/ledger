#!/bin/bash
# scripts/run-local.sh
#
# Local-dev orchestrator. Brings up Postgres (Docker), wires
# REAL Google Cloud Storage (developer-owned bucket via ADC),
# sets every env var the ledger needs, and runs the ledger
# binary against them.
#
# REAL GCS is REQUIRED — not fake-gcs-server. Local dev must
# exercise the same ADC + auth + retry + GCS-quirks code path
# that production uses. "Works on fake-gcs but breaks on GCS"
# is precisely the surprise we eliminate by always using the
# real backend.
#
# Prerequisites (one-time setup):
#
#   1. gcloud auth application-default login
#   2. Create a bucket:  gcloud storage buckets create gs://<your-bucket>
#   3. Export it before invoking this script:
#        export LEDGER_BYTE_STORE_GCS_BUCKET=<your-bucket>
#
# Usage:
#
#   ./scripts/run-local.sh                   # 1 instance, K=1 self-loop
#   ./scripts/run-local.sh clean             # wipe .run/ then run
#   ./scripts/run-local.sh down              # tear down Docker + spawned witnesses
#   ./scripts/run-local.sh integration       # boot integration topology + run integration tests
#   ./scripts/run-local.sh --witnesses N     # writer + N standalone witnesses (K=N quorum)
#   ./scripts/run-local.sh --witnesses 2 clean   # combined: clean + multi-witness
#
# Multi-witness mode (--witnesses N):
#
#   - Writer ledger on :8080 (LEDGER_ADDR), K=N quorum.
#   - N standalone-witness processes on :8081, :8082, ..., :808N.
#   - All N witnesses share Postgres (writer's DB only — witnesses
#     are stateless cosign HTTP servers and don't persist anything).
#   - Bootstrap doc lists writer DID + N witness DIDs.
#   - Tear down with `./scripts/run-local.sh down` (kills witnesses
#     by PID + downs Docker stack).
#
# Integration mode (`integration` subcommand):
#
#   - Brings up scripts/local/docker-compose.integration.yml
#     (2 ledger nodes, fake-gcs-server, dual Postgres DBs).
#   - Waits for both nodes' /healthz to report ok.
#   - Runs `go test -count=1 ./integration/`.
#   - Leaves the topology UP on success (use `make integration-down`
#     to tear down). On failure, also leaves it up so logs are
#     reachable via `make integration-logs`.
#
# Submit an entry from a second terminal:
#
#   go run ./cmd/submit-stamp -log-did "$LEDGER_LOG_DID"
#
# What this script wires (default + multi-witness mode):
#
#   * Postgres via scripts/local/docker-compose.testharness.yml
#     (only the postgres service — fake-gcs is NOT used).
#   * REAL GCS via the developer's bucket + ADC credentials.
#   * .run/{wal,tessera,antispam} as ephemeral on-disk volumes
#     (gitignored). `clean` wipes them; default re-runs preserve
#     state.
#   * Self-witness K=1 loopback (default) OR
#     writer + N standalone-witness processes (--witnesses N).
#   * Ephemeral signing keys (ledger entry signer, witness
#     signer, Tessera checkpoint signer) — local-dev only.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.testharness.yml"
INT_COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.integration.yml"
RUN_DIR="${REPO_ROOT}/.run"
WITNESS_PIDS_FILE="${RUN_DIR}/witness-pids"

# ── Parse flags ────────────────────────────────────────────────────
WITNESS_COUNT=0
SUBCMD="run"
CLEAN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --witnesses)
            WITNESS_COUNT="${2:-}"
            if ! [[ "${WITNESS_COUNT}" =~ ^[0-9]+$ ]]; then
                echo "FATAL: --witnesses requires a non-negative integer (got: ${WITNESS_COUNT})" >&2
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
            sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//' | head -n 50
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
        echo "== stopping spawned standalone-witness processes =="
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
        echo "   topology left UP for log inspection:"
        echo "     docker compose -f scripts/local/docker-compose.integration.yml logs ledger-node-a"
        echo "     docker compose -f scripts/local/docker-compose.integration.yml logs ledger-node-b"
    fi
    exit ${TEST_RC}
fi

# ── Default + multi-witness modes share the rest of the script ─────
if [ "${CLEAN}" = "1" ]; then
    echo "== wiping ${RUN_DIR} =="
    rm -rf "${RUN_DIR}"
fi

# ── Real-GCS preflight ────────────────────────────────────────────
# Fail fast if the developer hasn't done the one-time GCS setup.
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
    (service-account key file path)

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
mkdir -p "${RUN_DIR}/wal" "${RUN_DIR}/tessera" "${RUN_DIR}/antispam"

# ── Witness key + bootstrap doc ───────────────────────────────────
# The bootstrap doc defines the NETWORK's witness fleet (separate
# concept from the ledger writer):
#
# Default mode (WITNESS_COUNT=0):
#   - Network's witness set = [writer] (1 entry).
#   - Writer also serves /v1/cosign locally (K=1 self-loop).
#   - One key file at .run/witness.pem.
#
# Multi-witness mode (WITNESS_COUNT>0):
#   - Network's witness set = [N standalone-witness DIDs].
#   - Writer is NOT in the network's witness set; it's purely a
#     writer that talks to the N witnesses via /v1/cosign over HTTP.
#   - Writer's own witness key file is still generated below for
#     ledger-side code-path parity (every ledger config block
#     declares a witness key) but the writer's DID does NOT appear
#     in genesis_witness_set.
#   - N witness key files at .run/witnesses/witness-{1..N}.pem.
WITNESS_KEY_FILE="${RUN_DIR}/witness.pem"
NETWORK_BOOTSTRAP_FILE="${RUN_DIR}/network-bootstrap.json"
echo "== generating witness key + network bootstrap (extras=${WITNESS_COUNT}) =="
go run ./cmd/init-network \
    -out-witness-key="${WITNESS_KEY_FILE}" \
    -out-bootstrap="${NETWORK_BOOTSTRAP_FILE}" \
    -log-did="${LEDGER_LOG_DID:-did:attesta:ledger:local}" \
    -network-name="local-dev" \
    -extra-witnesses="${WITNESS_COUNT}"

# ── Spawn standalone witnesses (multi-witness mode only) ──────────
: > "${WITNESS_PIDS_FILE}"
WITNESS_ENDPOINTS_DEFAULT="http://localhost:8080"
QUORUM_K_DEFAULT=1
if [ "${WITNESS_COUNT}" -gt 0 ]; then
    echo "== spawning ${WITNESS_COUNT} standalone-witness processes =="
    LOG_DIR="${RUN_DIR}/logs"
    mkdir -p "${LOG_DIR}"

    ENDPOINTS=""
    for i in $(seq 1 "${WITNESS_COUNT}"); do
        port=$((8080 + i))
        wkey="${RUN_DIR}/witnesses/witness-${i}.pem"
        wlog="${LOG_DIR}/witness-${i}.log"
        if [ ! -f "${wkey}" ]; then
            echo "FATAL: expected ${wkey} (init-network should have produced it)" >&2
            exit 1
        fi
        echo "  starting witness-${i} on :${port}  (log=${wlog})"
        go run ./cmd/standalone-witness \
            -addr=":${port}" \
            -key-file="${wkey}" \
            -bootstrap="${NETWORK_BOOTSTRAP_FILE}" \
            > "${wlog}" 2>&1 &
        wpid=$!
        echo "${wpid}" >> "${WITNESS_PIDS_FILE}"
        if [ -n "${ENDPOINTS}" ]; then
            ENDPOINTS="${ENDPOINTS},http://localhost:${port}"
        else
            ENDPOINTS="http://localhost:${port}"
        fi
    done

    # Wait briefly for every witness's /healthz before starting the
    # writer. Each get up to ~5s; total bound = WITNESS_COUNT * ~5s.
    for i in $(seq 1 "${WITNESS_COUNT}"); do
        port=$((8080 + i))
        for attempt in $(seq 1 25); do
            if curl -fsS "http://localhost:${port}/healthz" >/dev/null 2>&1; then
                echo "  witness-${i} ready"
                break
            fi
            sleep 0.2
        done
    done

    WITNESS_ENDPOINTS_DEFAULT="${ENDPOINTS}"
    QUORUM_K_DEFAULT="${WITNESS_COUNT}"

    # Trap so Ctrl-C tears down spawned witnesses too.
    trap 'echo "== stopping spawned witnesses =="; \
          while read -r pid; do [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true; done < "'"${WITNESS_PIDS_FILE}"'"; \
          rm -f "'"${WITNESS_PIDS_FILE}"'"' EXIT INT TERM
fi

# ── Ledger env ────────────────────────────────────────────────────
# Postgres
export LEDGER_DATABASE_URL="${LEDGER_DATABASE_URL:-postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable}"

# Identity
export LEDGER_LOG_DID="${LEDGER_LOG_DID:-did:attesta:ledger:local}"

# Storage volumes
export LEDGER_WAL_PATH="${LEDGER_WAL_PATH:-${RUN_DIR}/wal}"
export LEDGER_TESSERA_STORAGE_DIR="${LEDGER_TESSERA_STORAGE_DIR:-${RUN_DIR}/tessera}"
export LEDGER_TESSERA_ANTISPAM_PATH="${LEDGER_TESSERA_ANTISPAM_PATH:-${RUN_DIR}/antispam}"

# Bytestore — REAL GCS. ADC handles auth.
export LEDGER_BYTE_STORE_BACKEND="gcs"
export LEDGER_BYTE_STORE_GCS_BUCKET
unset LEDGER_BYTE_STORE_GCS_ENDPOINT
unset LEDGER_BYTE_STORE_GCS_ANONYMOUS

# HTTP listen.
export LEDGER_ADDR="${LEDGER_ADDR:-:8080}"

# Witness wiring — flips from K=1 self-loop to K=N external when
# --witnesses N was passed.
export LEDGER_WITNESS_ENDPOINTS="${LEDGER_WITNESS_ENDPOINTS:-${WITNESS_ENDPOINTS_DEFAULT}}"
export LEDGER_WITNESS_QUORUM_K="${LEDGER_WITNESS_QUORUM_K:-${QUORUM_K_DEFAULT}}"
export LEDGER_WITNESS_KEY_FILE="${LEDGER_WITNESS_KEY_FILE:-${WITNESS_KEY_FILE}}"
export LEDGER_NETWORK_BOOTSTRAP_FILE="${LEDGER_NETWORK_BOOTSTRAP_FILE:-${NETWORK_BOOTSTRAP_FILE}}"

# ── Observability (D1-D7) ─────────────────────────────────────────
export LEDGER_METRICS_ENABLE="${LEDGER_METRICS_ENABLE:-true}"
export LEDGER_METRICS_ENVIRONMENT="${LEDGER_METRICS_ENVIRONMENT:-laptop-dev}"
export LEDGER_OTLP_TRACES_ENDPOINT="${LEDGER_OTLP_TRACES_ENDPOINT:-stdout}"
export LEDGER_PPROF_ADDR="${LEDGER_PPROF_ADDR:-127.0.0.1:6060}"

echo "== env ready =="
echo "  LEDGER_DATABASE_URL=${LEDGER_DATABASE_URL}"
echo "  LEDGER_LOG_DID=${LEDGER_LOG_DID}"
echo "  LEDGER_ADDR=${LEDGER_ADDR}"
echo "  LEDGER_BYTE_STORE_BACKEND=${LEDGER_BYTE_STORE_BACKEND} (bucket=${LEDGER_BYTE_STORE_GCS_BUCKET})"
echo "  LEDGER_WAL_PATH=${LEDGER_WAL_PATH}"
echo "  LEDGER_WITNESS_ENDPOINTS=${LEDGER_WITNESS_ENDPOINTS} (quorum_k=${LEDGER_WITNESS_QUORUM_K})"
echo "  LEDGER_WITNESS_KEY_FILE=${LEDGER_WITNESS_KEY_FILE}"
echo "  LEDGER_NETWORK_BOOTSTRAP_FILE=${LEDGER_NETWORK_BOOTSTRAP_FILE}"
echo "  LEDGER_METRICS_ENABLE=${LEDGER_METRICS_ENABLE}"
echo "  LEDGER_OTLP_TRACES_ENDPOINT=${LEDGER_OTLP_TRACES_ENDPOINT}"
echo "  LEDGER_PPROF_ADDR=${LEDGER_PPROF_ADDR}"
if [ "${WITNESS_COUNT}" -gt 0 ]; then
    echo "  spawned witnesses: ${WITNESS_COUNT} (logs in ${RUN_DIR}/logs/)"
fi
echo

# ── Run ───────────────────────────────────────────────────────────
echo "== starting ledger =="
exec go run ./cmd/ledger
