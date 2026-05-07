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
#   ./scripts/run-local.sh                # bring up + run
#   ./scripts/run-local.sh clean          # wipe .run/ then run
#   ./scripts/run-local.sh down           # tear down Docker infra
#
# Submit an entry from a second terminal:
#
#   go run ./cmd/submit-stamp -log-did "$LEDGER_LOG_DID"
#
# What this script wires:
#
#   * Postgres via scripts/local/docker-compose.testharness.yml
#     (only the postgres service — fake-gcs is NOT used).
#   * REAL GCS via the developer's bucket + ADC credentials.
#   * .run/{wal,tessera,antispam} as ephemeral on-disk volumes
#     (gitignored). `clean` wipes them; default re-runs preserve
#     state.
#   * Self-witness K=1 loopback: LEDGER_WITNESS_ENDPOINTS points
#     at the ledger itself with QUORUM_K=1. The cosign endpoint
#     is mounted (ephemeral witness key generated on boot) so the
#     same code paths run locally as in a production K=N witness
#     deployment — no test-mode flag.
#   * Ephemeral signing keys (ledger entry signer, witness
#     signer, Tessera checkpoint signer) — local-dev only; every
#     restart produces fresh DIDs.

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

# ── Real-GCS preflight ────────────────────────────────────────────
# Fail fast if the developer hasn't done the one-time GCS setup.
# These checks mirror `make dev-preflight` (the production-shaped
# multi-node compose) so single-node + multi-node bring-up share
# the same surprise-free contract.
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
tests, see `make integration-up`.

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

# Wait for Postgres readiness via psql connection probe.
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

# ── Witness K=1 self-loop bootstrap ───────────────────────────────
# The ledger requires LEDGER_NETWORK_BOOTSTRAP_FILE when witness
# mode is active (LEDGER_WITNESS_ENDPOINTS set below). Generate a
# stable witness key + bootstrap doc on first run; subsequent runs
# preserve the key (so the witness DID is stable across restarts)
# and re-derive the bootstrap doc from it.
WITNESS_KEY_FILE="${RUN_DIR}/witness.pem"
NETWORK_BOOTSTRAP_FILE="${RUN_DIR}/network-bootstrap.json"
echo "== generating witness key + network bootstrap =="
go run ./cmd/init-network \
    -out-witness-key="${WITNESS_KEY_FILE}" \
    -out-bootstrap="${NETWORK_BOOTSTRAP_FILE}" \
    -log-did="${LEDGER_LOG_DID:-did:attesta:ledger:local}" \
    -network-name="local-dev"

# ── Ledger env ─────────────────────────────────────────────────
# Postgres
export LEDGER_DATABASE_URL="${LEDGER_DATABASE_URL:-postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable}"

# Identity
export LEDGER_LOG_DID="${LEDGER_LOG_DID:-did:attesta:ledger:local}"

# Storage volumes
export LEDGER_WAL_PATH="${LEDGER_WAL_PATH:-${RUN_DIR}/wal}"
export LEDGER_TESSERA_STORAGE_DIR="${LEDGER_TESSERA_STORAGE_DIR:-${RUN_DIR}/tessera}"
export LEDGER_TESSERA_ANTISPAM_PATH="${LEDGER_TESSERA_ANTISPAM_PATH:-${RUN_DIR}/antispam}"

# Bytestore — REAL GCS. ADC handles auth; the bucket must already
# exist and the ADC principal must have storage.objects.{create,
# get, list, delete} on it.
export LEDGER_BYTE_STORE_BACKEND="gcs"
# LEDGER_BYTE_STORE_GCS_BUCKET — required, exported by caller.
export LEDGER_BYTE_STORE_GCS_BUCKET
# Endpoint + Anonymous explicitly UNSET so cloud.google.com/go/storage
# falls through to ADC against storage.googleapis.com.
unset LEDGER_BYTE_STORE_GCS_ENDPOINT
unset LEDGER_BYTE_STORE_GCS_ANONYMOUS

# HTTP listen — the witness self-loop below assumes this matches
# LEDGER_WITNESS_ENDPOINTS.
export LEDGER_ADDR="${LEDGER_ADDR:-:8080}"

# Self-witness K=1 loopback: ledger becomes its own witness.
# Same HeadSync → /v1/cosign → CosignHandler → tree_head_sigs path
# as a production K=N deployment. Witness key is STABLE — the
# init-network step above generates it on first run and preserves
# it across restarts. The bootstrap doc declares this witness's
# DID as the genesis witness set.
export LEDGER_WITNESS_ENDPOINTS="${LEDGER_WITNESS_ENDPOINTS:-http://localhost:8080}"
export LEDGER_WITNESS_QUORUM_K="${LEDGER_WITNESS_QUORUM_K:-1}"
export LEDGER_WITNESS_KEY_FILE="${LEDGER_WITNESS_KEY_FILE:-${WITNESS_KEY_FILE}}"
export LEDGER_NETWORK_BOOTSTRAP_FILE="${LEDGER_NETWORK_BOOTSTRAP_FILE:-${NETWORK_BOOTSTRAP_FILE}}"

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
echo "  LEDGER_WITNESS_KEY_FILE=${LEDGER_WITNESS_KEY_FILE}"
echo "  LEDGER_NETWORK_BOOTSTRAP_FILE=${LEDGER_NETWORK_BOOTSTRAP_FILE}"
echo "  LEDGER_METRICS_ENABLE=${LEDGER_METRICS_ENABLE}"
echo "  LEDGER_OTLP_TRACES_ENDPOINT=${LEDGER_OTLP_TRACES_ENDPOINT}"
echo "  LEDGER_PPROF_ADDR=${LEDGER_PPROF_ADDR}"
echo

# ── Run ───────────────────────────────────────────────────────────
echo "== starting ledger =="
exec go run ./cmd/ledger
