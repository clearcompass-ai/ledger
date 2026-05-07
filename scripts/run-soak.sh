#!/bin/bash
# scripts/run-soak.sh
#
# Runs the build-tag-isolated ledger soak test (tests/soak_test.go).
# Default: 1M entries against real GCS, ~3 min sustained throughput.
# Lower the count via ATTESTA_SOAK_ENTRIES for quick iteration.
#
# Postgres:
#   If ATTESTA_TEST_DSN is set, that DSN is used as-is (no docker).
#   If unset, this script auto-provisions Postgres in Docker using the
#   same compose file as scripts/run-local.sh and exports the canonical
#   testharness DSN. The container persists between runs; tear it down
#   with `./scripts/run-soak.sh down`.
#
# Required env (GCS — no auto-provision; soak is real-cloud by design):
#   ATTESTA_TEST_GCS_BUCKET       real GCS bucket name (REQUIRED)
#   GOOGLE_APPLICATION_CREDENTIALS path to a service-account key with
#                                  storage.objects.{create,get,list,delete}
#                                  on the bucket (or workload identity)
#
# Optional env:
#   ATTESTA_TEST_DSN              postgres connection string. If unset,
#                                 auto-provisioned via Docker (see above).
#
# Optional knobs (env, with defaults):
#   ATTESTA_SOAK_ENTRIES          1000000   total entries to submit
#   ATTESTA_SOAK_CONCURRENCY      8         concurrent submitter goroutines
#   ATTESTA_SOAK_VERIFY_SAMPLES   100       random subset to verify via /raw
#   ATTESTA_SOAK_P99_BOUND_MS     100       admission p99 ceiling
#
# Usage (auto-provisioned Postgres):
#   export ATTESTA_TEST_GCS_BUCKET=attesta-soak
#   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
#   ./scripts/run-soak.sh
#
# Usage (bring-your-own Postgres):
#   export ATTESTA_TEST_DSN=postgres://user:pw@host/db
#   export ATTESTA_TEST_GCS_BUCKET=attesta-soak
#   ./scripts/run-soak.sh
#
# Scale down for a quick run:
#   ATTESTA_SOAK_ENTRIES=10000 ATTESTA_SOAK_VERIFY_SAMPLES=20 \
#     ./scripts/run-soak.sh
#
# Tear down the auto-provisioned Postgres container:
#   ./scripts/run-soak.sh down

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.testharness.yml"
# Canonical testharness DSN — same as scripts/run-local.sh, so soak and
# laptop dev share one Postgres instance when they're not running
# concurrently.
DOCKER_DSN="postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable"

case "${1:-}" in
    down)
        echo "== tearing down testharness postgres =="
        docker compose -f "${COMPOSE_FILE}" down -v
        exit 0
        ;;
esac

cd "${REPO_ROOT}"

# ── GCS preflight (no auto-provision; soak is real-cloud) ─────────
if [ -z "${ATTESTA_TEST_GCS_BUCKET:-}" ]; then
    echo "FATAL: ATTESTA_TEST_GCS_BUCKET not set"
    echo
    echo "  export ATTESTA_TEST_GCS_BUCKET=<your-bucket>"
    exit 1
fi

if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ ! -r "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
    echo "FATAL: GOOGLE_APPLICATION_CREDENTIALS points at unreadable file:"
    echo "       ${GOOGLE_APPLICATION_CREDENTIALS}"
    exit 1
fi

# ── Postgres: auto-provision via Docker if no DSN was supplied ────
PROVISIONED_PG=0
if [ -z "${ATTESTA_TEST_DSN:-}" ]; then
    if ! command -v docker >/dev/null 2>&1; then
        cat <<'ERR' >&2
FATAL: ATTESTA_TEST_DSN not set and `docker` CLI not found on PATH.

Either install Docker so this script can auto-provision Postgres, or
supply a DSN to an existing Postgres instance:

  export ATTESTA_TEST_DSN=postgres://user:pw@host/db
ERR
        exit 1
    fi

    echo "== ATTESTA_TEST_DSN unset — provisioning Postgres in Docker =="
    docker compose -f "${COMPOSE_FILE}" up -d postgres

    echo "== waiting for postgres =="
    READY=0
    for i in $(seq 1 30); do
        if docker exec attesta_test_postgres \
                pg_isready -U attesta -d attesta_test >/dev/null 2>&1; then
            echo "postgres ready (attempt ${i})"
            READY=1
            break
        fi
        sleep 1
    done
    if [ "${READY}" -ne 1 ]; then
        echo "FATAL: postgres did not become ready within 30s"
        echo "       check: docker logs attesta_test_postgres"
        exit 1
    fi

    export ATTESTA_TEST_DSN="${DOCKER_DSN}"
    PROVISIONED_PG=1
    echo "   ATTESTA_TEST_DSN=${ATTESTA_TEST_DSN}"
    echo "   (tear down with: ./scripts/run-soak.sh down)"
fi

# Soak runs against REAL GCS — explicitly clear any container-mode signal
# the test harness might pick up.
unset ATTESTA_TEST_GCS_ENDPOINT

ENTRIES="${ATTESTA_SOAK_ENTRIES:-1000000}"
CONCURRENCY="${ATTESTA_SOAK_CONCURRENCY:-8}"
SAMPLES="${ATTESTA_SOAK_VERIFY_SAMPLES:-100}"
P99_BOUND_MS="${ATTESTA_SOAK_P99_BOUND_MS:-100}"

if [ "${PROVISIONED_PG}" -eq 1 ]; then
    DSN_SOURCE="docker (auto-provisioned)"
else
    DSN_SOURCE="env ATTESTA_TEST_DSN"
fi

echo "== attesta ledger soak =="
echo "   dsn source:   ${DSN_SOURCE}"
echo "   bucket:       ${ATTESTA_TEST_GCS_BUCKET}"
echo "   creds:        ${GOOGLE_APPLICATION_CREDENTIALS:-(workload identity / gcloud ADC)}"
echo "   entries:      ${ENTRIES}"
echo "   concurrency:  ${CONCURRENCY}"
echo "   verify:       ${SAMPLES}"
echo "   p99 bound ms: ${P99_BOUND_MS}"
echo

START_NS=$(date +%s%N)

# 30m ceiling — at 1M entries × 8 workers we expect ~3 min, but a slow
# bytestore drain at the end can extend the wall clock. The test's own
# drainTimeout is 10m to bound the worst case.
go test -tags=soak \
    -count=1 \
    -timeout 30m \
    -v \
    -run 'TestSoak' \
    ./tests/

END_NS=$(date +%s%N)
ELAPSED_S=$(( (END_NS - START_NS) / 1000000000 ))

echo
echo "== summary =="
cat <<EOF
{
  "entries":            ${ENTRIES},
  "concurrency":        ${CONCURRENCY},
  "verify_samples":     ${SAMPLES},
  "p99_bound_ms":       ${P99_BOUND_MS},
  "wall_clock_seconds": ${ELAPSED_S},
  "bucket":             "${ATTESTA_TEST_GCS_BUCKET}",
  "test_status":        "ok"
}
EOF

echo
echo "Cleanup verification: leftover soak objects under your bucket?"
echo "  gsutil ls 'gs://${ATTESTA_TEST_GCS_BUCKET}/soak/**' || echo '(none)'"
