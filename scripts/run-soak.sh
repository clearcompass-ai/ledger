#!/bin/bash
# scripts/run-soak.sh
#
# Runs the build-tag-isolated ledger soak test (tests/soak_test.go).
# Default: 1M entries, ~3 min sustained throughput.
#
# ── Bytestore selection ──────────────────────────────────────────────
#   ATTESTA_SOAK_BYTESTORE_BACKEND
#     gcs        Real GCS (default; preserves prior behavior).
#                Requires ATTESTA_TEST_GCS_BUCKET + Google ADC.
#     seaweedfs  Local SeaweedFS in Docker — fully self-contained.
#                Auto-provisions the container, pre-creates bucket,
#                exports S3 endpoint/creds. ZERO cloud dependencies.
#     s3         Bring-your-own S3-compatible (real AWS, MinIO, R2).
#                Requires ATTESTA_TEST_S3_* env vars.
#
# ── Postgres ─────────────────────────────────────────────────────────
#   If ATTESTA_TEST_DSN is set, that DSN is used as-is (no docker).
#   If unset, this script auto-provisions Postgres in Docker using the
#   same compose file as scripts/run-local.sh and exports the canonical
#   testharness DSN. Tear down with `./scripts/run-soak.sh down`.
#
# ── Required env (per backend) ───────────────────────────────────────
#   GCS:
#     ATTESTA_TEST_GCS_BUCKET       real GCS bucket name (REQUIRED)
#     GOOGLE_APPLICATION_CREDENTIALS path to a service-account key
#                                    (or workload identity / gcloud ADC)
#   SeaweedFS:
#     (nothing — fully self-contained)
#   BYO S3:
#     ATTESTA_TEST_S3_BUCKET, ATTESTA_TEST_S3_ENDPOINT,
#     ATTESTA_TEST_S3_ACCESS_KEY, ATTESTA_TEST_S3_SECRET_KEY
#
# ── Optional env ─────────────────────────────────────────────────────
#   ATTESTA_TEST_DSN              postgres connection string (or auto-docker)
#
# ── Optional knobs (env, with defaults) ──────────────────────────────
#   ATTESTA_SOAK_ENTRIES                1000000  total entries to submit
#   ATTESTA_SOAK_CONCURRENCY            8        submitter goroutines
#   ATTESTA_SOAK_VERIFY_SAMPLES         100      random subset to verify via /raw
#   ATTESTA_SOAK_P99_BOUND_MS           100      admission p99 ceiling (ms)
#   ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT  16       parallel uploads — bump for
#                                                higher-volume soaks
#   ATTESTA_SOAK_DRAIN_TIMEOUT          10m      in-test wait for WAL HWM
#   ATTESTA_SOAK_TEST_TIMEOUT           30m      go test process ceiling
#
# ── Usage examples ───────────────────────────────────────────────────
#
# Cloud-free, fully local 100k smoke (RECOMMENDED for quick iteration):
#   ATTESTA_SOAK_BYTESTORE_BACKEND=seaweedfs \
#   ATTESTA_SOAK_ENTRIES=100000 \
#   ./scripts/run-soak.sh
#
# Cloud-free 1M production-tuned validation:
#   ATTESTA_SOAK_BYTESTORE_BACKEND=seaweedfs \
#   ATTESTA_SOAK_ENTRIES=1000000 \
#   ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT=64 \
#   ATTESTA_SOAK_DRAIN_TIMEOUT=10m \
#   ATTESTA_SOAK_TEST_TIMEOUT=45m \
#   ./scripts/run-soak.sh
#
# Real-GCS 1M validation:
#   export ATTESTA_TEST_GCS_BUCKET=my-bucket
#   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
#   ATTESTA_SOAK_ENTRIES=1000000 \
#   ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT=64 \
#   ./scripts/run-soak.sh
#
# Tear down all auto-provisioned containers (postgres + seaweedfs):
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
        echo "== tearing down testharness (postgres, seaweedfs, etc.) =="
        docker compose -f "${COMPOSE_FILE}" down -v
        exit 0
        ;;
esac

cd "${REPO_ROOT}"

# ── Bytestore backend selection ───────────────────────────────────
#
# Default "gcs" preserves prior behavior. "seaweedfs" auto-provisions
# a SeaweedFS instance via Docker (mirrors the run-local.sh Postgres
# pattern) and re-exports the env vars the soak harness needs to
# route through the bytestore.S3 adapter.
#
# Supported values:
#   gcs        — real GCS (or fake-gcs per LEDGER_BYTE_STORE_GCS_ENDPOINT)
#   seaweedfs  — local SeaweedFS in Docker (S3-compatible)
BACKEND="${ATTESTA_SOAK_BYTESTORE_BACKEND:-gcs}"
PROVISIONED_SEAWEEDFS=0

case "${BACKEND}" in
    gcs)
        # GCS preflight (no auto-provision; soak is real-cloud).
        if [ -z "${ATTESTA_TEST_GCS_BUCKET:-}" ]; then
            echo "FATAL: ATTESTA_TEST_GCS_BUCKET not set (backend=gcs)"
            echo
            echo "  export ATTESTA_TEST_GCS_BUCKET=<your-bucket>"
            echo "  OR  export ATTESTA_SOAK_BYTESTORE_BACKEND=seaweedfs"
            exit 1
        fi
        if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ ! -r "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
            echo "FATAL: GOOGLE_APPLICATION_CREDENTIALS points at unreadable file:"
            echo "       ${GOOGLE_APPLICATION_CREDENTIALS}"
            exit 1
        fi
        ;;

    seaweedfs)
        # Auto-provision SeaweedFS via Docker, then route the soak's
        # bytestore through the bytestore.S3 adapter at the local
        # SeaweedFS endpoint.
        if ! command -v docker >/dev/null 2>&1; then
            echo "FATAL: backend=seaweedfs requires Docker (not on PATH)"
            exit 1
        fi
        echo "== ATTESTA_SOAK_BYTESTORE_BACKEND=seaweedfs — provisioning SeaweedFS in Docker =="
        docker compose -f "${COMPOSE_FILE}" up -d seaweedfs

        echo "== waiting for SeaweedFS S3 endpoint =="
        SW_READY=0
        for i in $(seq 1 60); do
            # weed mini exposes the S3 listener once the master + volume
            # come up. Anonymous root request returns 403 (AccessDenied);
            # any HTTP response code from the server proves the listener
            # is alive. NOTE: do NOT use `curl -f` here — it makes curl
            # exit non-zero on HTTP 4xx, which breaks the format-string
            # capture below (a 403 listener-up state would be
            # mis-classified as "not ready").
            HTTP_CODE=$(curl -sS --max-time 2 -o /dev/null \
                -w "%{http_code}" "http://localhost:8333/" 2>/dev/null \
                || echo "000")
            if echo "${HTTP_CODE}" | grep -qE "^[234][0-9]{2}$"; then
                echo "SeaweedFS ready (attempt ${i}, http=${HTTP_CODE})"
                SW_READY=1
                break
            fi
            sleep 1
        done
        if [ "${SW_READY}" -ne 1 ]; then
            echo "FATAL: SeaweedFS did not become ready within 60s"
            echo "       check: docker logs attesta_test_seaweedfs"
            exit 1
        fi

        # Bucket is auto-created by the seaweedfs container's S3_BUCKET
        # env var (see compose file). The credentials match.
        export ATTESTA_SOAK_BYTESTORE_BACKEND=s3
        export ATTESTA_TEST_S3_BUCKET="attesta-test-seaweed"
        export ATTESTA_TEST_S3_ENDPOINT="http://localhost:8333"
        export ATTESTA_TEST_S3_ACCESS_KEY="seaweedadmin"
        export ATTESTA_TEST_S3_SECRET_KEY="seaweedsecret"
        # SeaweedFS uses path-style addressing; explicit so a future
        # ATTESTA_TEST_S3_PATH_STYLE=false override doesn't surprise.
        unset ATTESTA_TEST_S3_PATH_STYLE
        PROVISIONED_SEAWEEDFS=1
        echo "   ATTESTA_TEST_S3_ENDPOINT=${ATTESTA_TEST_S3_ENDPOINT}"
        echo "   ATTESTA_TEST_S3_BUCKET=${ATTESTA_TEST_S3_BUCKET}"
        echo "   (tear down with: ./scripts/run-soak.sh down)"
        ;;

    s3)
        # User-supplied S3 (e.g. real AWS, R2, MinIO they manage).
        # We don't auto-provision; we just validate the env vars.
        if [ -z "${ATTESTA_TEST_S3_BUCKET:-}" ]; then
            echo "FATAL: ATTESTA_TEST_S3_BUCKET not set (backend=s3)"
            exit 1
        fi
        if [ -z "${ATTESTA_TEST_S3_ENDPOINT:-}" ]; then
            echo "WARN: ATTESTA_TEST_S3_ENDPOINT not set; defaulting to AWS S3 region endpoint"
        fi
        ;;

    *)
        echo "FATAL: ATTESTA_SOAK_BYTESTORE_BACKEND=${BACKEND} unsupported"
        echo "       Supported: gcs (default) | seaweedfs (local docker) | s3 (BYO)"
        exit 1
        ;;
esac

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
SHIPPER_MAX_IN_FLIGHT="${ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT:-16}"
DRAIN_TIMEOUT="${ATTESTA_SOAK_DRAIN_TIMEOUT:-10m}"
TEST_TIMEOUT="${ATTESTA_SOAK_TEST_TIMEOUT:-30m}"

# Both knobs are surfaced as env vars so the test process can pick
# them up via os.Getenv. Re-export to be safe even if the caller
# only set them in the script's local scope.
export ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT="${SHIPPER_MAX_IN_FLIGHT}"
export ATTESTA_SOAK_DRAIN_TIMEOUT="${DRAIN_TIMEOUT}"

if [ "${PROVISIONED_PG}" -eq 1 ]; then
    DSN_SOURCE="docker (auto-provisioned)"
else
    DSN_SOURCE="env ATTESTA_TEST_DSN"
fi

# Bytestore banner. After the case-block above, the env vars the soak
# reads are already routed to the right backend. We display the
# user-facing source so it's obvious what's about to be exercised.
if [ "${PROVISIONED_SEAWEEDFS}" -eq 1 ]; then
    BS_SOURCE="seaweedfs (auto-provisioned in docker)"
    BS_TARGET="${ATTESTA_TEST_S3_ENDPOINT}/${ATTESTA_TEST_S3_BUCKET}"
    BS_CREDS="${ATTESTA_TEST_S3_ACCESS_KEY}/...  (static, from compose)"
elif [ "${BACKEND}" = "s3" ]; then
    BS_SOURCE="s3 (env ATTESTA_TEST_S3_*)"
    BS_TARGET="${ATTESTA_TEST_S3_ENDPOINT:-aws}/${ATTESTA_TEST_S3_BUCKET}"
    BS_CREDS="${ATTESTA_TEST_S3_ACCESS_KEY:-(default credential chain)}"
else
    BS_SOURCE="gcs"
    BS_TARGET="${ATTESTA_TEST_GCS_BUCKET}"
    BS_CREDS="${GOOGLE_APPLICATION_CREDENTIALS:-(workload identity / gcloud ADC)}"
fi

echo "== attesta ledger soak =="
echo "   dsn source:        ${DSN_SOURCE}"
echo "   bytestore source:  ${BS_SOURCE}"
echo "   bytestore target:  ${BS_TARGET}"
echo "   bytestore creds:   ${BS_CREDS}"
echo "   entries:           ${ENTRIES}"
echo "   concurrency:       ${CONCURRENCY}        (submitter goroutines)"
echo "   shipper workers:   ${SHIPPER_MAX_IN_FLIGHT}        (parallel uploads)"
echo "   verify:            ${SAMPLES}"
echo "   p99 bound ms:      ${P99_BOUND_MS}"
echo "   drain timeout:     ${DRAIN_TIMEOUT}        (in-test wait for HWM)"
echo "   test timeout:      ${TEST_TIMEOUT}        (go test process ceiling)"
echo

START_NS=$(date +%s%N)

# Test process timeout. Should comfortably exceed expected
# submission-time + drain-time. Defaults to 30m for the legacy 1M
# soak; bump via ATTESTA_SOAK_TEST_TIMEOUT for higher-volume runs.
go test -tags=soak \
    -count=1 \
    -timeout "${TEST_TIMEOUT}" \
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
