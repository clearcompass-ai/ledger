#!/bin/bash
# scripts/run-soak.sh
#
# Runs the build-tag-isolated operator soak test (tests/soak_test.go).
# Default: 1M entries against real GCS, ~3 min sustained throughput.
# Lower the count via ORTHOLOG_SOAK_ENTRIES for quick iteration.
#
# Required env:
#   ORTHOLOG_TEST_DSN              postgres connection string (REQUIRED)
#   ORTHOLOG_TEST_GCS_BUCKET       real GCS bucket name (REQUIRED)
#   GOOGLE_APPLICATION_CREDENTIALS path to a service-account key with
#                                  storage.objects.{create,get,list,delete}
#                                  on the bucket (or workload identity)
#
# Optional knobs (env, with defaults):
#   ORTHOLOG_SOAK_ENTRIES          1000000   total entries to submit
#   ORTHOLOG_SOAK_CONCURRENCY      8         concurrent submitter goroutines
#   ORTHOLOG_SOAK_VERIFY_SAMPLES   100       random subset to verify via /raw
#   ORTHOLOG_SOAK_P99_BOUND_MS     100       admission p99 ceiling
#
# Usage:
#   export ORTHOLOG_TEST_DSN=postgres://...
#   export ORTHOLOG_TEST_GCS_BUCKET=ortholog-soak
#   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
#   ./scripts/run-soak.sh
#
# Or scale down for a quick run:
#   ORTHOLOG_SOAK_ENTRIES=10000 ORTHOLOG_SOAK_VERIFY_SAMPLES=20 \
#     ./scripts/run-soak.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# ── Validate inputs ───────────────────────────────────────────────
if [ -z "${ORTHOLOG_TEST_DSN:-}" ]; then
    echo "FATAL: ORTHOLOG_TEST_DSN not set"
    echo
    echo "  export ORTHOLOG_TEST_DSN=postgres://user:pw@host/db"
    exit 1
fi

if [ -z "${ORTHOLOG_TEST_GCS_BUCKET:-}" ]; then
    echo "FATAL: ORTHOLOG_TEST_GCS_BUCKET not set"
    echo
    echo "  export ORTHOLOG_TEST_GCS_BUCKET=<your-bucket>"
    exit 1
fi

if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ ! -r "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
    echo "FATAL: GOOGLE_APPLICATION_CREDENTIALS points at unreadable file:"
    echo "       ${GOOGLE_APPLICATION_CREDENTIALS}"
    exit 1
fi

# Soak runs against REAL GCS — explicitly clear any container-mode signal
# the test harness might pick up.
unset ORTHOLOG_TEST_GCS_ENDPOINT

ENTRIES="${ORTHOLOG_SOAK_ENTRIES:-1000000}"
CONCURRENCY="${ORTHOLOG_SOAK_CONCURRENCY:-8}"
SAMPLES="${ORTHOLOG_SOAK_VERIFY_SAMPLES:-100}"
P99_BOUND_MS="${ORTHOLOG_SOAK_P99_BOUND_MS:-100}"

echo "== ortholog operator soak =="
echo "   dsn:          (set, omitted)"
echo "   bucket:       ${ORTHOLOG_TEST_GCS_BUCKET}"
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
  "bucket":             "${ORTHOLOG_TEST_GCS_BUCKET}",
  "test_status":        "ok"
}
EOF

echo
echo "Cleanup verification: leftover soak objects under your bucket?"
echo "  gsutil ls 'gs://${ORTHOLOG_TEST_GCS_BUCKET}/soak/**' || echo '(none)'"
