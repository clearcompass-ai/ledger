#!/bin/bash
# scripts/run-gcs-tests-real.sh
#
# Runs the GCS entry-store tests against a REAL GCS bucket (not
# fake-gcs-server). Use this to validate the production code path
# end-to-end against actual Google Cloud Storage.
#
# Required env:
#   ORTHOLOG_REAL_GCS_BUCKET   the bucket name (REQUIRED)
#   GOOGLE_APPLICATION_CREDENTIALS  path to a service-account key
#                                   file that grants the test
#                                   identity:
#                                     - storage.objects.create
#                                     - storage.objects.get
#                                     - storage.objects.list
#                                     - storage.objects.delete
#                                   on $ORTHOLOG_REAL_GCS_BUCKET.
#
# Or set GOOGLE_APPLICATION_CREDENTIALS to a JSON key, OR run on
# GCE/GKE with workload identity, OR have `gcloud auth
# application-default login` configured.
#
# Usage:
#   export ORTHOLOG_REAL_GCS_BUCKET=my-test-bucket
#   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
#   ./scripts/run-gcs-tests-real.sh
#
# This script does NOT start docker-compose — it talks directly to
# real GCS. Each test creates a unique prefix
# (test/<TestName>/<unix-nano>) and t.Cleanup deletes everything
# under that prefix at test end, so repeated runs don't accumulate
# junk in your bucket.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# ── Validate inputs ───────────────────────────────────────────────
if [ -z "${ORTHOLOG_REAL_GCS_BUCKET:-}" ]; then
    echo "FATAL: ORTHOLOG_REAL_GCS_BUCKET not set"
    echo
    echo "  export ORTHOLOG_REAL_GCS_BUCKET=<your-bucket-name>"
    echo "  $0"
    exit 1
fi

# Either GOOGLE_APPLICATION_CREDENTIALS or workload identity must
# be in place. We can't easily check workload identity from a
# shell script (it surfaces only at SDK call time), but we CAN
# warn if neither GOOGLE_APPLICATION_CREDENTIALS nor a default
# gcloud config exists.
if [ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]; then
    if ! command -v gcloud >/dev/null 2>&1 || ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
        echo "WARNING: GOOGLE_APPLICATION_CREDENTIALS unset and no gcloud ADC detected."
        echo "         Tests will fail with auth errors unless you're running on"
        echo "         GCE/GKE with workload identity."
        echo
    fi
fi

# Sanity: confirm GOOGLE_APPLICATION_CREDENTIALS, if set, points at
# a readable file. Catches the typo case before tests waste time
# retrying.
if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]; then
    if [ ! -r "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
        echo "FATAL: GOOGLE_APPLICATION_CREDENTIALS points at unreadable file:"
        echo "       ${GOOGLE_APPLICATION_CREDENTIALS}"
        exit 1
    fi
fi

echo "== running GCS entry-store tests against REAL GCS =="
echo "   bucket: ${ORTHOLOG_REAL_GCS_BUCKET}"
echo "   creds:  ${GOOGLE_APPLICATION_CREDENTIALS:-(workload identity / gcloud ADC)}"
echo

# Real-mode signal: ORTHOLOG_TEST_GCS_BUCKET set, ENDPOINT unset.
# requireGCS detects this and uses ADC instead of anonymous auth.
unset ORTHOLOG_TEST_GCS_ENDPOINT
export ORTHOLOG_TEST_GCS_BUCKET="${ORTHOLOG_REAL_GCS_BUCKET}"

# Slightly longer timeout than the fake-gcs run — real GCS calls
# are network-bound and a cold-start ADC token fetch can spike
# latency on the first request.
go test -v -count=1 -timeout=300s \
    -run 'TestGCS_' \
    ./bytestore/

echo
echo "== done =="
echo
echo "Cleanup verification: list any leftover objects under test/ in your bucket"
echo "(should be empty after t.Cleanup ran):"
echo
echo "  gsutil ls 'gs://${ORTHOLOG_REAL_GCS_BUCKET}/test/**' || echo '(no leftovers — good)'"
