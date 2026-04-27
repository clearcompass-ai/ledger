#!/bin/bash
# scripts/run-bytestore-tests-real-s3.sh
#
# Runs the bytestore.S3 adapter test suite against a REAL AWS S3
# bucket. Use this to validate the production code path end-to-end
# against actual AWS S3 (parallel to run-gcs-tests-real.sh for GCS).
#
# Required env:
#   ORTHOLOG_REAL_S3_BUCKET   the bucket name (REQUIRED)
#   AWS_REGION                the bucket's region (e.g. us-east-1)
#   AWS_ACCESS_KEY_ID         OR an IAM role / instance profile / SSO
#   AWS_SECRET_ACCESS_KEY     credentials chain in scope
#
# The credentials must grant: s3:PutObject, s3:GetObject, s3:DeleteObject,
# s3:ListBucket on $ORTHOLOG_REAL_S3_BUCKET.
#
# Usage:
#   export ORTHOLOG_REAL_S3_BUCKET=my-test-bucket
#   export AWS_REGION=us-east-1
#   export AWS_ACCESS_KEY_ID=...
#   export AWS_SECRET_ACCESS_KEY=...
#   ./scripts/run-bytestore-tests-real-s3.sh
#
# This script does NOT start docker-compose — it talks directly to
# real AWS S3. Each test creates a unique prefix
# (test/<TestName>/<unix-nano>) and t.Cleanup deletes everything
# under that prefix at test end, so repeated runs don't accumulate
# junk in your bucket.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# ── Validate inputs ───────────────────────────────────────────────
if [ -z "${ORTHOLOG_REAL_S3_BUCKET:-}" ]; then
    echo "FATAL: ORTHOLOG_REAL_S3_BUCKET not set"
    echo
    echo "  export ORTHOLOG_REAL_S3_BUCKET=<your-bucket-name>"
    echo "  $0"
    exit 1
fi

if [ -z "${AWS_REGION:-}" ] && [ -z "${AWS_DEFAULT_REGION:-}" ]; then
    echo "FATAL: AWS_REGION (or AWS_DEFAULT_REGION) not set"
    echo "       AWS S3 requires a region for bucket addressing."
    exit 1
fi

if [ -z "${AWS_ACCESS_KEY_ID:-}" ] && [ -z "${AWS_PROFILE:-}" ] && [ ! -f ~/.aws/credentials ]; then
    echo "WARNING: no AWS_ACCESS_KEY_ID, AWS_PROFILE, or ~/.aws/credentials in scope."
    echo "         Tests will fail with auth errors unless you're running on EC2/EKS"
    echo "         with an instance-profile / IRSA role attached."
    echo
fi

echo "== running bytestore S3 tests against REAL AWS S3 =="
echo "   bucket: ${ORTHOLOG_REAL_S3_BUCKET}"
echo "   region: ${AWS_REGION:-${AWS_DEFAULT_REGION}}"
echo

# Real-S3 mode signal: ORTHOLOG_TEST_S3_REAL=1.
# requireS3 detects this and uses default credential chain + virtual-host URLs.
unset ORTHOLOG_TEST_S3_ENDPOINT
unset ORTHOLOG_TEST_S3_PATH_STYLE
export ORTHOLOG_TEST_S3_REAL=1
export ORTHOLOG_TEST_S3_BUCKET="${ORTHOLOG_REAL_S3_BUCKET}"
export ORTHOLOG_TEST_S3_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION}}"

# 5-minute timeout — real S3 cold-start credential discovery + cross-
# region writes can spike latency on the first request.
go test -v -count=1 -timeout=300s -run 'TestS3_' ./bytestore/

echo
echo "== done =="
echo
echo "Cleanup verification: list any leftover objects under test/ in your bucket"
echo "(should be empty after t.Cleanup ran):"
echo
echo "  aws s3 ls s3://${ORTHOLOG_REAL_S3_BUCKET}/test/ --recursive || echo '(no leftovers — good)'"
