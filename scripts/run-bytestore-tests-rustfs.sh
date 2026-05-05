#!/bin/bash
# scripts/run-bytestore-tests-rustfs.sh
#
# Runs the bytestore.S3 adapter test suite against the docker-compose
# RustFS container. Mirrors run-gcs-tests.sh for the GCS adapter.
#
# Usage:
#   docker compose -f scripts/local/docker-compose.testharness.yml up -d rustfs rustfs-init
#   ./scripts/run-bytestore-tests-rustfs.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.testharness.yml"

# Wait for RustFS ready.
echo "== ensuring rustfs is up =="
docker compose -f "${COMPOSE_FILE}" up -d rustfs rustfs-init

for i in $(seq 1 30); do
    health="$(docker inspect --format='{{.State.Health.Status}}' attesta_test_rustfs 2>/dev/null || true)"
    if [ "${health}" = "healthy" ]; then
        echo "rustfs healthy (attempt ${i})"
        break
    fi
    sleep 1
done

# Wait for the bucket-init job to complete (it exits 0 on success).
for i in $(seq 1 30); do
    status="$(docker inspect --format='{{.State.Status}}' attesta_test_rustfs_init 2>/dev/null || true)"
    exitcode="$(docker inspect --format='{{.State.ExitCode}}' attesta_test_rustfs_init 2>/dev/null || echo -1)"
    if [ "${status}" = "exited" ] && [ "${exitcode}" = "0" ]; then
        echo "bucket ready (attempt ${i})"
        break
    fi
    sleep 1
done

# Wait for host port reachability.
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 9000 2>/dev/null; then break; fi
    sleep 1
done

echo "== running bytestore S3 tests against RustFS =="
export ATTESTA_TEST_S3_ENDPOINT='http://127.0.0.1:9000'
export ATTESTA_TEST_S3_BUCKET='attesta-test-bytes'
export ATTESTA_TEST_S3_ACCESS_KEY='rustfsadmin'
export ATTESTA_TEST_S3_SECRET_KEY='rustfsadmin'
export ATTESTA_TEST_S3_PATH_STYLE='true'

go test -v -count=1 -timeout=120s -run 'TestS3_|TestConformance_S3_' ./bytestore/

echo
echo "== done =="
echo "to tear down:  docker compose -f scripts/local/docker-compose.testharness.yml down -v"
