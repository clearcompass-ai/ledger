#!/bin/bash
# scripts/run-gcs-tests.sh
#
# Runs the Phase 2 GCS byte-store tests against the
# fake-gcs-server in docker-compose. Same readiness pattern as
# run-cursor-tests.sh — waits for both container readiness and
# host port reachability before invoking go test.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/integration/docker-compose.yml"

if [ "${1:-}" = "down" ]; then
    docker compose -f "${COMPOSE_FILE}" down -v
    exit 0
fi

cd "${REPO_ROOT}"

echo "== bringing up integration docker-compose =="
docker compose -f "${COMPOSE_FILE}" up -d

echo "== waiting for fake-gcs container readiness =="
for i in $(seq 1 60); do
    # fake-gcs-server has its own healthcheck — wait for it to
    # report healthy via docker.
    health="$(docker inspect --format='{{.State.Health.Status}}' ortholog_test_gcs 2>/dev/null || true)"
    if [ "${health}" = "healthy" ]; then
        echo "fake-gcs container healthy (attempt ${i})"
        break
    fi
    if [ "$i" = "60" ]; then
        echo "FATAL: fake-gcs not healthy within 60s (status: ${health})"
        exit 1
    fi
    sleep 1
done

echo "== waiting for host-side port 4443 to accept connections =="
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 4443 2>/dev/null; then
        echo "host port 4443 reachable (attempt ${i})"
        break
    fi
    if [ "$i" = "60" ]; then
        echo "FATAL: host port 4443 not reachable within 60s"
        exit 1
    fi
    sleep 1
done

echo "== exporting test env =="
export ORTHOLOG_TEST_GCS_ENDPOINT='http://127.0.0.1:4443/storage/v1/'
export ORTHOLOG_TEST_GCS_BUCKET='ortholog-test-bytes'

echo "== running GCS entry-store tests =="
go test -v -count=1 -timeout=120s \
    -run 'TestGCSEntryStore' \
    ./tessera/

echo
echo "== done — to tear down: ./scripts/run-gcs-tests.sh down =="
