#!/bin/bash
# scripts/run-cursor-tests.sh
#
# Runs the Phase 1A cursor tests against the integration
# docker-compose harness. Self-contained — brings up the harness,
# waits for BOTH the container's pg_isready AND the host's port
# 5544 to actually accept connections (Docker Desktop on macOS
# has a known race between container readiness and host port
# forwarding readiness), then runs the test subset.
#
# Usage:
#   ./scripts/run-cursor-tests.sh
#
# The DSN below uses the keyword/value form (no `@` symbol) to
# avoid the "auto-link bites a pasted command" failure mode.
# Pgx accepts this form via pgconn.ParseConfig; same connection
# parameters as the URL form, just different syntax.
#
# Tear-down: ./scripts/run-cursor-tests.sh down

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/integration/docker-compose.yml"

# Tear-down mode.
if [ "${1:-}" = "down" ]; then
    echo "tearing down docker-compose..."
    docker compose -f "${COMPOSE_FILE}" down -v
    exit 0
fi

cd "${REPO_ROOT}"

echo "== bringing up integration docker-compose =="
docker compose -f "${COMPOSE_FILE}" up -d

echo "== waiting for postgres container readiness (pg_isready inside container) =="
for i in $(seq 1 60); do
    if docker exec ortholog_test_postgres pg_isready -U ortholog -d ortholog_test >/dev/null 2>&1; then
        echo "postgres container ready (attempt ${i})"
        break
    fi
    if [ "$i" = "60" ]; then
        echo "FATAL: postgres container did not become ready within 60s"
        exit 1
    fi
    sleep 1
done

echo "== waiting for host-side port 5544 to accept connections =="
# Docker Desktop on macOS sometimes lags between container-up
# and host-side port forwarding. nc -z hits the host TCP stack
# directly so we know go test will actually be able to connect.
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 5544 2>/dev/null; then
        echo "host port 5544 reachable (attempt ${i})"
        break
    fi
    if [ "$i" = "60" ]; then
        echo "FATAL: host port 5544 not reachable within 60s"
        echo "Check: docker compose ps"
        echo "       docker logs ortholog_test_postgres"
        exit 1
    fi
    sleep 1
done

echo "== exporting test env =="
# Keyword/value DSN — no @ symbol, no URL-shaped strings, so a
# terminal autolinker (paste-time markdown rewrite) cannot
# transform the string into something pgx fails to parse.
# Pgx accepts this exact format via pgconn.ParseConfig.
export ORTHOLOG_TEST_DSN='host=127.0.0.1 port=5544 user=ortholog password=ortholog dbname=ortholog_test sslmode=disable'
export ORTHOLOG_TEST_GCS_ENDPOINT='http://127.0.0.1:4443/storage/v1/'
export ORTHOLOG_TEST_GCS_BUCKET='ortholog-test-bytes'

echo "DSN length: ${#ORTHOLOG_TEST_DSN} chars (sanity: ~96 expected)"

echo "== running cursor + sequence tests =="
go test -v -count=1 -p 1 -timeout=120s \
    -run 'TestSequenceCursor|TestCursorReader' \
    ./store/ ./builder/

echo
echo "== done — to tear down: ./scripts/run-cursor-tests.sh down =="
