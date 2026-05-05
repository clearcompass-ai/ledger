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
COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.testharness.yml"

# Tear-down mode.
if [ "${1:-}" = "down" ]; then
    echo "tearing down docker-compose..."
    docker compose -f "${COMPOSE_FILE}" down -v
    exit 0
fi

cd "${REPO_ROOT}"

echo "== tearing down any prior stack (force-clear anonymous volumes) =="
# Postgres's official image declares VOLUME ["/var/lib/postgresql/data"]
# in its Dockerfile. Without an explicit `volumes:` in our
# compose, Docker creates an anonymous volume to back it. That
# volume survives `docker compose up -d --force-recreate` because
# anonymous volumes are not pruned on container recreation.
#
# Postgres initializes the database (creating POSTGRES_DB,
# POSTGRES_USER, etc.) only on first boot when the data dir is
# empty. So if a prior run left behind a populated data volume,
# the new container reuses it and skips init — the result is
# tests that fail with "database \"attesta_test\" does not exist".
#
# `down -v` removes anonymous volumes, guaranteeing a clean slate
# every run. Cheap (postgres init takes ~2s) and idempotent.
docker compose -f "${COMPOSE_FILE}" down -v 2>/dev/null || true

echo "== bringing up integration docker-compose =="
docker compose -f "${COMPOSE_FILE}" up -d

echo "== waiting for postgres container readiness (pg_isready inside container) =="
for i in $(seq 1 60); do
    if docker exec attesta_test_postgres pg_isready -U attesta -d attesta_test >/dev/null 2>&1; then
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
        echo "       docker logs attesta_test_postgres"
        exit 1
    fi
    sleep 1
done

echo "== exporting test env =="
# Keyword/value DSN — no @ symbol, no URL-shaped strings, so a
# terminal autolinker (paste-time markdown rewrite) cannot
# transform the string into something pgx fails to parse.
# Pgx accepts this exact format via pgconn.ParseConfig.
export ATTESTA_TEST_DSN='host=127.0.0.1 port=5544 user=attesta password=attesta dbname=attesta_test sslmode=disable'
export ATTESTA_TEST_GCS_ENDPOINT='http://127.0.0.1:4443/storage/v1/'
export ATTESTA_TEST_GCS_BUCKET='attesta-test-bytes'

echo "DSN length: ${#ATTESTA_TEST_DSN} chars (sanity: ~96 expected)"

echo "== running cursor + sequence tests =="
go test -v -count=1 -p 1 -timeout=120s \
    -run 'TestSequenceCursor|TestCursorReader' \
    ./store/ ./builder/

echo
echo "== done — to tear down: ./scripts/run-cursor-tests.sh down =="
