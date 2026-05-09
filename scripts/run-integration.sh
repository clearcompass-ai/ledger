#!/bin/bash
# scripts/run-integration.sh
#
# Canonical runner for the integration/ test suite. Owns the
# Docker compose lifecycle (Postgres on the testharness compose
# file) and runs `go test -tags=integration -count=1` against
# integration/ + the standalone-witness daemon e2e.
#
# Why this exists:
#   integration/ tests carry //go:build integration so they are
#   invisible to standard `go test ./...`. A developer typing
#   plain `go test` on a laptop without Docker should NOT see
#   a wall of red Postgres-connection errors. The build tag
#   keeps fast feedback fast; this script is the explicit opt-in
#   for the slow, infra-dependent tests.
#
# Usage:
#   ./scripts/run-integration.sh             # boot + run + leave up
#   ./scripts/run-integration.sh down        # tear down Docker
#   ./scripts/run-integration.sh --teardown  # boot + run + tear down
#
# Verified: every test under integration/ + the standalone-witness
# daemon-exec test runs once with -count=1 to defeat go-test caching.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.testharness.yml"
DOCKER_DSN="postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable"

case "${1:-}" in
    down)
        echo "== tearing down testharness postgres =="
        docker compose -f "${COMPOSE_FILE}" down -v
        exit 0
        ;;
esac

TEARDOWN=0
if [ "${1:-}" = "--teardown" ]; then
    TEARDOWN=1
fi

cd "${REPO_ROOT}"

# ── Postgres provisioning ────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    cat <<'ERR' >&2
FATAL: `docker` CLI not found on PATH. The integration/ test
suite requires a running Postgres reached at the canonical
testharness DSN. Either install Docker or supply the DSN
externally:

  export ATTESTA_TEST_DSN=postgres://user:pw@host/db
  go test -tags=integration -count=1 ./integration/

Then skip this script.
ERR
    exit 1
fi

echo "== bringing up postgres (testharness) =="
docker compose -f "${COMPOSE_FILE}" up -d postgres

echo "== waiting for postgres readiness =="
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
    echo "FATAL: postgres did not become ready within 30s" >&2
    echo "       check: docker logs attesta_test_postgres" >&2
    exit 1
fi

export ATTESTA_TEST_DSN="${ATTESTA_TEST_DSN:-${DOCKER_DSN}}"

# ── Run integration tests ───────────────────────────────────────
echo
echo "== running integration tests =="
echo "   ATTESTA_TEST_DSN=${ATTESTA_TEST_DSN}"
echo

START_NS=$(date +%s%N)

# Two test targets:
#   1. integration/ — Ledger's HTTP-driven tests (`integration` tag).
#   2. cmd/standalone-witness/tests/ — daemon binary e2e (no tag,
#      gated by testing.Short() instead). Runs because we don't
#      pass -short.
RC=0
go test -tags=integration -count=1 -v ./integration/ || RC=$?
echo
echo "== running standalone-witness daemon e2e =="
( cd cmd/standalone-witness && go test -count=1 -v ./tests/ ) || RC=$?

END_NS=$(date +%s%N)
ELAPSED_S=$(( (END_NS - START_NS) / 1000000000 ))

echo
echo "== integration summary =="
cat <<EOF
{
  "wall_clock_seconds":  ${ELAPSED_S},
  "exit_status":         ${RC}
}
EOF

if [ "${TEARDOWN}" = "1" ]; then
    echo
    echo "== tearing down testharness =="
    docker compose -f "${COMPOSE_FILE}" down -v
else
    echo
    echo "Postgres still running. Tear down when finished:"
    echo "  ./scripts/run-integration.sh down"
fi

exit ${RC}
