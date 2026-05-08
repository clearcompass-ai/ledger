#!/bin/bash
# scripts/run-p4.sh
#
# Runs the build-tag-isolated P4 production-realism + chaos test
# suite (tests/p4/, build tag `p4`).
#
# P4 tests are scenario-shaped — each test case asserts ONE
# production invariant under realistic load + adversarial conditions:
#
#   P4.2  advisory-lock split-brain   (THIS RUN)
#   P4.3  2-replica failover          (later commit)
#   P4.4  witness offline matrix      (later commit; awaits Backpressure
#                                       Stall implementation)
#   P4.5  cryptographic integrity master (later commit)
#   P4.1  multi-persona concurrent load (later commit)
#
# ── Postgres ─────────────────────────────────────────────────────────
#   If ATTESTA_TEST_DSN is set, that DSN is used as-is (no docker).
#   If unset, this script auto-provisions Postgres in Docker using the
#   same compose file as scripts/run-local.sh and exports the canonical
#   testharness DSN. Tear down with `./scripts/run-p4.sh down`.
#
# ── Run knobs (env, with defaults) ──────────────────────────────────
#   ATTESTA_P4_TEST_TIMEOUT          5m       go test process ceiling
#   ATTESTA_P4_RUN                   ""       -run filter (default: all P4 tests)
#   ATTESTA_P4_VERBOSE               1        passes -v to go test (default on)
#
# Quick start:
#
#   ./scripts/run-p4.sh
#
# With an existing Postgres:
#
#   export ATTESTA_TEST_DSN=postgres://user:pw@host/db
#   ./scripts/run-p4.sh
#
# Run a single matrix cell:
#
#   ATTESTA_P4_RUN=TestP4_AdvisoryLock_HandoffSequence ./scripts/run-p4.sh
#
# Tear down auto-provisioned containers:
#
#   ./scripts/run-p4.sh down

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.testharness.yml"
# Canonical testharness DSN — same as scripts/run-soak.sh + run-local.sh
# so dev / soak / p4 share one Postgres when not running concurrently.
DOCKER_DSN="postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable"

case "${1:-}" in
    down)
        echo "== tearing down testharness (postgres etc.) =="
        docker compose -f "${COMPOSE_FILE}" down -v
        exit 0
        ;;
esac

cd "${REPO_ROOT}"

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
    echo "   (tear down with: ./scripts/run-p4.sh down)"
fi

TEST_TIMEOUT="${ATTESTA_P4_TEST_TIMEOUT:-5m}"
RUN_FILTER="${ATTESTA_P4_RUN:-}"
VERBOSE="${ATTESTA_P4_VERBOSE:-1}"

if [ "${PROVISIONED_PG}" -eq 1 ]; then
    DSN_SOURCE="docker (auto-provisioned)"
else
    DSN_SOURCE="env ATTESTA_TEST_DSN"
fi

echo
echo "== attesta ledger P4 (production-realism + chaos) =="
echo "   dsn source:   ${DSN_SOURCE}"
echo "   test timeout: ${TEST_TIMEOUT}"
if [ -n "${RUN_FILTER}" ]; then
    echo "   run filter:   ${RUN_FILTER}"
fi
echo

GO_TEST_FLAGS=(
    -tags=p4
    -count=1
    -timeout "${TEST_TIMEOUT}"
)
if [ "${VERBOSE}" = "1" ]; then
    GO_TEST_FLAGS+=(-v)
fi
if [ -n "${RUN_FILTER}" ]; then
    GO_TEST_FLAGS+=(-run "${RUN_FILTER}")
fi

START_NS=$(date +%s%N)

go test "${GO_TEST_FLAGS[@]}" ./tests/p4/

END_NS=$(date +%s%N)
ELAPSED_S=$(( (END_NS - START_NS) / 1000000000 ))

echo
echo "== P4 summary =="
cat <<EOF
{
  "wall_clock_seconds":  ${ELAPSED_S},
  "dsn_source":          "${DSN_SOURCE}",
  "test_status":         "ok"
}
EOF

if [ "${PROVISIONED_PG}" -eq 1 ]; then
    echo
    echo "Postgres still running. Tear down when finished:"
    echo "  ./scripts/run-p4.sh down"
fi
