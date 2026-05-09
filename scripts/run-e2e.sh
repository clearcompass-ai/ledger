#!/bin/bash
# scripts/run-e2e.sh
#
# End-to-end test runner. Provisions the e2e topology
# (postgres + standalone-witness daemon) via docker compose,
# generates witness keys + network bootstrap on the host (bind-
# mounted into the witness container), and runs the e2e test
# suite against the live containerized stack.
#
# WHAT MAKES THIS "E2E" VS RUN-INTEGRATION
#
#   run-integration.sh  → postgres only; tests use in-process
#                          httptest cosign servers.
#   run-e2e.sh          → postgres + WITNESS DAEMON CONTAINER.
#                          Tests POST cosign requests over real
#                          docker bridge HTTP. Proves the binary
#                          ships, runs, and accepts traffic from
#                          outside its own process.
#
# Build tag: same `integration` tag as run-integration.sh — the
# tests skip cleanly when WITNESS_URL is unset, so this script
# both opts in and provides the URL.
#
# Usage:
#   ./scripts/run-e2e.sh               boot + run + leave up
#   ./scripts/run-e2e.sh --teardown    boot + run + tear down on success
#   ./scripts/run-e2e.sh down          tear down only
#   ./scripts/run-e2e.sh clean         wipe .run/e2e/ then proceed
#
# On test failure the topology is LEFT UP regardless so logs are
# inspectable via `docker compose -f scripts/local/docker-compose.e2e.yml logs witness`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.e2e.yml"
KEYS_DIR="${REPO_ROOT}/.run/e2e"
DOCKER_DSN="postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable"
WITNESS_URL_DEFAULT="http://localhost:8081"

# ── Parse args ────────────────────────────────────────────────────
TEARDOWN=0
CLEAN=0
SUBCMD="run"
for arg in "$@"; do
    case "${arg}" in
        down)
            SUBCMD="down"
            ;;
        clean)
            CLEAN=1
            ;;
        --teardown)
            TEARDOWN=1
            ;;
        -h|--help)
            sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument: ${arg}" >&2
            exit 2
            ;;
    esac
done

# ── Tear-down ────────────────────────────────────────────────────
if [ "${SUBCMD}" = "down" ]; then
    echo "== tearing down e2e topology =="
    docker compose -f "${COMPOSE_FILE}" down -v
    exit 0
fi

cd "${REPO_ROOT}"

if [ "${CLEAN}" = "1" ]; then
    echo "== wiping ${KEYS_DIR} =="
    rm -rf "${KEYS_DIR}"
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "FATAL: docker CLI not found on PATH" >&2
    exit 1
fi

# ── Generate witness keys + network bootstrap on host ─────────────
# These files are bind-mounted into the witness container at
# /keys/. The witness daemon reads them at boot.
echo "== generating witness key + network bootstrap (.run/e2e/) =="
mkdir -p "${KEYS_DIR}"
go run ./cmd/init-network \
    -out-dir="${KEYS_DIR}" \
    -out-bootstrap="${KEYS_DIR}/network-bootstrap.json" \
    -log-did="did:attesta:ledger:e2e" \
    -network-name="e2e-test" \
    -witnesses=1

# ── Bring up the e2e stack ───────────────────────────────────────
# E2E_KEYS_DIR is consumed by docker-compose.e2e.yml's bind mount.
export E2E_KEYS_DIR="${KEYS_DIR}"

echo
echo "== building witness container + bringing up topology =="
docker compose -f "${COMPOSE_FILE}" up -d --build

# Wait for both services to report healthy.
echo
echo "== waiting for postgres + witness readiness =="
READY=0
for i in $(seq 1 60); do
    pg_state=$(docker inspect --format='{{.State.Health.Status}}' attesta_e2e_postgres 2>/dev/null || echo "")
    wit_state=$(docker inspect --format='{{.State.Health.Status}}' attesta_e2e_witness 2>/dev/null || echo "")
    if [ "${pg_state}" = "healthy" ] && [ "${wit_state}" = "healthy" ]; then
        echo "ready: postgres + witness (attempt ${i})"
        READY=1
        break
    fi
    sleep 1
done
if [ "${READY}" -ne 1 ]; then
    echo "FATAL: e2e topology did not report healthy in 60s" >&2
    echo "       postgres state: ${pg_state}" >&2
    echo "       witness state:  ${wit_state}" >&2
    echo "       check: docker compose -f ${COMPOSE_FILE} logs" >&2
    exit 1
fi

# ── Run e2e tests ────────────────────────────────────────────────
export ATTESTA_TEST_DSN="${ATTESTA_TEST_DSN:-${DOCKER_DSN}}"
export WITNESS_URL="${WITNESS_URL:-${WITNESS_URL_DEFAULT}}"
export E2E_BOOTSTRAP="${KEYS_DIR}/network-bootstrap.json"

echo
echo "== running e2e tests =="
echo "   ATTESTA_TEST_DSN=${ATTESTA_TEST_DSN}"
echo "   WITNESS_URL=${WITNESS_URL}"
echo "   E2E_BOOTSTRAP=${E2E_BOOTSTRAP}"
echo

START_NS=$(date +%s%N)

RC=0
go test -tags=integration -count=1 -v ./integration/ || RC=$?

END_NS=$(date +%s%N)
ELAPSED_S=$(( (END_NS - START_NS) / 1000000000 ))

echo
echo "== e2e summary =="
cat <<EOF
{
  "wall_clock_seconds": ${ELAPSED_S},
  "exit_status":        ${RC}
}
EOF

if [ "${TEARDOWN}" = "1" ] && [ "${RC}" -eq 0 ]; then
    echo
    echo "== tearing down e2e topology =="
    docker compose -f "${COMPOSE_FILE}" down -v
elif [ "${RC}" -ne 0 ]; then
    echo
    echo "== tests FAILED — topology left UP for log inspection =="
    echo "   docker compose -f ${COMPOSE_FILE} logs witness"
    echo "   docker compose -f ${COMPOSE_FILE} logs postgres"
    echo "   tear down with: ./scripts/run-e2e.sh down"
else
    echo
    echo "Topology still running. Tear down when finished:"
    echo "  ./scripts/run-e2e.sh down"
fi

exit ${RC}
