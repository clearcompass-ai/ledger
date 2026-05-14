#!/bin/bash
# scripts/run-scale-determinism.sh
#
# Runs TestScale_DeterministicReplay (tests/scale_determinism_test.go)
# — the at-scale P5 idempotent-replay validator.
#
# DESIGN: continuous end-to-end per iteration. Each worker goroutine
# runs its own loop — build wire FRESH (EventTime stamped at submit),
# POST first, POST replay, verify byte-identity inline, next. No
# pre-built batch (eliminates the freshness-staleness defect that
# capped the previous bulk shape at ~3300 pairs / 5 min). No shared
# t.Fatalf-from-worker (eliminates the silent-error-counter defect
# of the previous shape).
#
# Validates end-to-end:
#   1. SDK primitive determinism (attesta v1.5.2 RFC 6979 ECDSA).
#   2. Ledger dedup-and-replay path (persisted canonical_hash +
#      log_time_micros returned verbatim on duplicate admission).
#   3. Pipeline integrity under concurrent realistic load.
#
# UNLIKE run-soak.sh, this test does NOT need a bytestore backend
# (uses startTestLedger's in-memory bytestore) — Postgres is the
# only external dependency.
#
# ── Required env ─────────────────────────────────────────────────────
#   ATTESTA_TEST_DSN  Postgres connection string. If unset, errors.
#
# ── Optional env (with defaults) ─────────────────────────────────────
#   ATTESTA_SCALE_DETERMINISM_N             10000  target pairs (= 2N submissions)
#   ATTESTA_SCALE_DETERMINISM_CONCURRENCY   8      worker goroutines
#   ATTESTA_SCALE_DETERMINISM_MAX_DURATION  15m    in-test safety-net deadline
#                                                  (workers stop early if this fires;
#                                                   the test then reports
#                                                   completed < target as a Fatal)
#   ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT 1      stop on first byte-identity
#                                                  violation (1/true = stop; 0/false
#                                                  = run to N and report drift count)
#   ATTESTA_SCALE_DETERMINISM_TIMEOUT       20m    go test process ceiling
#
# ── Usage ────────────────────────────────────────────────────────────
#
# Smoke (1K pairs, ~80s):
#   ATTESTA_SCALE_DETERMINISM_N=1000 ./scripts/run-scale-determinism.sh
#
# Default validation (10K pairs, expect ~10-15min at typical macOS dev rates):
#   ./scripts/run-scale-determinism.sh
#
# Regression sweep (50K pairs, observe drift distribution rather than fail-fast):
#   ATTESTA_SCALE_DETERMINISM_N=50000 \
#   ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT=0 \
#   ATTESTA_SCALE_DETERMINISM_MAX_DURATION=45m \
#   ATTESTA_SCALE_DETERMINISM_TIMEOUT=60m \
#     ./scripts/run-scale-determinism.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

if [ -z "${ATTESTA_TEST_DSN:-}" ]; then
    echo "FATAL: ATTESTA_TEST_DSN not set"
    echo
    echo "  export ATTESTA_TEST_DSN='postgres://attesta:attesta@localhost:5432/attesta_test?sslmode=disable'"
    echo
    echo "  (Or run scripts/run-local.sh up to auto-provision Postgres.)"
    exit 1
fi

N="${ATTESTA_SCALE_DETERMINISM_N:-10000}"
CONCURRENCY="${ATTESTA_SCALE_DETERMINISM_CONCURRENCY:-8}"
MAX_DURATION="${ATTESTA_SCALE_DETERMINISM_MAX_DURATION:-15m}"
STOP_ON_DRIFT="${ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT:-1}"
TIMEOUT="${ATTESTA_SCALE_DETERMINISM_TIMEOUT:-20m}"

echo "== at-scale determinism replay (continuous end-to-end) =="
echo "   target n:         ${N} pairs (= ${N} × 2 submissions)"
echo "   concurrency:      ${CONCURRENCY} workers (each runs its own loop)"
echo "   max duration:     ${MAX_DURATION} (in-test safety net)"
echo "   stop on drift:    ${STOP_ON_DRIFT} (1=fail fast, 0=keep going)"
echo "   test timeout:     ${TIMEOUT} (go test process ceiling)"
echo
echo "shape: each worker builds wire FRESH per iteration, POSTs first +"
echo "       replay, verifies byte-identity inline, then next. No pre-"
echo "       built batch (no staleness). Non-fatal submit (errors are"
echo "       counted, not silenced)."
echo
echo "what passes look like:"
echo "  scale-determinism PASS: ${N} pairs end-to-end, all byte-identical"
echo "  (canonical_hash + log_time_micros + signature)"
echo
echo "what failures point at:"
echo "  canonical_hash drift → wire-construction mutation upstream of the SCT path"
echo "  log_time_micros drift → ledger persisted-replay regression"
echo "  signature drift       → SDK RFC 6979 regression OR random state in signed payload"
echo

START_NS=$(date +%s%N)

ATTESTA_TEST_DSN="${ATTESTA_TEST_DSN}" \
ATTESTA_SCALE_DETERMINISM_N="${N}" \
ATTESTA_SCALE_DETERMINISM_CONCURRENCY="${CONCURRENCY}" \
ATTESTA_SCALE_DETERMINISM_MAX_DURATION="${MAX_DURATION}" \
ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT="${STOP_ON_DRIFT}" \
go test -tags=scale \
    -count=1 \
    -timeout "${TIMEOUT}" \
    -v \
    -run '^TestScale_DeterministicReplay$' \
    ./tests/

END_NS=$(date +%s%N)
WALL_SEC=$(( (END_NS - START_NS) / 1000000000 ))

echo
echo "== summary =="
echo "  target n:          ${N}"
echo "  concurrency:       ${CONCURRENCY}"
echo "  wall_clock_secs:   ${WALL_SEC}"
echo "  contract verified: SDK v1.5.2 RFC 6979 ECDSA + ledger dedup-and-replay"
