#!/bin/bash
# scripts/run-scale-determinism.sh
#
# Runs TestScale_DeterministicReplay (tests/scale_determinism_test.go)
# — the at-scale P5 idempotent-replay validator. Submits N entries
# TWICE each and asserts every pair's SCT is byte-identical
# (canonical_hash + log_time_micros + signature).
#
# Validates end-to-end:
#   1. SDK primitive determinism (attesta v1.5.2 RFC 6979 ECDSA).
#   2. Ledger dedup-and-replay path (persisted canonical_hash +
#      log_time_micros returned verbatim on duplicate admission).
#   3. Pipeline integrity under concurrent submission.
#
# UNLIKE run-soak.sh, this test does NOT need a bytestore backend
# (uses startTestLedger's in-memory bytestore) — Postgres is the
# only external dependency.
#
# ── Required env ─────────────────────────────────────────────────────
#   ATTESTA_TEST_DSN  Postgres connection string. If unset, errors.
#
# ── Optional env (with defaults) ─────────────────────────────────────
#   ATTESTA_SCALE_DETERMINISM_N            10000   total pairs (=2N submissions)
#   ATTESTA_SCALE_DETERMINISM_CONCURRENCY  8       worker goroutines
#   ATTESTA_SCALE_DETERMINISM_P99_MS       200     submit p99 ceiling (soft check)
#   ATTESTA_SCALE_DETERMINISM_TIMEOUT      15m     go test process ceiling
#
# ── Usage ────────────────────────────────────────────────────────────
#
# Smoke (1K pairs, ~10s):
#   ATTESTA_SCALE_DETERMINISM_N=1000 ./scripts/run-scale-determinism.sh
#
# Full validation (10K pairs, ~2 min):
#   ./scripts/run-scale-determinism.sh
#
# High-volume regression check (100K pairs):
#   ATTESTA_SCALE_DETERMINISM_N=100000 \
#   ATTESTA_SCALE_DETERMINISM_TIMEOUT=30m \
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
P99_MS="${ATTESTA_SCALE_DETERMINISM_P99_MS:-200}"
TIMEOUT="${ATTESTA_SCALE_DETERMINISM_TIMEOUT:-15m}"

echo "== at-scale determinism replay =="
echo "   n:               ${N} pairs (= ${N} × 2 submissions)"
echo "   concurrency:     ${CONCURRENCY} workers"
echo "   p99 bound:       ${P99_MS} ms (soft check)"
echo "   test timeout:    ${TIMEOUT}"
echo
echo "what passes look like:"
echo "  PASS: ${N}/${N} pairs byte-identical (canonical_hash + log_time_micros + signature)"
echo
echo "what failures point at:"
echo "  hash_drift > 0 → wire-construction mutation upstream of the SCT path"
echo "  time_drift > 0 → ledger persisted-replay regression (log_time_micros not stored or not replayed)"
echo "  sig_drift  > 0 → SDK RFC 6979 regression OR fresh random state mixed into the signed payload"
echo

START_NS=$(date +%s%N)

ATTESTA_TEST_DSN="${ATTESTA_TEST_DSN}" \
ATTESTA_SCALE_DETERMINISM_N="${N}" \
ATTESTA_SCALE_DETERMINISM_CONCURRENCY="${CONCURRENCY}" \
ATTESTA_SCALE_DETERMINISM_P99_MS="${P99_MS}" \
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
echo "  n_pairs:           ${N}"
echo "  concurrency:       ${CONCURRENCY}"
echo "  wall_clock_secs:   ${WALL_SEC}"
echo "  contract verified: SDK v1.5.2 RFC 6979 ECDSA + ledger dedup-and-replay"
