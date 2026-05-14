#!/bin/bash
# scripts/_validation_determinism.sh — internal profile body.
# Invoke via run-validation.sh, not directly.
#
# Runs TestScale_DeterministicReplay (tests/scale_determinism_test.go).
# At-scale P5 idempotent-replay validator: each worker builds wire
# FRESH per iteration, POSTs first + replay, verifies byte-identity
# inline. No pre-built batch (no staleness). Non-fatal submit (errors
# counted, not silenced).
#
# VALIDATES (end-to-end):
#   1. SDK primitive determinism (attesta v1.5.2 RFC 6979 ECDSA).
#   2. Ledger dedup-and-replay path.
#   3. Pipeline integrity under concurrent realistic load.
#
# UNLIKE the soak profile, this does NOT need a bytestore backend
# (uses startTestLedger's in-memory bytestore) — Postgres is the
# only external dependency.
#
# REQUIRED ENV:
#   ATTESTA_TEST_DSN  Postgres connection string. Asserted before
#                     work starts. No auto-provisioning here (this
#                     profile is meant to be quick; if Postgres
#                     isn't already up, fail fast).
#
# OPTIONAL KNOBS (with defaults):
#   ATTESTA_SCALE_DETERMINISM_N             10000  target pairs
#                                                  (= 2N submissions)
#   ATTESTA_SCALE_DETERMINISM_CONCURRENCY   8      worker goroutines
#   ATTESTA_SCALE_DETERMINISM_MAX_DURATION  15m    in-test safety net
#                                                  (workers stop early
#                                                  if exceeded)
#   ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT 1      fail-fast toggle
#                                                  (1=stop on first
#                                                  drift, 0=keep going)
#   ATTESTA_SCALE_DETERMINISM_TIMEOUT       20m    go test process
#                                                  ceiling
#
# Bash because: set -o pipefail (POSIX has only set -e), and the
# resolved-defaults block below is clearer with bash's parameter
# expansion than POSIX equivalents.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# shellcheck source=lib/validation_common.sh
. "${REPO_ROOT}/scripts/lib/validation_common.sh"

validation_preflight_dsn

# Resolve every knob to its final value, then re-export. The script
# becomes the single source of truth for "what the test process
# actually saw" — banner + go test invocation read from the same
# locals. Without re-export, an unset env var would cause the test
# process to apply ITS OWN default (defined in Go) which might drift
# from what this script's banner advertises. Re-exporting closes
# that gap.
N="${ATTESTA_SCALE_DETERMINISM_N:-10000}"
CONCURRENCY="${ATTESTA_SCALE_DETERMINISM_CONCURRENCY:-8}"
MAX_DURATION="${ATTESTA_SCALE_DETERMINISM_MAX_DURATION:-15m}"
STOP_ON_DRIFT="${ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT:-1}"
TIMEOUT="${ATTESTA_SCALE_DETERMINISM_TIMEOUT:-20m}"

export ATTESTA_SCALE_DETERMINISM_N="${N}"
export ATTESTA_SCALE_DETERMINISM_CONCURRENCY="${CONCURRENCY}"
export ATTESTA_SCALE_DETERMINISM_MAX_DURATION="${MAX_DURATION}"
export ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT="${STOP_ON_DRIFT}"

echo "== validation profile: determinism (continuous end-to-end replay) =="
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
echo "  canonical_hash drift  → wire-construction mutation upstream of the SCT path"
echo "  log_time_micros drift → ledger persisted-replay regression"
echo "  signature drift       → SDK RFC 6979 regression OR random state in signed payload"
echo

validation_start_timer

go test -tags=scale \
    -count=1 \
    -timeout "${TIMEOUT}" \
    -v \
    -run '^TestScale_DeterministicReplay$' \
    ./tests/

WALL_SEC="$(validation_elapsed_secs)"

echo
echo "== summary =="
echo "  target n:          ${N}"
echo "  concurrency:       ${CONCURRENCY}"
echo "  wall_clock_secs:   ${WALL_SEC}"
echo "  contract verified: SDK v1.5.2 RFC 6979 ECDSA + ledger dedup-and-replay"
