#!/bin/bash
# scripts/_validation_audit.sh — internal profile body.
# Invoke via run-validation.sh, not directly.
#
# Runs TestScale_AuditLookup (tests/audit_lookup_test.go) — the
# trustless-auditor walk against a populated ledger. Asserts that
# a third party with NOTHING but the bootstrap document (the trust
# root) can verify network binding, K-of-N witness cosignatures,
# inclusion proofs across tile boundaries, equivocation detection,
# consistency between snapshots, and tamper rejection.
#
# Every cryptographic step uses an SDK primitive — the test
# reproduces what a real auditor would do byte-for-byte. No
# back-channel from the test harness to the verification surface.
#
# REQUIRED ENV:
#   ATTESTA_TEST_DSN  Postgres connection string. Asserted before
#                     work starts. No auto-provisioning here (this
#                     is a focused crypto-correctness test; Postgres
#                     should already be up).
#
# OPTIONAL KNOBS (with defaults):
#   ATTESTA_AUDIT_N              250000   target entries
#                                         (volume that produces
#                                         meaningful multi-tile
#                                         coverage; >=65536 also
#                                         exercises level-1 tiles)
#   ATTESTA_AUDIT_M              1000     extension entries for
#                                         consistency-proof phase
#   ATTESTA_AUDIT_CONCURRENCY    8        submitter goroutines
#                                         (bump for production hw)
#   ATTESTA_AUDIT_INCL_RANDOM    300      random inclusion samples
#   ATTESTA_AUDIT_DRAIN_TIMEOUT  20m      in-test HWM wait
#   ATTESTA_AUDIT_TEST_TIMEOUT   120m     go test process ceiling
#
# Bash because: set -o pipefail (POSIX only has set -e); the
# resolved-defaults block is clearer with bash parameter
# expansion than POSIX equivalents.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# shellcheck source=lib/validation_common.sh
. "${REPO_ROOT}/scripts/lib/validation_common.sh"

validation_preflight_dsn

# Resolve every knob to its final value, then re-export. The script
# is the single source of truth for "what the test process saw" —
# banner + test invocation read from the same locals. Re-exporting
# closes the banner-vs-test-default drift gap.
N="${ATTESTA_AUDIT_N:-250000}"
M="${ATTESTA_AUDIT_M:-1000}"
CONCURRENCY="${ATTESTA_AUDIT_CONCURRENCY:-8}"
INCL_RANDOM="${ATTESTA_AUDIT_INCL_RANDOM:-300}"
DRAIN_TIMEOUT="${ATTESTA_AUDIT_DRAIN_TIMEOUT:-20m}"
TIMEOUT="${ATTESTA_AUDIT_TEST_TIMEOUT:-120m}"

export ATTESTA_AUDIT_N="${N}"
export ATTESTA_AUDIT_M="${M}"
export ATTESTA_AUDIT_CONCURRENCY="${CONCURRENCY}"
export ATTESTA_AUDIT_INCL_RANDOM="${INCL_RANDOM}"
export ATTESTA_AUDIT_DRAIN_TIMEOUT="${DRAIN_TIMEOUT}"

echo "== validation profile: audit (trustless auditor walk) =="
echo "   target n:           ${N} entries (multi-tile coverage)"
echo "   extension m:        ${M} (for consistency-proof phase)"
echo "   concurrency:        ${CONCURRENCY} submitter workers"
echo "   inclusion samples:  ${INCL_RANDOM} random + tile-boundary samples"
echo "   drain timeout:      ${DRAIN_TIMEOUT}"
echo "   test timeout:       ${TIMEOUT}"
echo
echo "what the test does (6 phases):"
echo "  phase 1 — submit N entries; wait for builder convergence"
echo "  phase 2 — verify on-disk tile structure (level-0 + level-1)"
echo "  phase 3a — TRUSTLESS HEAD VERIFICATION (chain walk):"
echo "             read bootstrap doc → derive NetworkID via SHA-256(JCS)"
echo "             → bind to /v1/log-info → resolve did:key witnesses"
echo "             → construct WitnessKeySet → verify K-of-N cosignatures"
echo "             → verify /checkpoint origin signature"
echo "  phase 3b — verify ${INCL_RANDOM} random inclusion proofs"
echo "  phase 3c — verify inclusion at every level-0 tile boundary"
echo "             (stresses cross-tile proof construction)"
echo "  phase 3.5 — equivocation detection (head twice, monotonic"
echo "              + prefix-consistent)"
echo "  phase 4 — consistency proof: extend by M entries, verify"
echo "            no rewrite between the pre/post heads"
echo "  phase 5 — tamper rejection: flip a proof byte, flip a root"
echo "            byte, assert the SDK verifiers reject both"
echo "  phase 6 — JSON-shaped summary report"
echo
echo "what passes look like:"
echo "  scale-audit PASS: trustless auditor walk complete"
echo
echo "what failures point at:"
echo "  phase3a NETWORK BINDING FAILED  → ledger serving a different"
echo "                                     network than the bootstrap doc"
echo "  phase3a COSIGNATURE VERIFY      → witnesses didn't cosign, or"
echo "                                     KeysFromDIDs derivation broke"
echo "  phase3b INCLUSION VERIFY        → proof construction or"
echo "                                     verification regression"
echo "  phase3c TILE-BOUNDARY INCLUSION → cross-tile proof regression"
echo "  phase3.5 EQUIVOCATION DETECTED  → log served two different roots"
echo "                                     at the same size (covert fork)"
echo "  phase4 CONSISTENCY VERIFY       → rewrite between snapshots"
echo "  phase5 TAMPER-REJECTION FAILED  → SDK verifier became too lax"
echo

validation_start_timer

go test -tags=audit \
    -count=1 \
    -timeout "${TIMEOUT}" \
    -v \
    -run '^TestScale_AuditLookup$' \
    ./tests/

WALL_SEC="$(validation_elapsed_secs)"

echo
echo "== summary =="
echo "  n_entries:         ${N}"
echo "  m_extension:       ${M}"
echo "  concurrency:       ${CONCURRENCY}"
echo "  inclusion_samples: ${INCL_RANDOM} random + tile-boundary"
echo "  wall_clock_secs:   ${WALL_SEC}"
echo "  contract verified: trustless auditor walk (bootstrap doc →"
echo "                     NetworkID → witness keys → cosignatures →"
echo "                     inclusion + consistency proofs → tamper-reject)"
