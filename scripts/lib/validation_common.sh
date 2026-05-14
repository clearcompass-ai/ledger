# scripts/lib/validation_common.sh
#
# Sourced by run-validation.sh and the per-profile _validation_*.sh
# scripts. POSIX-only — no bashisms — so it works under either
# /bin/sh or /bin/bash without surprise. Don't add `local`, `[[ ]]`,
# arrays, `set -o pipefail`, or process-substitution `<()` to this
# file.
#
# Functions exported:
#
#   validation_print_usage     — prints the canonical multi-profile
#                                usage block to stderr. Single source
#                                of truth for the operator-facing
#                                env-var inventory.
#
#   validation_preflight_dsn   — asserts ATTESTA_TEST_DSN is set;
#                                prints actionable error + exits 1
#                                if not. Both profiles need Postgres,
#                                so the check lives here, not per-
#                                profile.
#
#   validation_start_timer     — captures the wall-clock start time
#                                in VALIDATION_START_NS (global,
#                                because POSIX functions can't return
#                                multi-byte values without an extra
#                                fork).
#
#   validation_elapsed_secs    — echoes integer seconds since
#                                validation_start_timer. Caller embeds
#                                in its own summary so each profile
#                                keeps full control of summary
#                                formatting.

# Print the canonical usage block. Routed to stderr because operator
# error (no profile, unknown profile) belongs there. Heredoc with
# 'EOF' (quoted) prevents variable expansion inside.
validation_print_usage() {
    cat >&2 <<'EOF'
Usage: ./scripts/run-validation.sh <profile> [profile-args]

Profiles:
  determinism   SCT byte-identity contract validation.
                Light. In-memory bytestore. Default 10K pairs (~3min wall).
                Tests TestScale_DeterministicReplay (-tags=scale).

  soak          Throughput + bytestore durability + Merkle integrity.
                Heavy. Requires S3-compatible bytestore + Postgres.
                Default 1M entries. Wall time depends on N.
                Tests TestSoak_LedgerBytestore (-tags=soak).

  audit         Trustless-auditor walk: bootstrap doc → NetworkID →
                witness keys → K-of-N cosignatures → inclusion proofs
                across tile boundaries → equivocation detection →
                consistency proof between snapshots → tamper rejection.
                Default 250K entries (meaningful multi-tile coverage).
                Tests TestScale_AuditLookup (-tags=audit).

Required env (all profiles):
  ATTESTA_TEST_DSN          Postgres connection string. Asserted before
                            any work. Soak profile auto-provisions
                            Postgres in Docker if unset; determinism
                            and audit profiles fail fast.

Profile-specific env (knobs documented in each profile body):
  determinism:  ATTESTA_SCALE_DETERMINISM_{N,CONCURRENCY,
                  MAX_DURATION,STOP_ON_DRIFT,TIMEOUT}
  soak:         ATTESTA_SOAK_{ENTRIES,CONCURRENCY,
                  VERIFY_SAMPLES,TREE_PROOF_SAMPLES,SMT_PROOF_SAMPLES,
                  P99_BOUND_MS,SHIPPER_MAX_IN_FLIGHT,
                  SEQUENCER_MAX_IN_FLIGHT,DRAIN_TIMEOUT,
                  TEST_TIMEOUT,BYTESTORE_BACKEND,KEEP_DATA}
                Plus ATTESTA_TEST_S3_*  (s3 / seaweedfs backends)
                  or ATTESTA_TEST_GCS_BUCKET (gcs backend).
  audit:        ATTESTA_AUDIT_{N,M,CONCURRENCY,INCL_RANDOM,
                  DRAIN_TIMEOUT,TEST_TIMEOUT}

  Soak's VERIFY_SAMPLES cascades to TREE_PROOF_SAMPLES + SMT_PROOF_SAMPLES
  when those are unset. Set VERIFY_SAMPLES once and every sampled
  verifier scales together; override individuals only when needed.

Examples:
  ./scripts/run-validation.sh determinism
  ATTESTA_SCALE_DETERMINISM_N=1000 ./scripts/run-validation.sh determinism

  ATTESTA_SOAK_ENTRIES=10000 ATTESTA_SOAK_VERIFY_SAMPLES=10% \
    ./scripts/run-validation.sh soak

  ATTESTA_AUDIT_N=1024 ./scripts/run-validation.sh audit   # smoke
  ./scripts/run-validation.sh audit                        # full 250K

  ./scripts/run-validation.sh soak down       # tear down docker (soak only)

Backward-compatible entry points:
  ./scripts/run-soak.sh                → run-validation.sh soak
  ./scripts/run-scale-determinism.sh   → run-validation.sh determinism
  ./scripts/run-audit.sh               → run-validation.sh audit
EOF
}

# Asserts ATTESTA_TEST_DSN is set; exits 1 with an actionable message
# otherwise. Profiles that auto-provision Postgres (soak, currently)
# call this AFTER their own provisioning attempt, so the only path
# this fires through is "no DSN AND no docker."
validation_preflight_dsn() {
    if [ -z "${ATTESTA_TEST_DSN:-}" ]; then
        cat >&2 <<'EOF'
FATAL: ATTESTA_TEST_DSN not set

  export ATTESTA_TEST_DSN='postgres://attesta:attesta@localhost:5432/attesta_test?sslmode=disable'

  Or run scripts/run-local.sh up to auto-provision Postgres.
EOF
        exit 1
    fi
}

# Stamps the wall-clock start time. Single global VALIDATION_START_NS
# is the simplest portable carrier — POSIX functions can't return
# multi-byte values via stdout without an extra subshell fork, and
# we don't want timing helpers to fork.
validation_start_timer() {
    VALIDATION_START_NS=$(date +%s%N)
}

# Echoes integer seconds elapsed since validation_start_timer. Caller
# captures via $(validation_elapsed_secs).
#
# Note: macOS BSD `date` doesn't support %N — falls back to
# nanosecond-zero, so ELAPSED_S resolves to 0 on macOS. To keep the
# library single-platform, we accept that quirk; the per-profile
# scripts can override timing if sub-second resolution ever matters.
validation_elapsed_secs() {
    end_ns=$(date +%s%N)
    echo $(( (end_ns - VALIDATION_START_NS) / 1000000000 ))
}
