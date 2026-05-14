#!/bin/sh
# scripts/run-audit.sh — convenience entry point for the audit profile.
# Delegates to the unified validation runner. Symmetric with
# run-soak.sh and run-scale-determinism.sh.
#
# Canonical form: ./scripts/run-validation.sh audit [args]
exec "$(dirname "$0")/run-validation.sh" audit "$@"
