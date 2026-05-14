#!/bin/sh
# scripts/run-soak.sh — historical entry point.
# Delegates to the unified validation runner. Operator muscle memory
# preserved: every existing invocation (including `down`) continues
# to work unchanged.
#
# Canonical form: ./scripts/run-validation.sh soak [args]
exec "$(dirname "$0")/run-validation.sh" soak "$@"
