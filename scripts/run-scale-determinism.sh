#!/bin/sh
# scripts/run-scale-determinism.sh — historical entry point.
# Delegates to the unified validation runner. Operator muscle memory
# preserved: every existing invocation continues to work unchanged.
#
# Canonical form: ./scripts/run-validation.sh determinism [args]
exec "$(dirname "$0")/run-validation.sh" determinism "$@"
