#!/bin/sh
# scripts/run-validation.sh — unified validation runner.
#
# Single canonical entry point for the project's at-scale validation
# tests. Dispatches to a per-profile body script via the first
# positional argument. Profile-specific knobs live in env vars in
# the ATTESTA_<PROFILE>_* namespace; the dispatcher itself reads
# only the profile name + forwards the remaining args verbatim.
#
# POSIX shell — works under any /bin/sh implementation. Per-profile
# bodies (_validation_*.sh) use bash where the extra features
# (set -o pipefail, [[ ]], local) materially help.
#
# Backward compatibility: the historical entry-point scripts
# (run-soak.sh, run-scale-determinism.sh) still exist as 2-line
# shims that exec this script with the right profile name. Operator
# muscle memory unchanged.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# shellcheck source=lib/validation_common.sh
. "${REPO_ROOT}/scripts/lib/validation_common.sh"

PROFILE="${1:-}"
if [ -z "${PROFILE}" ]; then
    validation_print_usage
    exit 1
fi
shift

case "${PROFILE}" in
    determinism)
        exec "${REPO_ROOT}/scripts/_validation_determinism.sh" "$@"
        ;;
    soak)
        exec "${REPO_ROOT}/scripts/_validation_soak.sh" "$@"
        ;;
    -h|--help|help)
        validation_print_usage
        exit 0
        ;;
    *)
        echo "FATAL: unknown profile '${PROFILE}'" >&2
        echo >&2
        validation_print_usage
        exit 1
        ;;
esac
