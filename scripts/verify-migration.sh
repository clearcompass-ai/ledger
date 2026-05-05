#!/usr/bin/env bash
# FILE PATH: scripts/verify-migration.sh
#
# Verifies the v0.3.0-tessera migration was applied correctly. Run this
# after copying files from /mnt/user-data/outputs/ and before running go
# vet / go test.
#
# Invariants checked (mechanically, via grep and go vet):
#
#   SOURCE (must be present):
#     1. go.mod pins attesta v0.3.0-tessera
#     2. anchor/publisher.go: PublisherConfig has LogDID, uses crypto.HashBytes,
#        NewEntry sets Destination
#     3. builder/commitment_publisher.go: has logDID field, constructor takes it
#     4. builder/loop.go: step 6 uses envelope.EntryIdentity (NOT EntryLeafHash,
#        NOT sha256 of wireBytes)
#     5. api/submission.go: has step 3a (Validate), 3b (destination), 3c (freshness)
#     6. api/queries.go: uses envelope.EntryIdentity after Deserialize
#     7. lifecycle/shard_manager.go: NewEntry has Destination+EventTime
#     8. cmd/ledger/main.go: wires LogDID to PublisherConfig and
#        NewCommitmentPublisher
#
#   SOURCE (must be absent):
#     9. No builder/loop.go references to sha256.Sum256(wireBytes) or AppendSignature
#        at the Merkle append site
#    10. No EntryLeafHash anywhere in ledger source (RFC 6962 wrapping is
#        Tessera's job, not the ledger's)
#
#   BUILD:
#    11. go vet ./... clean
#    12. go build ./... clean
#
#   TESTS:
#    13. go test ./... clean
#
# Exit code:
#   0 — all invariants hold
#   1 — at least one invariant failed (specifics printed)
#
# Run from ledger repo root.

set -uo pipefail

PASS=0
FAIL=0
WARN=0

green()  { printf "\033[32m%s\033[0m\n" "$*"; }
red()    { printf "\033[31m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

pass() { green "  ✓ $1"; PASS=$((PASS+1)); }
fail() { red   "  ✗ $1"; FAIL=$((FAIL+1)); }
warn() { yellow "  ⚠ $1"; WARN=$((WARN+1)); }

must_contain() {
    local file="$1" pattern="$2" desc="$3"
    if [[ ! -f "$file" ]]; then
        fail "$desc — file missing: $file"
        return
    fi
    if grep -q "$pattern" "$file"; then
        pass "$desc"
    else
        fail "$desc — pattern not found: $pattern"
    fi
}

must_not_contain() {
    local file="$1" pattern="$2" desc="$3"
    if [[ ! -f "$file" ]]; then
        fail "$desc — file missing: $file"
        return
    fi
    if grep -q "$pattern" "$file"; then
        fail "$desc — pattern STILL present: $pattern"
        grep -n "$pattern" "$file" | head -5 | sed 's/^/      /'
    else
        pass "$desc"
    fi
}

bold "━━━ SOURCE: presence checks ━━━"

must_contain "go.mod" \
    "attesta v0.3.0-tessera" \
    "go.mod pinned to SDK v0.3.0-tessera"

must_contain "anchor/publisher.go" \
    "LogDID" \
    "anchor/publisher.go PublisherConfig has LogDID field"

must_contain "anchor/publisher.go" \
    "crypto.HashBytes" \
    "anchor/publisher.go uses crypto.HashBytes for tree head ref"

must_contain "anchor/publisher.go" \
    "Destination:.*p\.cfg\.LogDID\|Destination: p\.cfg\.LogDID" \
    "anchor/publisher.go passes LogDID as Destination"

must_contain "builder/commitment_publisher.go" \
    "logDID" \
    "builder/commitment_publisher.go has logDID field"

must_contain "builder/commitment_publisher.go" \
    "Destination:.*cp\.logDID\|Destination: cp\.logDID" \
    "builder/commitment_publisher.go uses logDID as Destination"

must_contain "builder/loop.go" \
    "envelope\.EntryIdentity" \
    "builder/loop.go step 6 uses envelope.EntryIdentity"

must_contain "api/submission.go" \
    "entry\.Validate()" \
    "api/submission.go has step 3a entry.Validate() check"

must_contain "api/submission.go" \
    "entry\.Header\.Destination != deps\.LogDID" \
    "api/submission.go has step 3b destination check"

must_contain "api/submission.go" \
    "policy\.CheckFreshness" \
    "api/submission.go has step 3c freshness check"

must_contain "api/submission.go" \
    "envelope\.EntryIdentity" \
    "api/submission.go uses envelope.EntryIdentity for hashing"

must_contain "api/submission.go" \
    "admission\.CurrentEpoch" \
    "api/submission.go uses admission.CurrentEpoch helper"

must_contain "api/submission.go" \
    "FreshnessTolerance" \
    "api/submission.go has FreshnessTolerance field on SubmissionDeps"

must_contain "api/queries.go" \
    "envelope\.EntryIdentity" \
    "api/queries.go uses envelope.EntryIdentity after Deserialize"

must_contain "lifecycle/shard_manager.go" \
    "Destination:.*NewShardDID\|Destination: cfg\.NewShardDID" \
    "lifecycle/shard_manager.go genesis has Destination = NewShardDID"

must_contain "lifecycle/shard_manager.go" \
    "EventTime:" \
    "lifecycle/shard_manager.go genesis has EventTime"

must_contain "cmd/ledger/main.go" \
    "cfg\.LogDID" \
    "cmd/ledger/main.go threads cfg.LogDID"

must_contain "cmd/ledger/main.go" \
    "NewCommitmentPublisher(" \
    "cmd/ledger/main.go calls NewCommitmentPublisher"

echo ""
bold "━━━ SOURCE: absence checks (must NOT regress) ━━━"

# EntryLeafHash is for consumer-side verification. Ledger MUST NOT use
# it — Tessera-personality applies RFC 6962 leaf prefix internally, and
# EntryLeafHash in the ledger would double-apply it.
if grep -rn "envelope\.EntryLeafHash" --include="*.go" \
        --exclude-dir=vendor --exclude-dir=.git . 2>/dev/null | \
        grep -v "_test\.go\|EntryLeafHash is for" >/dev/null; then
    fail "EntryLeafHash is referenced in non-test ledger code — must use EntryIdentity at AppendLeaf sites"
    grep -rn "envelope\.EntryLeafHash" --include="*.go" \
        --exclude-dir=vendor --exclude-dir=.git . | \
        grep -v "_test\.go\|EntryLeafHash is for" | head -5 | sed 's/^/      /'
else
    pass "No EntryLeafHash in ledger source (correct — Tessera applies it)"
fi

# The old Merkle leaf scheme computed sha256 over wireBytes. Must be gone.
if grep -n "sha256\.Sum256(wireBytes)" builder/loop.go 2>/dev/null; then
    fail "builder/loop.go still has sha256.Sum256(wireBytes) — migration incomplete"
else
    pass "builder/loop.go no longer uses sha256.Sum256(wireBytes)"
fi

# AppendSignature + sha256 combo at the Merkle site would reveal an
# incomplete migration (hashing canonical+sig instead of EntryIdentity).
if grep -A2 "AppendSignature" builder/loop.go 2>/dev/null | grep -q "sha256\.Sum256" ; then
    fail "builder/loop.go has AppendSignature+sha256 combo near Merkle append — step 6 not migrated"
else
    pass "builder/loop.go Merkle append site is clean"
fi

echo ""
bold "━━━ SHA256 call-site audit (informational) ━━━"

echo "  Entry-shaped sha256 sites (should be zero in non-test source):"
E_COUNT=$(grep -rn "sha256\.Sum256" --include="*.go" \
    --exclude-dir=vendor --exclude-dir=.git \
    --exclude="*_test.go" \
    api/ builder/ anchor/ lifecycle/ cmd/ 2>/dev/null | \
    grep -v "witness/serve\.go\|tessera/proof_adapter\.go\|crypto/" | wc -l | tr -d ' ')

if [[ "$E_COUNT" == "0" ]]; then
    pass "Non-test ledger code has zero stray sha256.Sum256 calls"
else
    warn "Non-test ledger code has $E_COUNT sha256.Sum256 sites — review each:"
    grep -rn "sha256\.Sum256" --include="*.go" \
        --exclude-dir=vendor --exclude-dir=.git \
        --exclude="*_test.go" \
        api/ builder/ anchor/ lifecycle/ cmd/ 2>/dev/null | \
        grep -v "witness/serve\.go\|tessera/proof_adapter\.go\|crypto/" | \
        sed 's/^/      /'
fi

echo ""
echo "  Keep-as-is sha256 sites (reference, should be present):"
grep -n "sha256\.Sum256" witness/serve.go tessera/proof_adapter.go 2>/dev/null | \
    sed 's/^/      /' || warn "expected witness/serve.go and tessera/proof_adapter.go sha256 sites not found"

echo ""
bold "━━━ BUILD ━━━"

if go vet ./... 2>&1 | tee /tmp/vet.out | head -20; then
    if [[ -s /tmp/vet.out ]]; then
        fail "go vet reported issues (above)"
    else
        pass "go vet clean"
    fi
else
    fail "go vet exited non-zero"
fi

if go build ./... 2>&1 | tee /tmp/build.out | head -20; then
    if [[ -s /tmp/build.out ]]; then
        fail "go build reported errors (above)"
    else
        pass "go build clean"
    fi
else
    fail "go build exited non-zero"
fi

echo ""
bold "━━━ TESTS (optional — may take a while) ━━━"

if [[ "${SKIP_TESTS:-0}" == "1" ]]; then
    warn "SKIP_TESTS=1 set — skipping go test"
else
    echo "  Running go test ./... (set SKIP_TESTS=1 to skip)"
    if go test ./... 2>&1 | tail -20; then
        pass "go test ./... completed"
    else
        fail "go test ./... failed (see output above)"
    fi
fi

echo ""
bold "━━━ SUMMARY ━━━"
echo "  Passed:   $PASS"
if (( WARN > 0 )); then yellow "  Warnings: $WARN"; fi
if (( FAIL > 0 )); then red    "  Failed:   $FAIL"; fi

echo ""
if (( FAIL == 0 )); then
    green "MIGRATION VERIFIED ✓"
    echo "The v0.3.0-tessera migration looks complete. Tag a release, rebuild tiles,"
    echo "publish the new tree head to consumers."
    exit 0
else
    red "MIGRATION INCOMPLETE ✗"
    echo "Review the failures above. Re-run after fixes."
    exit 1
fi
