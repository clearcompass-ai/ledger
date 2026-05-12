/*
FILE PATH: tests/chaos/harness/injection.go

Codified inventory of every chaos injection point the harness
can drive. The kill point names are Go constants — NOT string
literals — so a typo at the test callsite becomes a
compile-time error instead of a silent test-skip.

WHY CONSTANTS, NOT LITERALS

The chaos contract has two sides:

  1. Production code site (e.g., sequencer/loop.go) calls
     chaos.Trigger("post_appendleaf").
  2. Chaos test (e.g., kill_appendleaf_test.go) sets
     LEDGER_CHAOS_PANIC_AT=post_appendleaf via RestartOpts.

If those two strings DON'T match, the trigger never fires.
The subprocess runs to completion; the chaos test runs the
"clean restart" path and asserts invariants, which pass; the
test reports SUCCESS while having validated nothing about
crash recovery.

Codifying the names as Go constants (KillPointPostAppendLeaf
etc.) prevents this entire failure mode. A typo at the chaos
test callsite ("KillPointPostAppendLeef") fails compilation;
a typo at the production callsite is caught by the unit test
in chaos/trigger_chaos_test.go (which asserts the marker
includes name=...).

THE FOUR REGISTERED POINTS

Each constant value matches the string passed to chaos.Trigger
at the production callsite. Do NOT change the values without
updating EVERY production callsite AND every chaos test that
references it.

  KillPointPostAppendLeaf      sequencer/loop.go:processOne
                               just after Tessera.AppendLeaf
                               returns, before stage-1 emits
                               the stagedEntry to commitCh.

  KillPointPreCommitPostPG     sequencer/committer.go:flushBatch
                               after the PG transaction
                               commits, before applyPostCommitForOne
                               fires WAL.Sequence.

  KillPointPreShipperUpload    shipper/shipper.go:shipOne
                               after WAL Read, before
                               bytestore.WriteEntry.

  KillPointPreWALFsync         wal/committer.go:flushBatch
                               inside the group-commit
                               goroutine, after txn commit,
                               before db.Sync().

REGISTRY DISCIPLINE

Adding a new kill point:
  1. Add the constant here with a descriptive name.
  2. Add it to AllKillPoints below.
  3. Add the chaos.Trigger call at the production callsite,
     passing the constant value (NOT a string literal).
  4. Document it in chaos/trigger.go's INJECTION POINTS
     REGISTERED section.

Removing a point: delete the constant + the production
callsite + any chaos test that referenced it. The chaos
package is permissive about unknown names (treats them as
no-ops), so partial removal is safe.
*/
package harness

// KillPoint is a typed string for chaos injection point names.
// Distinct type so a stray string literal can't be passed where
// a kill point is expected without an explicit conversion.
type KillPoint string

const (
	// KillPointPostAppendLeaf — sequencer/loop.go::processOne,
	// just after Tessera.AppendLeaf returns. Tests recovery
	// from a kill where Tessera assigned the seq but the stage-1
	// worker never reached the commitCh emit. On restart the
	// hash is still WAL Pending; AppendLeaf dedupes to the same
	// seq; flow resumes normally.
	KillPointPostAppendLeaf KillPoint = "post_appendleaf"

	// KillPointPreCommitPostPG — sequencer/committer.go::flushBatch,
	// after the PG transaction commits but before
	// applyPostCommitForOne fires WAL.Sequence. The exact
	// window committerStaleRecover was written for. Most
	// load-bearing single point in the system.
	KillPointPreCommitPostPG KillPoint = "pre_commit_post_pg"

	// KillPointPreShipperUpload — shipper/shipper.go::shipOne,
	// after WAL Read but before bytestore.WriteEntry. Tests that
	// the bytestore upload path is idempotent under retry — the
	// re-upload after restart MUST land at the same URL.
	KillPointPreShipperUpload KillPoint = "pre_shipper_upload"

	// KillPointPreWALFsync — wal/committer.go::flushBatch,
	// inside the group-commit goroutine after the Badger txn
	// commit but before db.Sync(). The hardest durability
	// claim: every 202'd submission must be recoverable via
	// Badger WAL replay, even if SIGKILL fires the instant
	// before fsync.
	KillPointPreWALFsync KillPoint = "pre_wal_fsync"
)

// AllKillPoints enumerates every registered kill point. Used by
// the harness smoke test to validate each one is wired by setting
// LEDGER_CHAOS_PANIC_AT to its string value + asserting the
// marker fires on a freshly-spawned subprocess.
var AllKillPoints = []KillPoint{
	KillPointPostAppendLeaf,
	KillPointPreCommitPostPG,
	KillPointPreShipperUpload,
	KillPointPreWALFsync,
}

// String returns the underlying string for env-var encoding.
func (k KillPoint) String() string { return string(k) }

// IsRegistered reports whether name matches one of the
// constants above. Useful in defensive code paths that accept
// dynamic kill-point names from CLI flags or env vars.
func IsRegistered(name string) bool {
	for _, kp := range AllKillPoints {
		if string(kp) == name {
			return true
		}
	}
	return false
}

// WithKillPoint constructs a RestartOpts with PanicAt set to
// the typed kill point. Preferred over manually building
// RestartOpts{PanicAt: "post_appendleaf"} because the typed
// helper enforces the kill point is from the registered set.
//
// AfterN sets the per-name counter threshold (1-indexed). 0 =
// first match fires.
func WithKillPoint(kp KillPoint, afterN int) RestartOpts {
	return RestartOpts{
		PanicAt:     string(kp),
		PanicAfterN: afterN,
	}
}
