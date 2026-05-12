/*
FILE PATH: chaos/trigger.go

Build-tag-isolated chaos injection points for production-grade
crash-recovery testing. The package exports a single function,
chaos.Trigger(name), called at specific points in production
code where chaos tests need to simulate process death or fault.

PRODUCTION (default) BUILD

In non-chaos builds the entire package compiles to a no-op:
Trigger() returns immediately, the compiler inlines + dead-code-
eliminates the call, and zero runtime cost remains. The Go
toolchain confirms this — disassembling sequencer.processOne
with `go tool objdump` shows the chaos.Trigger call vanishes
in non-chaos builds. The pattern matches CockroachDB's
testserver injection, TiDB's failpoint package, and the Go
stdlib's runtime/race build-tag isolation.

CHAOS BUILD (-tags=chaos)

When built with `-tags=chaos`, trigger_chaos.go takes over.
Trigger reads LEDGER_CHAOS_PANIC_AT from the environment. If
the env var matches the name passed to Trigger, the process
panics with a recognizable message, simulating an OOM kill or
SIGKILL at that exact code point. The test harness then
SIGKILL's the subprocess to ensure stack unwinding doesn't
mask the abrupt-termination semantics — panic is the trigger;
SIGKILL is the realistic kill.

WHY BUILD TAGS, NOT RUNTIME GATING

A runtime flag (e.g., env var checked inside an always-compiled
Trigger function) would add an env-var read + comparison to
every hot-path call in production. Build tags compile the
production binary with the no-op variant, the compiler
eliminates the call site entirely. This is the only zero-cost
fault-injection pattern for hot paths.

INTEGRATION CONTRACT

  - Trigger calls live in production code at named points.
  - Adding a new point: pick a stable string ("post_appendleaf"),
    add chaos.Trigger("post_appendleaf") at the line, document
    in this file's INJECTION POINTS section below.
  - Removing a point: delete the call site. The chaos package
    treats unknown names as no-ops.
  - Renaming: bump a major version of the chaos test that
    depends on the name. The injection-point name is part of
    the chaos contract.

INJECTION POINTS REGISTERED

The following names are currently used by chaos tests under
tests/chaos/. Keep this list in sync with the call sites in
production code.

  - post_appendleaf         sequencer/loop.go after AppendLeaf returns
  - pre_commit_post_pg      sequencer/committer.go between PG commit
                            and applyPostCommitForOne (the
                            committerStaleRecover window)
  - pre_shipper_upload      shipper after WAL state read, before
                            bytestore.WriteEntry
  - pre_wal_fsync           wal/committer.go inside the group-commit
                            goroutine, before db.Sync()
*/
package chaos
