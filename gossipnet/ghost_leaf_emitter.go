/*
FILE PATH: gossipnet/ghost_leaf_emitter.go

In-tree GhostLeafEmitter implementations.

This file ships the FALLBACK emitters used when the SDK gossip
path isn't wired (witness-disabled deployments, unit tests,
gossip-bundle construction failures). The PRODUCTION emitter —
the one that signs+appends+broadcasts via attesta SDK v0.5.0's
findings.GhostLeafFinding — lives in sdk_ghost_leaf_emitter.go.

# WHY KindGhostLeaf EXISTS

See attesta/gossip/findings/ghost_leaf.go (SDK v0.5.0) for the
load-bearing rationale. Short version: external Static-CT
auditors observing a duplicate Tessera leaf need a signed
ledger-side confession that the duplicate is a benign crash-
recovery artifact; without it they reasonably flag the ledger
for an integrity violation. KindGhostLeaf IS that confession.

Note the SDK doc explicitly says ghost leaves are NOT consumed
by the equivocation scanner — the EntryCommitmentEquivocation
constructor's identical-hash check makes false positives
unreachable. The scanner does not look up ghost leaves.

# CONTRACT

All implementations of sequencer.GhostLeafEmitter (declared on
the consumer side in sequencer/sequencer.go) MUST:

  - Treat Emit as best-effort, fire-and-forget. The committer's
    hot path is unaffected by emitter behaviour.
  - Never block (no synchronous I/O on the commit path's caller
    goroutine for longer than a single log line).
  - Never return an error. Failures are logged + counted
    internally.

The PG ghost row written by the committer is the authoritative
record; gossip is broadcast amplification for auditor visibility.
*/
package gossipnet

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/clearcompass-ai/ledger/sequencer"
)

// LoggingGhostLeafEmitter records each emission at INFO and
// increments an atomic counter. Used when gossip is disabled
// AND as a fallback when the SDK adapter's construction fails.
//
// The log line carries the raw uint64 ObservedAtUnixNano (and,
// alongside it, an RFC-3339Nano human-readable rendering for
// operator diagnosis ONLY — the cryptographic-bytes path
// elsewhere hashes the uint64 directly per the SDK contract).
type LoggingGhostLeafEmitter struct {
	Logger *slog.Logger
	count  atomic.Uint64
}

// NewLoggingGhostLeafEmitter constructs a logging-only emitter.
// nil logger falls back to slog.Default.
func NewLoggingGhostLeafEmitter(logger *slog.Logger) *LoggingGhostLeafEmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoggingGhostLeafEmitter{Logger: logger}
}

// Emit logs the event + bumps the counter. Non-blocking;
// never returns an error.
func (e *LoggingGhostLeafEmitter) Emit(ctx context.Context, ev sequencer.GhostLeafEvent) {
	e.count.Add(1)
	e.Logger.InfoContext(ctx,
		"ghost leaf emitted (logging-only emitter; not broadcast to peers)",
		"ghost_seq", ev.GhostSeq,
		"canonical_seq", ev.CanonicalSeq,
		"canonical_hash", shortHash(ev.CanonicalHash),
		"log_did", ev.LogDID,
		"observed_at_unix_nano", ev.ObservedAtUnixNano,
		"observed_at_human", time.Unix(0, int64(ev.ObservedAtUnixNano)).UTC().Format(time.RFC3339Nano),
	)
}

// EmittedCount returns the running count of emissions. Used by
// integration tests and SRE dashboards to verify the committer
// invoked the emitter the expected number of times.
func (e *LoggingGhostLeafEmitter) EmittedCount() uint64 {
	return e.count.Load()
}

// shortHash returns the first 8 bytes of a [32]byte as 16
// lowercase hex chars. Used by both emitter implementations for
// diagnostic log lines.
func shortHash(h [32]byte) string {
	const hex = "0123456789abcdef"
	var out [16]byte
	for i := 0; i < 8; i++ {
		out[2*i] = hex[h[i]>>4]
		out[2*i+1] = hex[h[i]&0x0f]
	}
	return string(out[:])
}

// nopGhostLeafEmitter discards every emission. Test fixtures
// that exercise ghost-row paths without asserting on emission
// use this via NopGhostLeafEmitter().
type nopGhostLeafEmitter struct{}

func (nopGhostLeafEmitter) Emit(_ context.Context, _ sequencer.GhostLeafEvent) {}

// NopGhostLeafEmitter returns a discarding emitter satisfying
// sequencer.GhostLeafEmitter. Used by unit tests that want to
// exercise the committer's ghost-row path without observing the
// emit-side behaviour.
func NopGhostLeafEmitter() sequencer.GhostLeafEmitter {
	return nopGhostLeafEmitter{}
}
