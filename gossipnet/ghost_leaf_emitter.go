/*
FILE PATH: gossipnet/ghost_leaf_emitter.go

GhostLeafEmitter — the seam between the sequencer (which writes
ghost-leaf rows after detecting a Tessera antispam dedup gap) and
the SDK gossip path (which signs + broadcasts a KindGhostLeaf
event so offline auditors can correlate the duplicate Tessera
leaf with the ledger's own public confession).

WHY KindGhostLeaf EXISTS (corrected)

The SDK's gossip/findings/entry_commitment_equivocation.go
*EntryCommitmentEquivocationFinding.Validate* already rejects
identical-hash pairs:

	if f.SideA.CanonicalHash == f.SideB.CanonicalHash {
	    return fmt.Errorf("...identical canonical hashes —
	                       not equivocation")
	}

So a ghost-leaf scenario (two seqs sharing one canonical_hash)
CANNOT produce a KindEntryCommitmentEquivocation publication.
The local EquivocationScanner builds the finding via the SDK
constructor and the constructor refuses to build — no
suppression path is needed at the scanner.

# THE REAL USE CASE — OFFLINE AUDITOR VISIBILITY

External Static-CT auditors download the ledger's tile data and
walk the Merkle tree. When they encounter two distinct leaves
(at seq_a and seq_b) containing the same canonical_hash, the
default assumption is "the ledger's uniqueness constraint is
broken" — a flaggable integrity violation. KindGhostLeaf is the
ledger's PUBLIC CONFESSION that the duplicate leaf at ghost_seq
is a deliberate crash-recovery artifact whose bytes the API
redirects (308) to canonical_seq.

An auditor pipeline that observes a duplicate Tessera leaf MUST
look up KindGhostLeaf events keyed on the canonical_hash (via
the gossip /by-binding/{hash} endpoint, where Bindings()
publishes canonical_hash). Finding a matching event = benign
recovery, no alert. NOT finding one = real integrity break,
escalate.

# WHY A LOCAL INTERFACE

The sequencer must not depend on attesta/gossip types directly —
that would couple the hot commit path to gossip wire semantics
and force every test fixture to construct an SDK Signer +
Network ID just to exercise commit logic. The local
GhostLeafEmitter interface lets the sequencer hold a one-method
dependency that:

  - any future SDK gossip type (currently v0.5.0's
    findings.GhostLeafFinding) satisfies STRUCTURALLY through
    the production adapter built in gossipnet/wiring.go;
  - the in-tree LoggingGhostLeafEmitter satisfies for unit tests
  - the no-gossip startup mode (witness-disabled deployments,
    fixtures that only exercise PG correctness);
  - failing builds against a missing SDK release surface as an
    ADAPTER-side compile error in wiring.go, not a load-bearing
    sequencer/committer.go compile error.

PRODUCTION ADAPTER (when SDK v0.5.0 ships)

Replace the LoggingGhostLeafEmitter wired by wire.go with a
SDKGossipGhostLeafEmitter that:

 1. Calls findings.NewGhostLeafFinding(ev.GhostSeq, ev.CanonicalSeq,
    ev.CanonicalHash, ev.LogDID, ev.ObservedAtUnixNano).
 2. Reads the originator chain head + advances lamport.
 3. Calls gossip.Sign under cosign.PurposeGossipEventV1.
 4. Calls GossipStore.Append(signed) for the local audit log.
 5. Calls Sink.Broadcast(signed) for peer distribution.

The swap is ONE wire.go assignment. The interface contract is
stable; the implementation behind it can evolve without touching
any sequencer code.

# CRYPTOGRAPHIC-DETERMINISM DISCIPLINE — uint64 OBSERVED-AT

ObservedAt is carried as a uint64 (Unix nanoseconds since epoch),
NEVER as a time.Time, for two independent reasons:

	(1) Cross-language interop. Go's time.RFC3339Nano formatter
	    strips trailing zeros from the fractional-seconds field
	    (verified empirically — Go-only round-trip via
	    time.Parse(time.RFC3339Nano, s).UnixNano() is in fact
	    lossless). But a Rust/JS/Python consumer's RFC-3339
	    parser is not bound to mirror Go's tolerance: a `.123` ms
	    wire string parsed by a stricter implementation could
	    yield a different UnixNano. uint64 sidesteps the parser
	    entirely — the bytes on the wire ARE the integer.

	(2) Format-string drift risk. If anyone ever replaces
	    time.RFC3339Nano with a custom format string in either
	    producer or consumer (a refactor that looks harmless),
	    the canonical bytes silently diverge and every signed
	    event fails verification. Hashing a raw uint64 bypasses
	    string-formatting entirely; there is no format string to
	    drift.

Either reason is sufficient to mandate uint64. SDK Principle 8
(Deterministic Idempotency) requires the canonical bytes survive
every plausible producer/consumer boundary intact; uint64 is
the only encoding that preserves that invariant across the full
ecosystem.

# OBSERVABILITY DISCIPLINE — BEST-EFFORT EMISSION

Every emitter implementation MUST do best-effort emission only —
never block the committer's hot path. The Emit method takes a
context for cancellation but does not return an error: a failed
emit is logged + counted by the implementation; the committer
treats emission as fire-and-forget. The ghost-leaf row in PG is
the authoritative record; gossip is the broadcast amplification
for offline-auditor visibility.
*/
package gossipnet

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/clearcompass-ai/ledger/sequencer"
)

// NewGhostLeafEventNow constructs a sequencer.GhostLeafEvent
// using time.Now().UTC().UnixNano() for ObservedAtUnixNano.
// Convenience for the committer's hot-path callsite so it
// doesn't have to repeat the uint64 conversion + UTC
// normalization at every call.
//
// The returned value is the sequencer-defined struct (not a
// gossipnet-local alias): the sequencer is the consumer of the
// emit-side contract, so it owns the type. gossipnet's emitter
// implementations accept the sequencer's type directly.
func NewGhostLeafEventNow(ghostSeq, canonicalSeq uint64,
	canonicalHash [32]byte, logDID string,
) sequencer.GhostLeafEvent {
	return sequencer.GhostLeafEvent{
		GhostSeq:           ghostSeq,
		CanonicalSeq:       canonicalSeq,
		CanonicalHash:      canonicalHash,
		LogDID:             logDID,
		ObservedAtUnixNano: uint64(time.Now().UTC().UnixNano()),
	}
}

// LoggingGhostLeafEmitter is the in-tree stub. Records each
// emission at INFO and increments an atomic counter so
// integration tests and SRE dashboards can verify the
// committer's emit call-path fires.
//
// This is the default emitter wired in wire.go pre-v0.5.0; the
// gossip-disabled deployment mode (witness count 0) also uses
// this verbatim. The same counter shape is preserved when the
// SDK adapter ships — operators reading the metric never see
// a discontinuity.
type LoggingGhostLeafEmitter struct {
	Logger *slog.Logger
	count  atomic.Uint64
}

// NewLoggingGhostLeafEmitter constructs a logging-only emitter.
// nil logger is permitted and falls back to slog.Default().
func NewLoggingGhostLeafEmitter(logger *slog.Logger) *LoggingGhostLeafEmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoggingGhostLeafEmitter{Logger: logger}
}

// Emit logs the event + bumps the counter. Never blocks; never
// returns an error. The committer's hot path is unaffected by
// emitter behaviour.
//
// The log line formats ObservedAtUnixNano back into a
// human-readable RFC-3339-with-nanos string for operator
// diagnosis ONLY. The cryptographic-bytes path elsewhere uses
// the raw uint64; this formatter is for human eyeballs only.
func (e *LoggingGhostLeafEmitter) Emit(ctx context.Context, ev sequencer.GhostLeafEvent) {
	e.count.Add(1)
	e.Logger.InfoContext(ctx,
		"ghost leaf emitted (logging-only emitter; gossip publication pending SDK v0.5.0 KindGhostLeaf)",
		"ghost_seq", ev.GhostSeq,
		"canonical_seq", ev.CanonicalSeq,
		"canonical_hash", shortHash(ev.CanonicalHash),
		"log_did", ev.LogDID,
		"observed_at_unix_nano", ev.ObservedAtUnixNano,
		"observed_at_human", time.Unix(0, int64(ev.ObservedAtUnixNano)).UTC().Format(time.RFC3339Nano),
	)
}

// EmittedCount returns the running count of emissions. Used by
// the harness and unit tests to verify the committer invoked
// the emitter the expected number of times.
func (e *LoggingGhostLeafEmitter) EmittedCount() uint64 {
	return e.count.Load()
}

// shortHash returns the first 8 bytes as hex — readable enough
// for diagnostic logs without dominating the log line. Bounded
// to 16 characters of output.
func shortHash(h [32]byte) string {
	const hex = "0123456789abcdef"
	var out [16]byte
	for i := 0; i < 8; i++ {
		out[2*i] = hex[h[i]>>4]
		out[2*i+1] = hex[h[i]&0x0f]
	}
	return string(out[:])
}

// nopGhostLeafEmitter discards every emission. Used by test
// fixtures that don't care about gossip and want zero allocations
// on the commit path. Not exported because the LoggingGhost-
// LeafEmitter is the documented default; tests that explicitly
// want silence construct one inline.
type nopGhostLeafEmitter struct{}

func (nopGhostLeafEmitter) Emit(_ context.Context, _ sequencer.GhostLeafEvent) {}

// NopGhostLeafEmitter returns a discarding emitter. Used by the
// sequencer's in-tree tests where ghost-row paths are exercised
// without asserting on emission. Returns sequencer.GhostLeafEmitter
// (the consumer's interface) — gossipnet implementations always
// satisfy the consumer-side contract structurally.
func NopGhostLeafEmitter() sequencer.GhostLeafEmitter {
	return nopGhostLeafEmitter{}
}
