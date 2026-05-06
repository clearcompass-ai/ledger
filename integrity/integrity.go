/*
Package integrity is the cryptographic-agreement layer between the
ledger's local WAL and the embedded Tessera log. Two surfaces:

  - Verifier (read-only): point-in-time checks that the hash at a
    given sequence number in Tessera matches what the WAL recorded.
    Used by the periodic Detector to spot-check agreement.

  - Reasserter (idempotent re-Add): boot-time reconciliation. The
    primitive is "re-issue Tessera.Add for an inflight identity";
    Tessera's deduplicator (wired via wal.TesseraDedup) makes the
    call idempotent — already-integrated entries return their
    existing index without re-integrating.

DESIGN: WHY RE-ADD INSTEAD OF LOOKUP?

	The naive boot reconciliation is "for each WAL inflight breadcrumb,
	ask Tessera 'do you have this hash?'". That is unsafe because the
	Add → integrate → dedup-record sequence is not atomic in upstream
	Tessera — there's a window where Add has accepted the entry but
	the dedup hasn't yet recorded the index. A boot in that window
	would see "Tessera doesn't know this hash" and incorrectly GC the
	bytes; Tessera would then integrate the entry against a hash whose
	bytes no longer exist.

	Re-Add closes the race because it's idempotent. If Tessera already
	has the entry, dedup returns the existing index. If Tessera doesn't
	have it (true phantom), Add inserts it and returns a fresh index.
	Either way, the entry ends up properly recorded; reconciliation
	converges.

DESIGN: WHY PANIC ON DIVERGENCE?

	CT logs cannot tolerate disagreement between the ledger's
	recorded state and the Merkle tree's committed state. If the
	Detector finds a sequence where WAL claims hash A but Tessera
	shows hash B, every proof rooted at the current tree head
	potentially carries a lie. The only correct response is to stop
	the ledger immediately so consumers can't be served corrupt
	proofs. The Detector returns ErrDiverged; the composition root
	in cmd/ledger/main.go panics on it.

	Process-level termination is the correct response across every
	orchestrator (Kubernetes, systemd, bare metal) because non-zero
	exit + restart-loop is a universal signal. The ledger does NOT
	decide what to do next (page on-call, dump evidence, etc.) —
	that's infra's job.

PACKAGE LAYOUT:

	integrity.go types + sentinels + minimal interfaces from
	                      the WAL surface (decoupled from wal/ package
	                      proper)
	verifier.go Verifier interface + tile-reader-backed impl
	reasserter.go Reasserter interface + appender-backed impl
	tessera_adapter.go one struct that satisfies both, wrapping
	                      an embedded Tessera appender + tile reader
	detector.go Reconcile (boot) + Loop (periodic sample-verify)
*/
package integrity

import (
	"context"
	"errors"
)

// ErrDiverged is returned when the WAL's recorded hash for a sequence
// does not match the hash Tessera commits to at that sequence. The
// composition root MUST panic on this error — see file docblock.
var ErrDiverged = errors.New("integrity: WAL state diverges from Tessera (panic)")

// ErrPhantom is returned during boot reconciliation when Tessera
// rejects a re-Add (e.g., the identity is malformed in a way the
// integrator refuses). True phantoms — entries the ledger wrote
// to the WAL but never made it past Tessera's acceptance — surface
// here. The Detector logs them and continues; the bytes stay in the
// WAL until an ledger reviews them.
var ErrPhantom = errors.New("integrity: phantom entry (Tessera refuses re-Add)")

// ─────────────────────────────────────────────────────────────────────
// Minimal interfaces from the WAL surface
// ─────────────────────────────────────────────────────────────────────
//
// Defined here so the integrity package doesn't import wal/ directly.
// The Reconciler bridges *wal.Committer.IterateInflight (which yields
// wal.PendingHash) to the integrity-side iterator (which yields raw
// [32]byte) via a thin adapter at the call site. This avoids the
// integrity package depending on a wal.PendingHash named type that
// would force a hard import.

// WALReader is the read surface integrity needs. Decoupled so the
// composition root can mock it in tests.
type WALReader interface {
	// HashAt returns the WAL-recorded hash at the given sequence.
	// Used by Detector to spot-check Tessera agreement.
	HashAt(ctx context.Context, seq uint64) ([32]byte, error)

	// HWM returns the highest contiguous shipped sequence — the
	// upper bound on what the Detector samples.
	HWM(ctx context.Context) (uint64, error)
}
