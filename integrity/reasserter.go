/*
FILE PATH: integrity/reasserter.go

Reasserter — boot-time idempotent re-Add primitive.

CONTRACT:
  Reassert(ctx, hash) → seq. The implementation calls upstream
  Tessera's Add for the supplied 32-byte identity. With the
  deduplicator wired (wal.TesseraDedup → tessera.WithDeduplication),
  the upstream Add returns:
    - on first integration: the freshly-assigned sequence number
    - on subsequent calls with the same identity: the previously-
      assigned sequence number (no re-integration)

  Reassert is therefore safe to call across boots: re-issuing it
  for a WAL inflight entry converges on the entry's correct
  sequence whether or not the operator's prior process completed
  the original Add → Sequence round trip.

WHY NOT JUST LOOKUP?
  See integrity.go's design block. Lookup-only reconciliation has
  a race window between Tessera Add-acceptance and dedup-record
  writes; re-Add is the only race-free primitive.
*/
package integrity

import (
	"context"
	"fmt"
)

// Reasserter is the idempotent re-Add surface. One implementation
// in production: tesseraReasserter, which forwards to an
// AppenderBackend (wraps the embedded Tessera library).
type Reasserter interface {
	Reassert(ctx context.Context, identity [32]byte) (seq uint64, err error)
}

// AppenderBackend is the minimal surface integrity needs from
// Tessera. *tessera.EmbeddedAppender satisfies it (and so does
// *tessera.ReadOnlyAppender, though calling Reassert on the
// read-only side returns ErrReadOnly).
//
// Defined here mirroring tessera.AppenderBackend so the integrity
// package doesn't depend on internal tessera types beyond the
// already-imported TileReader.
type AppenderBackend interface {
	AppendLeaf(data []byte) (uint64, error)
}

// tesseraReasserter satisfies Reasserter via an AppenderBackend.
type tesseraReasserter struct {
	appender AppenderBackend
}

// NewReasserter returns a Reasserter rooted at the supplied
// AppenderBackend. With tessera.WithDeduplication wired at the
// composition root, Reassert is idempotent across process restarts.
func NewReasserter(appender AppenderBackend) Reasserter {
	return &tesseraReasserter{appender: appender}
}

// Reassert forwards identity to AppenderBackend.AppendLeaf. The
// return value is the seq Tessera assigned (or had previously
// assigned via dedup).
//
// identity MUST be exactly 32 bytes — Tessera's hash-only tile
// format requires it, and AppendLeaf rejects anything else.
func (r *tesseraReasserter) Reassert(ctx context.Context, identity [32]byte) (uint64, error) {
	if r == nil || r.appender == nil {
		return 0, fmt.Errorf("integrity/reasserter: nil appender")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	seq, err := r.appender.AppendLeaf(identity[:])
	if err != nil {
		return 0, fmt.Errorf("integrity/reasserter: AppendLeaf %x: %w", identity[:8], err)
	}
	return seq, nil
}
