/*
FILE PATH: wal/errors.go

Sentinel errors for the wal package.
*/
package wal

import "errors"

// ErrQueueFull is returned by Submit when the in-memory submission
// channel is full. The HTTP admission handler maps this to 503 +
// Retry-After. NOT a fatal error — submitters retry on their side.
var ErrQueueFull = errors.New("wal: submission queue full (backpressure)")

// ErrNotFound wraps "no entry exists at this key" returns from Read /
// MetaState / SeqIndex etc. Callers test with errors.Is(err, wal.ErrNotFound).
var ErrNotFound = errors.New("wal: entry not found")

// ErrPhantom is returned by Reconcile when an inflight entry has no
// matching record in Tessera (the ledger crashed before Tessera
// received the entry, OR the entry was written but never sequenced).
// True phantoms are GC'd; the caller's reconcile loop converts them
// to terminal state.
var ErrPhantom = errors.New("wal: phantom entry (Tessera does not have it)")

// ErrDiverged is returned when the WAL's recorded state for an entry
// does not match Tessera's. The composition root MUST panic on this —
// CT logs cannot tolerate divergent state. See the integrity package.
var ErrDiverged = errors.New("wal: WAL state diverges from Tessera (panic)")

// ErrClosed is returned from Submit / Sequence / etc. when the
// committer has been closed (typically during shutdown).
var ErrClosed = errors.New("wal: committer closed")

// ErrEmptyWire is returned from Submit when the caller passes an
// empty or nil wire bytes slice. Production callers never hit this
// (admission has already validated size); the guard is for tests
// and defensive correctness.
var ErrEmptyWire = errors.New("wal: empty wire bytes")
