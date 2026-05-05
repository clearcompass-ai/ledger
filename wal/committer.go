/*
FILE PATH: wal/committer.go

Committer — the durable-bytes primitive. Submit blocks until the wire
bytes are fsync'd to disk; group commit amortizes fsync cost across
multiple concurrent admissions.

GROUP COMMIT:

  HTTP admission paths call Submit(ctx, hash, wire). Submit pushes a
  submission record (including a per-call done channel) onto an
  in-memory queue, then blocks on done. A single background goroutine
  drains the queue, batches submissions, opens a single Badger txn
  that writes entry + meta + inflight for every batched submission,
  commits the txn, then calls db.Sync() ONCE for the whole batch.
  After Sync returns, the goroutine signals every batched
  submission's done channel with the same error.

  Triggers (whichever fires first):
    - len(batch) >= BatchMaxEntries
    - bytes(batch) >= BatchMaxBytes
    - elapsed since first submission in batch >= BatchMaxLatency

BACKPRESSURE:

  Submit uses a non-blocking send to the queue. If the queue is full,
  Submit returns ErrQueueFull immediately; the HTTP handler maps to
  503 + Retry-After. This protects the operator from running out of
  memory or scheduler slots during burst load.

DURABILITY GUARANTEE:

  Badger is opened with SyncWrites=false so individual txn commits
  return after writing to the in-memory memtable + the WAL buffer
  (NOT after fsync). The committer goroutine calls db.Sync()
  explicitly after each batched commit, which flushes Badger's WAL
  to disk. Submit returns only after Sync has confirmed durability.

  Failure semantics: if db.Sync() errors, EVERY submission in that
  batch sees the same error. None proceeds to tessera.Add. Submitters
  retry on their side; the WAL is left in a "partial-but-not-
  acknowledged" state — entries that are present in the file but
  never produced a 202 are reconciled at startup as phantoms.
*/
package wal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// CommitterConfig configures NewCommitter.
type CommitterConfig struct {
	// QueueSize bounds the in-memory submission queue. When full,
	// Submit returns ErrQueueFull. Default 4096.
	QueueSize int

	// BatchMaxEntries triggers a group-commit flush when the in-flight
	// batch reaches this many submissions. Default 256.
	BatchMaxEntries int

	// BatchMaxBytes triggers a group-commit flush when the in-flight
	// batch's wire-byte total reaches this many bytes. Default 5 MiB.
	BatchMaxBytes int

	// BatchMaxLatency triggers a group-commit flush when the oldest
	// submission in the in-flight batch is this old. Bounds the p99
	// latency floor for Submit at light load. Default 10 ms.
	BatchMaxLatency time.Duration

	// DisableSync skips the post-batch db.Sync() call. Production
	// MUST leave this false — without Sync the durability guarantee
	// is broken. Tests that use in-memory Badger MUST set this true:
	// Badger's Sync() panics with a nil-pointer dereference when no
	// on-disk WAL file exists.
	DisableSync bool

	// Logger. Defaults to slog.Default if nil.
	Logger *slog.Logger
}

// Committer is the durable-bytes primitive. Methods are safe to call
// from multiple goroutines.
type Committer struct {
	db     *badger.DB
	cfg    CommitterConfig
	logger *slog.Logger

	in       chan *submission
	closing  chan struct{}
	closed   chan struct{}
	closedMu sync.Mutex
}

// submission is a per-Submit record handed to the commit goroutine.
type submission struct {
	hash          [32]byte
	wire          []byte
	logTimeMicros int64 // unix-micros, persisted in Meta for P5 idempotency
	done          chan error
}

// NewCommitter wraps an open Badger DB and starts the group-commit
// goroutine. Caller is responsible for opening the DB with
// SyncWrites=false (the committer manages fsync explicitly via
// db.Sync()) and for closing the DB after Close returns.
func NewCommitter(db *badger.DB, cfg CommitterConfig) *Committer {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.BatchMaxEntries <= 0 {
		cfg.BatchMaxEntries = 256
	}
	if cfg.BatchMaxBytes <= 0 {
		cfg.BatchMaxBytes = 5 << 20
	}
	if cfg.BatchMaxLatency <= 0 {
		cfg.BatchMaxLatency = 10 * time.Millisecond
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	c := &Committer{
		db:      db,
		cfg:     cfg,
		logger:  cfg.Logger,
		in:      make(chan *submission, cfg.QueueSize),
		closing: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	go c.commitLoop()
	return c
}

// Submit writes wire bytes to the WAL and blocks until they are
// fsync'd to disk. Returns ErrQueueFull when the in-memory queue is
// full (HTTP handler should map to 503), ErrEmptyWire on a nil/empty
// wire, ctx.Err() on cancellation, or the underlying Badger / Sync
// error if the group commit failed.
//
// logTimeMicros is the operator-assigned admission time (unix
// microseconds) that gets persisted in the Meta record. Used by the
// HTTP handler's deterministic-idempotency path (P5): a
// byte-identical resubmission reads back the persisted value and
// re-issues the SAME SCT bytes instead of returning 409 Conflict.
func (c *Committer) Submit(ctx context.Context, hash [32]byte, wire []byte, logTimeMicros int64) error {
	if len(wire) == 0 {
		return ErrEmptyWire
	}
	s := &submission{
		hash:          hash,
		wire:          wire,
		logTimeMicros: logTimeMicros,
		done:          make(chan error, 1),
	}
	select {
	case c.in <- s:
	case <-c.closing:
		return ErrClosed
	default:
		return ErrQueueFull
	}
	select {
	case err := <-s.done:
		return err
	case <-ctx.Done():
		// Submitter gave up before group commit completed. The
		// submission is still in flight; the commit goroutine will
		// flush its batch normally and write to a now-orphaned
		// done channel (buffered, so non-blocking). The bytes will
		// be durable on disk regardless — at-least-once semantics.
		return ctx.Err()
	case <-c.closing:
		return ErrClosed
	}
}

// Close stops the commit goroutine. In-flight batches are flushed
// before Close returns. Submissions arriving after Close return
// ErrClosed. Caller is responsible for closing the underlying Badger
// DB after Close returns.
func (c *Committer) Close() error {
	c.closedMu.Lock()
	defer c.closedMu.Unlock()
	select {
	case <-c.closing:
		return nil // already closed
	default:
		close(c.closing)
	}
	<-c.closed
	return nil
}

// commitLoop drains submissions, batches them, and group-commits.
func (c *Committer) commitLoop() {
	defer close(c.closed)

	var (
		batch        []*submission
		batchBytes   int
		batchTimer   = time.NewTimer(time.Hour) // long, never fires until reset
		timerRunning bool
	)
	batchTimer.Stop()

	flush := func(reason string) {
		if len(batch) == 0 {
			return
		}
		err := c.flushBatch(batch)
		for _, s := range batch {
			// Buffered done channel; non-blocking even if submitter
			// gave up via ctx.Done.
			s.done <- err
		}
		c.logger.Debug("wal: group commit",
			"reason", reason,
			"batch", len(batch),
			"bytes", batchBytes,
			"err", err,
		)
		batch = batch[:0]
		batchBytes = 0
		if timerRunning {
			batchTimer.Stop()
			timerRunning = false
		}
	}

	for {
		select {
		case <-c.closing:
			// Drain any pending submissions that already landed in
			// the channel (closing was signaled; nothing else will
			// be sent because Submit checks closing first).
			for {
				select {
				case s := <-c.in:
					batch = append(batch, s)
					batchBytes += len(s.wire)
				default:
					flush("close")
					return
				}
			}

		case s := <-c.in:
			if len(batch) == 0 {
				batchTimer.Reset(c.cfg.BatchMaxLatency)
				timerRunning = true
			}
			batch = append(batch, s)
			batchBytes += len(s.wire)
			if len(batch) >= c.cfg.BatchMaxEntries || batchBytes >= c.cfg.BatchMaxBytes {
				flush("size")
			}

		case <-batchTimer.C:
			timerRunning = false
			flush("latency")
		}
	}
}

// flushBatch opens one Badger txn covering all submissions, commits,
// then fsyncs. Returns the error to fan out to every submission's
// done channel.
func (c *Committer) flushBatch(batch []*submission) error {
	now := time.Now().UnixNano()
	err := c.db.Update(func(txn *badger.Txn) error {
		for _, s := range batch {
			// entry:<hash> = wire (immutable, write-once).
			// Re-Submit of byte-identical content overwrites with
			// identical bytes — no harm.
			if err := txn.Set(entryKey(s.hash), s.wire); err != nil {
				return fmt.Errorf("wal/committer: set entry: %w", err)
			}
			// meta:<hash>: Submit-on-existing-entry preserves the
			// existing State (Sequenced / Shipped) AND the original
			// LogTimeMicros. Without this, a re-Submit would
			// regress State Sequenced → Pending and overwrite the
			// original log_time, breaking deterministic
			// idempotency (P5).
			//
			// First-time Submit: write {State: Pending, LogTime:
			//                          this submission's micros}.
			var existing Meta
			if rerr := readMeta(txn, s.hash, &existing); rerr == nil {
				// Entry already exists — preserve everything. The
				// idempotent re-Submit reaches here.
			} else if errors.Is(rerr, ErrNotFound) ||
				errors.Is(rerr, badger.ErrKeyNotFound) {
				existing = Meta{
					State:         StatePending,
					LogTimeMicros: s.logTimeMicros,
				}
			} else {
				return fmt.Errorf("wal/committer: read meta: %w", rerr)
			}
			if err := txn.Set(metaKey(s.hash), encodeMeta(existing)); err != nil {
				return fmt.Errorf("wal/committer: set meta: %w", err)
			}
			// inflight:<hash> = now. Cleared by Sequence; scanned by
			// Reconcile on boot.
			ts := make([]byte, 8)
			for i := 0; i < 8; i++ {
				ts[i] = byte(now >> (56 - 8*i))
			}
			if err := txn.Set(inflightKey(s.hash), ts); err != nil {
				return fmt.Errorf("wal/committer: set inflight: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Single fsync for the whole batch — the load-bearing performance
	// property of group commit. Without this call, Badger commits
	// return when memtable is updated but the WAL has not been
	// flushed; submitters would see "success" before durability.
	//
	// Tests using in-memory Badger MUST disable this — Badger's
	// Sync() nil-derefs when there is no on-disk WAL. Production
	// MUST leave it enabled.
	if !c.cfg.DisableSync {
		if err := c.db.Sync(); err != nil {
			return fmt.Errorf("wal/committer: db.Sync: %w", err)
		}
	}
	return nil
}
