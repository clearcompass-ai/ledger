/*
FILE PATH: sequencer/loop.go

drainOnce — one cycle of the Sequencer pipeline. Companion to
sequencer.go which owns the lifecycle (Run, ticker, supervisor
shape).

PER-ENTRY PIPELINE:

  for each StatePending entry in WAL.IterateInflight:
    1. Re-probe MetaState — skip if no longer Pending (concurrent
       drain or v1 facade picked it up).
    2. wal.Read(hash) → wire bytes.
    3. envelope.Deserialize(wire) → recover header metadata for
       entry_index INSERT.
    4. tessera.AppendLeaf(hash[:]) → assigned seq.
       Antispam dedup makes this idempotent under retries: a
       second AppendLeaf for the same hash returns the same seq.
    5. WithReadCommittedTx: store.Insert(EntryRow{seq, hash, ...}).
       UNIQUE(canonical_hash) collisions are tolerated — they
       indicate a previous drain cycle already won this race.
    6. wal.Sequence(hash, seq) — pending → sequenced.

ERROR HANDLING:

  Per-entry errors don't abort the iteration. Each entry tracks a
  retry counter (in-memory; resets on operator restart). After
  cfg.MaxAttempts (default 10) the entry transitions to
  StateManual and the Sequencer stops attempting it; operators
  inspect WAL state and take action.

  Transient failures (Tessera transport blip, Postgres lock
  contention) hit MarkRetry and exponential backoff before the
  next cycle picks them up again.

CONCURRENCY:

  The drain is single-goroutine within a single drainOnce call.
  Bounded concurrency across entries (cfg.MaxInFlight) is
  intentionally NOT used here because the per-entry work
  serializes through Tessera + Postgres anyway. If profiling
  shows headroom we can parallelize within a cycle later; today
  the cost is a sequential walk of (hash, AppendLeaf, INSERT,
  Sequence) that runs at single-digit milliseconds per entry on
  warm caches.
*/
package sequencer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"

	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// drainOnce drains the WAL of all currently-Pending entries. Any
// per-entry error is logged + counted; the iteration continues.
func (s *Sequencer) drainOnce(ctx context.Context) {
	if err := ctx.Err(); err != nil {
		return
	}
	s.metrics.drainCycles.Add(1)

	var pending int64
	err := s.wal.IterateInflight(ctx, func(p wal.PendingHash) error {
		if err := ctx.Err(); err != nil {
			// Iterator's stop signal; not a per-entry failure.
			return err
		}
		pending++
		s.processOne(ctx, p.Hash)
		// Continue iteration regardless of per-entry result.
		// processOne handles its own logging + state transitions.
		return nil
	})
	s.metrics.currentLag.Store(pending)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		s.logger.Error("sequencer: drain iterate", "error", err)
	}
}

// processOne runs the per-entry pipeline. Error paths log,
// increment counters, and trigger MarkRetry / MarkManual; they
// never bubble up to the iteration.
func (s *Sequencer) processOne(ctx context.Context, hash [32]byte) {
	// Step 1: state guard.
	meta, err := s.wal.MetaState(ctx, hash)
	if err != nil {
		if errors.Is(err, wal.ErrNotFound) {
			// Entry was GC'd between iterator snapshot and now.
			s.resetAttempts(hash)
			return
		}
		s.logger.Error("sequencer: meta probe", "hash", hashPrefix(hash), "error", err)
		s.metrics.failures.Add(1)
		return
	}
	if meta.State != wal.StatePending {
		// Already past Pending — another drain cycle, the v1
		// facade, or boot recovery already advanced this entry.
		s.resetAttempts(hash)
		return
	}

	// Step 2: read wire bytes.
	wire, err := s.wal.Read(ctx, hash)
	if err != nil {
		s.handleEntryError(ctx, hash, "wal read", err)
		return
	}

	// Step 3: deserialize for metadata extraction.
	entry, err := envelope.Deserialize(wire)
	if err != nil {
		// Deserialization failure on durable WAL bytes is
		// catastrophic — those bytes admitted, so they passed
		// envelope.NewUnsignedEntry at submit time. Treat as
		// permanent and transition to Manual immediately.
		s.logger.Error("sequencer: deserialize WAL bytes — transitioning to Manual",
			"hash", hashPrefix(hash), "error", err)
		s.metrics.failures.Add(1)
		s.metrics.manualCount.Add(1)
		if mErr := s.wal.MarkManual(ctx, hash); mErr != nil {
			s.logger.Error("sequencer: MarkManual after deserialize", "error", mErr)
		}
		s.resetAttempts(hash)
		return
	}

	// Step 4: Tessera AppendLeaf — antispam-idempotent under
	// retries.
	seq, err := s.tessera.AppendLeaf(hash[:])
	if err != nil {
		s.handleEntryError(ctx, hash, "tessera AppendLeaf", err)
		return
	}

	// Step 5: Postgres entry_index INSERT inside a transaction.
	if err := s.insertEntryIndex(ctx, seq, hash, entry); err != nil {
		// UNIQUE collision on canonical_hash: a prior drain or
		// the v1 facade beat us. Idempotent — fall through to
		// the WAL state transition.
		if !isUniqueViolation(err) {
			s.handleEntryError(ctx, hash, "entry_index insert", err)
			return
		}
		s.logger.Debug("sequencer: entry_index already inserted (idempotent)",
			"seq", seq, "hash", hashPrefix(hash))
	}

	// Step 6: WAL state transition pending → sequenced.
	if err := s.wal.Sequence(ctx, hash, seq); err != nil {
		// At-least-once: the entry IS sequenced in Tessera and
		// indexed in Postgres. WAL state lag is recoverable —
		// the next drain cycle re-probes MetaState and short-
		// circuits at Step 1.
		s.handleEntryError(ctx, hash, "wal Sequence", err)
		return
	}

	s.metrics.processed.Add(1)
	s.resetAttempts(hash)
	s.logger.Debug("sequencer: entry sequenced",
		"seq", seq, "hash", hashPrefix(hash))
}

// insertEntryIndex runs the entry_index INSERT inside a
// ReadCommitted transaction. Mirrors the path the old inline
// admission step 12 took.
func (s *Sequencer) insertEntryIndex(
	ctx context.Context,
	seq uint64,
	hash [32]byte,
	entry *envelope.Entry,
) error {
	if s.db == nil || s.store == nil {
		// Test mode: nil DB skips the INSERT entirely. Real
		// production wiring requires both.
		return nil
	}
	var targetRoot, cosigOf, schemaRef []byte
	if entry.Header.TargetRoot != nil {
		targetRoot = store.SerializeLogPosition(*entry.Header.TargetRoot)
	}
	if entry.Header.CosignatureOf != nil {
		cosigOf = store.SerializeLogPosition(*entry.Header.CosignatureOf)
	}
	if entry.Header.SchemaRef != nil {
		schemaRef = store.SerializeLogPosition(*entry.Header.SchemaRef)
	}
	// EventTime is microseconds since epoch (matches the SDK's
	// freshness check unit). Zero means a pre-EventTime entry or
	// a corrupted header; fall back to the zero time.Time which
	// store.EntryRow accepts as "unknown".
	var logTime time.Time
	if entry.Header.EventTime != 0 {
		logTime = time.UnixMicro(entry.Header.EventTime).UTC()
	}

	return store.WithReadCommittedTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		return s.store.Insert(ctx, tx, store.EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  hash,
			LogTime:        logTime,
			SignerDID:      entry.Header.SignerDID,
			TargetRoot:     targetRoot,
			CosignatureOf:  cosigOf,
			SchemaRef:      schemaRef,
		})
	})
}

// handleEntryError centralizes the retry-vs-manual decision for a
// per-entry failure. Increments attempt counter, marks WAL state,
// updates metrics.
func (s *Sequencer) handleEntryError(ctx context.Context, hash [32]byte, op string, cause error) {
	attempt := s.recordAttempt(hash)
	s.metrics.failures.Add(1)
	s.logger.Warn("sequencer: per-entry failure",
		"op", op, "hash", hashPrefix(hash),
		"attempt", attempt, "max", s.cfg.MaxAttempts,
		"error", cause,
	)
	if attempt >= s.cfg.MaxAttempts {
		s.metrics.manualCount.Add(1)
		if err := s.wal.MarkManual(ctx, hash); err != nil {
			s.logger.Error("sequencer: MarkManual",
				"hash", hashPrefix(hash), "error", err)
		}
		s.resetAttempts(hash)
		return
	}
	if err := s.wal.MarkRetry(ctx, hash); err != nil {
		s.logger.Error("sequencer: MarkRetry",
			"hash", hashPrefix(hash), "error", err)
	}
}

// hashPrefix returns the first 8 bytes of a hash as a hex prefix
// — useful for log lines without dumping the full 64 hex chars.
func hashPrefix(h [32]byte) string {
	return fmt.Sprintf("%x", h[:8])
}

// isUniqueViolation reports whether err wraps a Postgres
// UNIQUE-constraint violation. pgx surfaces these via
// pgconn.PgError with SQLSTATE 23505; we string-match rather
// than typed-switch so this package doesn't acquire a pgconn
// dependency for one error path.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{"23505", "duplicate key value", "UNIQUE constraint"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
