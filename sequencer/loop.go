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

	Bounded concurrency across entries (cfg.MaxInFlight) is enforced
	by a buffered channel acting as a semaphore. The Tessera antispam
	dedup means re-Add of the same hash is idempotent, so concurrent
	processOne calls on distinct hashes are safe — Tessera serializes
	the antispam path internally and the Postgres
	WithReadCommittedTx insulates entry_index + commitment_split_id
	inserts. drainOnce blocks until every spawned worker completes,
	so cycle metrics (currentLag, processed) reflect the actual
	post-cycle state.
*/
package sequencer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	sdkschema "github.com/clearcompass-ai/ortholog-sdk/schema"

	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// drainOnce drains the WAL of all currently-Pending entries. Any
// per-entry error is logged + counted; iteration continues. Per-
// entry work runs concurrently up to cfg.MaxInFlight, with the
// drain blocking until every worker completes.
func (s *Sequencer) drainOnce(ctx context.Context) {
	if err := ctx.Err(); err != nil {
		return
	}
	s.metrics.drainCycles.Add(1)

	// Semaphore caps in-flight processOne workers. Buffered to
	// MaxInFlight; sending blocks the iterator when the sem is full.
	sem := make(chan struct{}, s.cfg.MaxInFlight)
	var wg sync.WaitGroup

	var pending int64
	err := s.wal.IterateInflight(ctx, func(p wal.PendingHash) error {
		if err := ctx.Err(); err != nil {
			// Iterator's stop signal; not a per-entry failure.
			return err
		}
		pending++

		// Acquire a slot — respect ctx cancellation while waiting.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}

		wg.Add(1)
		hash := p.Hash // capture by value for the goroutine
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.processOne(ctx, hash)
		}()
		return nil
	})

	// Wait for every goroutine spawned this cycle to complete
	// before recording metrics — currentLag must reflect the
	// state after this drain, not mid-flight.
	wg.Wait()

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
	extractedSplitID, extractedSchemaID, dispatchErr := dispatchCommitmentSchema(entry)
	if dispatchErr != nil {
		return fmt.Errorf("commitment schema: %w", dispatchErr)
	}

	return store.WithReadCommittedTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.store.Insert(ctx, tx, store.EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  hash,
			LogTime:        logTime,
			SignerDID:      entry.Header.SignerDID,
			TargetRoot:     targetRoot,
			CosignatureOf:  cosigOf,
			SchemaRef:      schemaRef,
		}); err != nil {
			return err
		}
		if extractedSplitID != nil {
			if _, err := tx.Exec(ctx, `
				INSERT INTO commitment_split_id (sequence_number, schema_id, split_id)
				VALUES ($1, $2, $3)`,
				seq, extractedSchemaID, extractedSplitID[:],
			); err != nil {
				return fmt.Errorf("commitment_split_id insert: %w", err)
			}
		}
		return nil
	})
}

type commitmentPayloadPeek struct {
	SchemaID string `json:"schema_id"`
}

func dispatchCommitmentSchema(entry *envelope.Entry) (*[32]byte, string, error) {
	if entry == nil || len(entry.DomainPayload) == 0 {
		return nil, "", nil
	}
	var peek commitmentPayloadPeek
	if err := json.Unmarshal(entry.DomainPayload, &peek); err != nil {
		return nil, "", nil
	}
	switch peek.SchemaID {
	case artifact.PREGrantCommitmentSchemaID:
		commitment, err := sdkschema.ParsePREGrantCommitmentEntry(entry)
		if err != nil {
			return nil, "", err
		}
		sid := commitment.SplitID
		return &sid, artifact.PREGrantCommitmentSchemaID, nil
	case escrow.EscrowSplitCommitmentSchemaID:
		commitment, err := sdkschema.ParseEscrowSplitCommitmentEntry(entry)
		if err != nil {
			return nil, "", err
		}
		sid := commitment.SplitID
		return &sid, escrow.EscrowSplitCommitmentSchemaID, nil
	default:
		return nil, "", nil
	}
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
