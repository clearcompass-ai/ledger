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
	retry counter (in-memory; resets on ledger restart). After
	cfg.MaxAttempts (default 10) the entry transitions to
	StateManual and the Sequencer stops attempting it; ledgers
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

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/crypto/escrow"
	sdkschema "github.com/clearcompass-ai/attesta/schema"

	"github.com/clearcompass-ai/ledger/lifecycle"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/wal"
)

// drainOnce drains the WAL of all currently-Pending entries. Any
// per-entry error is logged + counted; iteration continues. Per-
// entry work runs concurrently up to cfg.MaxInFlight, with the
// drain blocking until every worker completes.
//
// BACKPRESSURE STALL: when a LagReader is wired and the observed
// builder lag (admitted entries minus committed-by-builder
// entries) is at-or-above cfg.MaxBuilderLag, this cycle returns
// without consuming from the WAL. The WAL queue then saturates
// to wal.QueueSize and admission returns 503 Service Unavailable
// — the physical wire from a stalled builder to honest HTTP
// backpressure. The next cycle re-checks: as soon as the builder
// catches up below the threshold, drain resumes.
func (s *Sequencer) drainOnce(ctx context.Context) {
	if err := ctx.Err(); err != nil {
		return
	}
	s.metrics.drainCycles.Add(1)

	if s.lagReader != nil && s.cfg.MaxBuilderLag > 0 {
		lag, err := s.lagReader.Lag(ctx)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return
		case err != nil:
			// Don't fail the cycle on a transient Postgres blip; the
			// gate is best-effort and the next tick re-checks. Log
			// once at warn so chronic failures surface.
			s.logger.Warn("sequencer: lag probe failed; skipping gate",
				"error", err)
		case uint64(lag) >= s.cfg.MaxBuilderLag:
			s.metrics.backpressureStalls.Add(1)
			s.logger.Warn("sequencer: backpressure stall — builder lag at limit",
				"lag", lag, "max_builder_lag", s.cfg.MaxBuilderLag)
			return
		}
	}

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
			// Per-entry panic recovery. A bug in processOne for
			// one entry must not crash the binary; log + continue.
			// processOne already handles per-entry errors internally
			// (MarkRetry / MarkManual), so the SafeRun branch only
			// fires on a panic, not on a normal error path.
			_ = lifecycle.SafeRun(ctx, "sequencer-process-entry", s.logger, nil, func() error {
				s.processOne(ctx, hash)
				return nil
			})
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
	seq, err := s.tessera.AppendLeaf(ctx, hash[:])
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

	if err := store.WithReadCommittedTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
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
	}); err != nil {
		return err
	}

	// Postgres committed. Now write the splitid index entry to
	// the ledger-local Badger store (prefix 0x0A) so the
	// gossipnet.EquivocationScanner's db.Subscribe wakes and
	// detects collisions. AFTER the Postgres commit so a
	// rollback never leaves a stale index entry.
	//
	// Best-effort: a write failure here doesn't block the commit
	// path. Postgres still has the durable record; on ledger
	// restart the splitid index is rebuilt by replaying
	// entry_index (future migration — not in this PR's scope).
	if extractedSplitID != nil && s.splitIDIndex != nil && len(entry.Signatures) > 0 {
		idxEntry := SplitIDIndexEntry{
			EquivocatorDID: entry.Header.SignerDID,
			CanonicalHash:  hash,
			SigBytes:       append([]byte{}, entry.Signatures[0].Bytes...),
		}
		if werr := s.splitIDIndex.WriteSplitIDIndexEntry(
			ctx, extractedSchemaID, *extractedSplitID, seq, idxEntry,
		); werr != nil {
			s.logger.Warn("sequencer: splitid index write failed",
				"seq", seq, "schema_id", extractedSchemaID,
				"error", werr)
		}
	}

	// 0x0C entry-lookup projection (pure CQRS read path). Same write
	// discipline as 0x0A: AFTER the Postgres commit, best-effort,
	// non-blocking. The full canonical wire bytes are captured
	// here so the read endpoint serves /v1/commitments/by-split-id
	// without re-loading from Postgres or Tessera.
	if extractedSplitID != nil && s.entryLookup != nil {
		canonical, serr := envelope.Serialize(entry)
		if serr != nil {
			// Best-effort projection write only — log and skip.
			// The Postgres entry_index row is already durable; the
			// 0x0C projection is a read-side cache that the boot
			// replayer can rebuild from Postgres.
			s.logger.Warn("sequencer: entry-lookup serialize failed",
				"seq", seq, "schema_id", extractedSchemaID, "error", serr)
		} else {
			lookupEntry := EntryLookupIndexEntry{
				CanonicalBytes: canonical,
				LogTimeMicros:  entry.Header.EventTime,
				LogDID:         s.logDID,
			}
			if werr := s.entryLookup.WriteEntryLookupEntry(
				ctx, extractedSchemaID, *extractedSplitID, seq, lookupEntry,
			); werr != nil {
				s.logger.Warn("sequencer: entry lookup projection write failed",
					"seq", seq, "schema_id", extractedSchemaID,
					"error", werr)
			}
		}
	}
	return nil
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
