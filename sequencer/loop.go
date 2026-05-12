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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/crypto/escrow"
	sdkschema "github.com/clearcompass-ai/attesta/schema"

	"github.com/clearcompass-ai/ledger/chaos"
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

	// Per-cycle work budget. After dispatching MaxEntriesPerCycle
	// entries the iterator returns errCycleBudget; drainOnce waits
	// for in-flight workers and exits. The ticker re-enters
	// drainOnce on its next firing for the next batch.
	//
	// Why: without a per-cycle bound a single drainOnce iterates the
	// whole inflight queue (could be 60K+ entries under load) and
	// wg.Wait blocks until ALL of them finish — a "cycle" lasting
	// minutes. The drainCycles metric becomes useless as a liveness
	// signal, shutdown is unbounded, and memory pressure scales with
	// queue depth instead of concurrency.
	var dispatched int
	err := s.wal.IterateInflight(ctx, func(p wal.PendingHash) error {
		if err := ctx.Err(); err != nil {
			// Iterator's stop signal; not a per-entry failure.
			return err
		}
		if s.cfg.MaxEntriesPerCycle > 0 && dispatched >= s.cfg.MaxEntriesPerCycle {
			// Stop iteration cleanly; the budget-exhausted error is
			// expected and not logged as failure below.
			return errCycleBudget
		}
		dispatched++

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
			// Per-entry panic recovery. A bug in processOne for one
			// entry must not crash the binary; log + continue.
			// processOne already handles per-entry errors internally
			// (MarkRetry / MarkManual); recover() here only fires on
			// an actual panic, not on a normal error path.
			//
			// Inline rather than lifecycle.SafeRun because the latter
			// emits INFO-level "goroutine started" + "goroutine stopped"
			// lines per call — at 10K entries × 4 in-flight that's
			// 80K log lines for a single soak. Hot path needs panic
			// safety, not lifecycle telemetry.
			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, 4096)
					n := runtime.Stack(buf, false)
					s.logger.Error("sequencer: processOne panic recovered",
						"goroutine", "sequencer-process-entry",
						"hash", hashPrefix(hash),
						"panic", fmt.Sprintf("%v", r),
						"stack", string(buf[:n]),
					)
				}
			}()
			s.processOne(ctx, hash)
		}()
		return nil
	})

	// Wait for every goroutine spawned this cycle to complete
	// before recording metrics — currentLag must reflect the
	// state after this drain, not mid-flight.
	wg.Wait()

	// currentLag = dispatched is a per-cycle proxy: how many entries
	// the iterator OBSERVED this cycle. When the iteration stops on
	// the budget, dispatched == MaxEntriesPerCycle. When the queue
	// drains below the budget, dispatched < budget. Either way it's
	// a real signal of work this cycle.
	s.metrics.currentLag.Store(int64(dispatched))
	if err != nil &&
		!errors.Is(err, errCycleBudget) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		s.logger.Error("sequencer: drain iterate", "error", err)
	}
}

// errCycleBudget is returned by the IterateInflight callback when
// the per-cycle work budget (MaxEntriesPerCycle) is exhausted. It
// is an intentional stop signal, not a failure — drainOnce filters
// it out of the error log.
var errCycleBudget = errors.New("sequencer: per-cycle work budget exhausted")

// processOne runs the per-entry STAGE-1 pipeline: MetaState guard,
// WAL read, deserialize, Tessera AppendLeaf, then emit a stagedEntry
// tuple to commitCh for the committer goroutine to atomically batch
// into entry_index. Error paths log, increment counters, and trigger
// MarkRetry / MarkManual; they never bubble up to the iteration.
//
// STAGE-1 / STAGE-2 SPLIT:
//
//	Stage-1 (this function, runs in MaxInFlight parallel workers):
//	  Step 1. MetaState guard — skip if no longer Pending.
//	  Step 2. wal.Read → wire bytes.
//	  Step 3. envelope.Deserialize → header metadata.
//	  Step 4. tessera.AppendLeaf → assigned seq.
//	  Step 5. dispatchCommitmentSchema → split-id (if applicable).
//	  Step 6. Build stagedEntry; emit to commitCh.
//
//	Stage-2 (committer goroutine, singleton — see committer.go):
//	  Step 7. Pop contiguous prefix from min-heap.
//	  Step 8. Batched INSERT into entry_index (+ commitment_split_id).
//	  Step 9. Per-entry WAL.Sequence / MarkManual (post-commit).
//	  Step 10. Sidecar writes 0x0A (splitid index), 0x0C (entry lookup).
//
// THE INVARIANT THE SPLIT ENFORCES:
//
//	Steps 1-4 are idempotent under retries. Once Tessera.AppendLeaf
//	returns, the seq is irrevocably allocated; the stage-1 worker
//	MUST emit a tuple to commitCh (live or tombstone) or the
//	committer's heap stalls forever waiting for that seq. The
//	tombstone routing below covers the only post-AppendLeaf failure
//	currently reachable in stage-1 (dispatchCommitmentSchema
//	parse error); any future post-AppendLeaf work that could fail
//	permanently MUST emit a tombstone via the same path or risk the
//	deadlock.
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

	// Step 3: deserialize for metadata extraction. PRE-AppendLeaf —
	// no tombstone needed if this fails because no seq has been
	// assigned yet. Deserialization failure on durable WAL bytes is
	// catastrophic — those bytes were admitted, so they passed
	// envelope.NewUnsignedEntry at submit time. Treat as permanent
	// and transition to Manual immediately.
	entry, err := envelope.Deserialize(wire)
	if err != nil {
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
	// retries. POINT OF NO RETURN: once this returns, `seq` exists
	// in Tessera permanently. From here, every code path MUST emit
	// a tuple to commitCh (live or tombstone) or risk deadlocking
	// the committer's contiguous-prefix drain.
	//
	// IN-FLIGHT TRACKING: increment BEFORE the synchronous AppendLeaf
	// call and decrement AFTER it returns (regardless of outcome).
	// This means tesseraInFlight reflects exactly the count of
	// workers currently blocked inside Tessera's antispam future
	// resolution — the silent-stall failure mode where Tessera's
	// integration loop hangs and no observations are recorded by
	// tesseraLatency (because AppendLeaf never returns). The high-
	// water mark is updated via CAS so a peak that has since
	// receded is still visible in the snapshot.
	inFlight := s.metrics.tesseraInFlight.Add(1)
	for {
		hw := s.metrics.tesseraInFlightHighWater.Load()
		if inFlight <= hw || s.metrics.tesseraInFlightHighWater.CompareAndSwap(hw, inFlight) {
			break
		}
	}
	tesseraStart := time.Now()
	seq, err := s.tessera.AppendLeaf(ctx, hash[:])
	// Chaos injection point #1 — "post_appendleaf":
	// Tessera has assigned the seq but the staged-entry tuple
	// hasn't been emitted yet. A kill here tests the WAL/Tessera
	// recovery path: Tessera dedupes on re-AppendLeaf (same hash
	// → same seq), so on restart the seq is re-assigned and
	// flows through normally. No production-build cost: chaos.Trigger
	// is a no-op compiled to nothing in default builds.
	chaos.Trigger("post_appendleaf")
	s.metrics.tesseraInFlight.Add(-1)
	if err != nil {
		// No seq assigned — normal retry path. Tombstone NOT needed.
		s.handleEntryError(ctx, hash, "tessera AppendLeaf", err)
		return
	}
	tesseraElapsed := time.Since(tesseraStart)
	// Aggregate observation — feeds the end-of-run / end-of-soak
	// summary that answers "does Tessera saturate at MaxInFlight=N".
	// Lock-free; safe to call from every stage-1 worker concurrently.
	s.metrics.tesseraLatency.Observe(tesseraElapsed)
	// Per-entry probe — DEBUG so it surfaces only when explicitly
	// enabled for forensics. INFO-level production runs see the
	// committer's batch-level log lines instead (one per ~16 entries),
	// which carry the same correlatable seq + timing info at a sane
	// signal-to-noise ratio.
	s.logger.Debug("sequencer: tessera seq assigned (committer enqueue pending)",
		"seq", seq,
		"hash", hashPrefix(hash),
		"tessera_elapsed", tesseraElapsed.Round(time.Microsecond),
	)

	// Step 5: parse commitment-schema sidecar info. dispatchErr
	// here is a post-AppendLeaf failure — Tessera owns the seq but
	// the entry's domain payload couldn't be schema-dispatched, so
	// we route to a tombstone to preserve the committer's
	// contiguous-prefix invariant. The hash is still valid; only
	// the projection-side metadata is dropped.
	extractedSplitID, extractedSchemaID, dispatchErr := s.dispatchCommitmentSchema(entry)
	if dispatchErr != nil {
		s.logger.Error("sequencer: post-AppendLeaf dispatchCommitmentSchema error — routing to tombstone",
			"seq", seq, "hash", hashPrefix(hash), "error", dispatchErr)
		s.emitTombstone(ctx, seq, hash, fmt.Sprintf("dispatchCommitmentSchema: %v", dispatchErr))
		return
	}

	// Step 6: build the staged tuple and emit to commitCh. The
	// pre-built EntryRow lets the committer batch-INSERT N tuples
	// without per-entry serialization work in the critical section.
	tuple := s.buildLiveStagedEntry(seq, hash, entry, extractedSplitID, extractedSchemaID)
	// Stamp the emit time at the moment of channel send (not at
	// buildLiveStagedEntry construction) so commitRaceWindow and
	// staleAge measurements include the actual time-in-channel as
	// well as the time-in-heap.
	tuple.emittedAt = time.Now()

	select {
	case s.commitCh <- tuple:
		// Queued — committer will batch + commit + transition WAL
		// state. Per-entry metrics fire from inside the committer
		// (see committer.go::applyPostCommitForOne).
	case <-ctx.Done():
		// Shutdown — entry stays in WAL Pending state. On restart,
		// drainOnce re-fetches; AppendLeaf returns same seq
		// (idempotent via Tessera antispam); the tuple is rebuilt
		// and emitted again. No state loss.
		s.logger.Warn("sequencer: ctx cancelled before committer enqueue",
			"seq", seq, "hash", hashPrefix(hash))
	}
}

// buildLiveStagedEntry assembles a stagedEntry for a normal (live)
// entry: extracts the EventTime, serializes the LogPositions, and
// populates the entry_index Row + optional commitment-split-id
// sidecar payload.
func (s *Sequencer) buildLiveStagedEntry(
	seq uint64,
	hash [32]byte,
	entry *envelope.Entry,
	extractedSplitID *[32]byte,
	extractedSchemaID string,
) stagedEntry {
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

	tuple := stagedEntry{
		Seq:       seq,
		Hash:      hash,
		Tombstone: false,
		Entry:     entry,
		Row: store.EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  hash,
			LogTime:        logTime,
			SignerDID:      entry.Header.SignerDID,
			TargetRoot:     targetRoot,
			CosignatureOf:  cosigOf,
			SchemaRef:      schemaRef,
			Status:         store.StatusLive,
		},
	}
	if extractedSplitID != nil {
		tuple.HasSplitID = true
		tuple.SplitID = *extractedSplitID
		tuple.SchemaID = extractedSchemaID
	}
	return tuple
}

// emitTombstone is the post-AppendLeaf safety valve. Tessera has
// assigned `seq` for `hash`, but the entry cannot be projected
// normally (e.g., dispatchCommitmentSchema parse error). We emit
// a tombstone tuple so the committer's contiguous-prefix drain
// advances past `seq` instead of stalling. The entry_index row
// carries the real hash but the metadata fields are NULL and
// signer_did = TombstoneSignerDID.
//
// Reason is logged when the committer transitions WAL state to
// Manual (see committer.go::applyPostCommitForOne). Auditors
// querying /v1/entries/{seq} for a tombstoned seq receive a
// definitive "manual" status response rather than an infinite 404.
func (s *Sequencer) emitTombstone(ctx context.Context, seq uint64, hash [32]byte, reason string) {
	tuple := stagedEntry{
		Seq:       seq,
		Hash:      hash,
		Tombstone: true,
		Reason:    reason,
		Row: store.EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  hash,
			LogTime:        time.Now().UTC(),
			SignerDID:      store.TombstoneSignerDID,
			Status:         store.StatusTombstone,
		},
		// Tombstones have no Entry / sidecar fields; explicit zero
		// for readability.
		Entry:      nil,
		HasSplitID: false,
		// Same emit-stamp discipline as buildLiveStagedEntry: set
		// here for the histogram observability path.
		emittedAt: time.Now(),
	}
	select {
	case s.commitCh <- tuple:
	case <-ctx.Done():
		// Shutdown before tombstone enqueued. WAL state is still
		// Pending; on restart, drainOnce re-fetches and stage-1
		// re-runs. dispatchCommitmentSchema will produce the same
		// error and re-emit the tombstone.
		s.logger.Warn("sequencer: ctx cancelled before tombstone enqueue",
			"seq", seq, "hash", hashPrefix(hash))
	}
}

type commitmentPayloadPeek struct {
	SchemaID string `json:"schema_id"`
}

// dispatchCommitmentSchema decides whether an entry carries a
// commitment schema we recognize, validates it via the v0.4.0 DI
// schema registry (when wired), and parses it to extract the
// SplitID.
//
// Order of operations:
//
//  1. JSON-peek the SchemaID. Non-JSON or missing → not a
//     commitment, return (nil, "", nil) — caller stages without
//     SplitID indexing.
//  2. If a schema registry is wired (production path), consult
//     Registry.Has: an unknown SchemaID is treated as no-
//     commitment (back-compat: pre-registry deployments and test
//     fixtures both produce that result). For a known SchemaID,
//     Registry.ValidateEntry runs as the admission gate. A
//     validator error here is a structural rejection — the caller
//     emits a tombstone.
//  3. Parse the entry via the SDK's typed parser to extract the
//     SplitID. Post-validation the parse cannot fail for
//     structural reasons but the SDK contract still surfaces an
//     error path; we propagate it (defensive) and the caller
//     tombstones.
//
// When schemaRegistry is nil (test fixtures), the legacy hard-
// coded switch runs verbatim — preserves existing test behaviour
// without requiring every test to construct a registry.
func (s *Sequencer) dispatchCommitmentSchema(entry *envelope.Entry) (*[32]byte, string, error) {
	if entry == nil || len(entry.DomainPayload) == 0 {
		return nil, "", nil
	}
	var peek commitmentPayloadPeek
	if err := json.Unmarshal(entry.DomainPayload, &peek); err != nil {
		return nil, "", nil
	}

	// Production path — registry-driven admission.
	if s.schemaRegistry != nil {
		sid := sdkschema.SchemaID(peek.SchemaID)
		if !s.schemaRegistry.Has(sid) {
			// Unbound SchemaID: not a commitment we recognize.
			// Stage the entry without SplitID indexing — same
			// semantic as the default branch of the legacy switch.
			return nil, "", nil
		}
		if err := s.schemaRegistry.ValidateEntry(sid, entry); err != nil {
			// Admission rejection. Caller emits a tombstone via
			// the dispatchErr path in processOne.
			return nil, "", err
		}
		// Validated: parse to extract the SplitID. The parse
		// re-deserializes the payload; the cost is small relative
		// to the AppendLeaf that already ran for this entry, and
		// the defense-in-depth is worth keeping (a future Validator
		// might tolerate a payload the legacy parser rejects).
		switch peek.SchemaID {
		case artifact.PREGrantCommitmentSchemaID:
			commitment, err := sdkschema.ParsePREGrantCommitmentEntry(entry)
			if err != nil {
				return nil, "", err
			}
			out := commitment.SplitID
			return &out, artifact.PREGrantCommitmentSchemaID, nil
		case escrow.EscrowSplitCommitmentSchemaID:
			commitment, err := sdkschema.ParseEscrowSplitCommitmentEntry(entry)
			if err != nil {
				return nil, "", err
			}
			out := commitment.SplitID
			return &out, escrow.EscrowSplitCommitmentSchemaID, nil
		default:
			// Registry.Has returned true but no parser branch — this
			// would indicate the registry was bound to a SchemaID we
			// don't have an in-process parser for, a wiring error in
			// boot/schemareg. Surface as a dispatch error.
			return nil, "", fmt.Errorf("dispatchCommitmentSchema: %s is registry-bound but has no SplitID parser",
				peek.SchemaID)
		}
	}

	// Legacy path — preserved verbatim for tests that haven't
	// wired a registry. Production code MUST go through the
	// registry branch above (wire.go enforces this at boot).
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
