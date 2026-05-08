/*
FILE PATH: builder/commitment_publisher.go

Publishes SMT derivation commitments as commentary entries on the log.
Commentary: Target_Root=null, Authority_Path=null → zero SMT impact.

KEY ARCHITECTURAL DECISIONS:
  - Commentary entry: no SMT leaf created or modified.
  - Frequency controlled: every N entries OR every T duration, whichever first.
  - Commitment serialized as JSON in Domain Payload.
  - submitFn: signs and submits the commentary entry to the log.
    Uses SubmitViaHTTP (same pattern as anchor/publisher.go).
    nil submitFn = commitments computed but not published on the log.
  - WithCommitmentStore: optional persistence to derivation_commitments
    table for indexed lookup by fraud proof verifiers.
  - Destination-bound: commitments are commentary on THIS log,
    so Destination = LogDID. Threaded through constructor.

PERSISTENCE NOTE: Commitment persistence runs POST-COMMIT (loop.go
step 7). A crash between atomic commit and persistence loses the
commitment row. This is acceptable — the table is a lookup index, not
consensus-critical state. Rebuild by replaying entries if diverged.

submitFn NOTE: submitFn must be wired to a real submission path for
commentary entries to appear on the log. The anchor/publisher.go
pattern (SubmitViaHTTP) is the reference implementation. Until
submitFn is wired, the commentary_seq column in derivation_commitments
has no value.

SDK ALIGNMENT:
  - envelope.NewEntry(header, payload, signatures)  — fully signed
  - envelope.NewUnsignedEntry(header, payload)      — sign-then-attach
    The publisher constructs the commentary unsigned and hands it to
    submitFn for signing and submission, so the right constructor is
    NewUnsignedEntry. submitFn (or SubmitViaHTTP) is responsible for
    populating entry.Signatures before envelope.Serialize is invoked.
*/
package builder

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
)

// CommitmentPublisherConfig configures commitment frequency.
type CommitmentPublisherConfig struct {
	IntervalEntries int           // Entries between commitments (default 1000).
	IntervalTime    time.Duration // Max time between commitments (default 1h).
}

// CommitmentPublisher publishes derivation commitments.
type CommitmentPublisher struct {
	ledgerDID    string
	logDID       string // destination for self-published commentary.
	cfg          CommitmentPublisherConfig
	logger       *slog.Logger
	mu           sync.Mutex
	lastPublish  time.Time
	entriesSince int
	submitFn     func(entry *envelope.Entry) error
	commitStore  *store.CommitmentStore // nil = no table persistence
}

// NewCommitmentPublisher creates a commitment publisher.
//
// ledgerDID: the key DID signing the commentary entries.
// logDID:      the destination the commentary binds to (this ledger's log).
//
// logDID MUST be non-empty — envelope.NewUnsignedEntry will reject
// construction otherwise (destination-binding).
func NewCommitmentPublisher(
	ledgerDID string,
	logDID string,
	cfg CommitmentPublisherConfig,
	submitFn func(entry *envelope.Entry) error,
	logger *slog.Logger,
) *CommitmentPublisher {
	if cfg.IntervalEntries <= 0 {
		cfg.IntervalEntries = 1000
	}
	if cfg.IntervalTime <= 0 {
		cfg.IntervalTime = 1 * time.Hour
	}
	return &CommitmentPublisher{
		ledgerDID:   ledgerDID,
		logDID:      logDID,
		cfg:         cfg,
		submitFn:    submitFn,
		logger:      logger,
		lastPublish: time.Now(),
	}
}

// WithCommitmentStore enables persistence to the derivation_commitments table.
// Fluent setter — avoids changing constructor signature for existing callers.
func (cp *CommitmentPublisher) WithCommitmentStore(cs *store.CommitmentStore) *CommitmentPublisher {
	cp.commitStore = cs
	return cp
}

// MaybePublish checks if a commitment should be published based on frequency.
func (cp *CommitmentPublisher) MaybePublish(
	ctx context.Context,
	batchSize int,
	rangeStart, rangeEnd types.LogPosition,
	priorRoot [32]byte,
	result *sdkbuilder.BatchResult,
) {
	cp.mu.Lock()
	cp.entriesSince += batchSize
	shouldPublish := cp.entriesSince >= cp.cfg.IntervalEntries ||
		time.Since(cp.lastPublish) >= cp.cfg.IntervalTime
	if shouldPublish {
		cp.entriesSince = 0
		cp.lastPublish = time.Now()
	}
	cp.mu.Unlock()

	if !shouldPublish || result == nil || len(result.Mutations) == 0 {
		return
	}

	cp.publish(ctx, rangeStart, rangeEnd, priorRoot, result)
}

// ForcePublish publishes a commitment unconditionally.
func (cp *CommitmentPublisher) ForcePublish(
	ctx context.Context,
	rangeStart, rangeEnd types.LogPosition,
	priorRoot [32]byte,
	result *sdkbuilder.BatchResult,
) {
	if result == nil || len(result.Mutations) == 0 {
		return
	}
	cp.mu.Lock()
	cp.entriesSince = 0
	cp.lastPublish = time.Now()
	cp.mu.Unlock()

	cp.publish(ctx, rangeStart, rangeEnd, priorRoot, result)
}

func (cp *CommitmentPublisher) publish(
	ctx context.Context,
	rangeStart, rangeEnd types.LogPosition,
	priorRoot [32]byte,
	result *sdkbuilder.BatchResult,
) {
	commitment := sdkbuilder.GenerateBatchCommitment(rangeStart, rangeEnd, priorRoot, result)

	payload, err := json.Marshal(commitment)
	if err != nil {
		cp.logger.Error("commitment serialization failed", "error", err)
		return
	}

	// Build commentary entry: Target_Root=null, Authority_Path=null.
	// Destination = logDID — this commentary lands in the local log.
	//
	// NewUnsignedEntry per the envelope API split: this
	// publisher constructs the entry, submitFn signs and submits.
	// Fully-signed callers use envelope.NewEntry(header, payload, sigs).
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   cp.ledgerDID,
		Destination: cp.logDID,
		// EventTime in microseconds — matches what SDK
		// exchange/policy.CheckFreshness actually reads
		// (time.UnixMicro), not what the SDK docstring claims
		// (Unix seconds). Same fix as cmd/submit-stamp and
		// anchor/publisher.
		EventTime: time.Now().UTC().UnixMicro(),
	}, payload)
	if err != nil {
		cp.logger.Error("commitment entry creation failed", "error", err)
		return
	}

	// Submit commentary entry to the log (correction #6).
	if cp.submitFn != nil {
		if err := cp.submitFn(entry); err != nil {
			cp.logger.Error("commitment submission failed", "error", err)
			// Continue to persist even if submission fails — the commitment
			// data is still useful for fraud proof verification.
		}
	}

	// Persist to derivation_commitments table (correction #4).
	// Post-commit, best-effort. Crash here loses the row — acceptable
	// because commitments are reconstructable from entries.
	if cp.commitStore != nil {
		row := store.CommitmentRow{
			RangeStartSeq: rangeStart.Sequence,
			RangeEndSeq:   rangeEnd.Sequence,
			PriorSMTRoot:  priorRoot,
			PostSMTRoot:   commitment.PostSMTRoot,
			MutationsJSON: payload,
		}
		if insertErr := cp.commitStore.Insert(ctx, row); insertErr != nil {
			cp.logger.Error("commitment persistence failed", "error", insertErr)
		}
	}

	cp.logger.Info("derivation commitment published",
		"range_start", rangeStart.String(),
		"range_end", rangeEnd.String(),
		"mutations", commitment.MutationCount,
	)
}
