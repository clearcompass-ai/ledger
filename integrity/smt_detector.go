/*
FILE PATH: integrity/smt_detector.go

SMT-root divergence detector — closes the symmetric gap left by
attesta v0.8.0's TreeHead.SMTRoot dual-commitment binding.

# WHAT THIS DEFENDS AGAINST

attesta v0.8.0 binds the SMT projection root into the witness-
cosigned TreeHead, so the witness K-of-N quorum signs both the
RFC 6962 chronological root AND the SMT state root atomically.
The ledger's builder loop computes a single SMT root per batch
and writes it BOTH into smt_root_state (consumed by /v1/smt/root)
AND into the head it submits to RequestCosignatures (which lands
in tree_heads.smt_root). The two writes are gated by the same
in-memory value (builder/loop.go::Step 6b) so they're equal at
write time.

This detector verifies they STAY equal at rest. Failure modes
caught:

  - Out-of-band Postgres tampering with smt_root_state.current_root
    (DBA mistake, attacker with DB access, replication lag bug).
  - smt_root_state corruption from an aborted-but-partially-applied
    transaction (would require a serializable-isolation bug; this
    detector is the canary).
  - Future refactor that decouples the smt_root_state write from
    the head-publish write (a regression that lets them drift would
    silently surface here).

# WHAT THIS DOES NOT CATCH

  - In-flight builder bugs that produce a wrong SMT root in
    BOTH writes from the same source value. A wrong root that's
    consistently wrong at both surfaces would still match. The
    upstream sdkbuilder.ProcessBatch correctness tests catch
    that class.

  - tree_heads.smt_root tampering (would require the cosignature
    re-verification detector, not this one). That detector is a
    natural follow-up — see integrity.go::"FUTURE WORK" hint.

# DETECTION SHAPE

Periodic loop. Each tick:

 1. Read smt_root_state {CurrentRoot, CommittedThroughSeq}.
 2. Look up the cosigned tree_head at TreeSize == CommittedThroughSeq.
 3. If no cosigned head exists yet at that seq, SKIP — transient
    state between batches; the next cycle will re-roll.
 4. If head.SMTRoot != smt_root_state.CurrentRoot: ErrSMTRootDiverged.
    The Detector returns the error; the composition root panics on
    it via the same fatal-channel pattern integrity.Detector uses.

# DISTINCT FROM integrity.Detector

The existing integrity.Detector samples WAL hash vs Tessera
chronological tile hash for individual seqs — the RFC 6962 leaf
binding. This detector samples the SMT projection binding at the
SAME-TreeSize boundary. They share zero state and run in parallel
goroutines from the composition root.

# OBSERVABILITY

Three orthogonal counters mirror integrity.Detector's shape:

  samplesVerified — Tick reached the comparison and SMTRoot matched
  samplesSkipped  — Tick bailed out (no cosigned head at current
                    committed_through_seq yet)
  invariantFailures — Tick detected a divergence (always 1 before
                    the FATAL panic terminates the process)

SREs use these to compute alignment-rate over a window. A
healthy ledger should be 100% verified within minutes after each
batch (the lag is the witness-cosignature collection cadence).
*/
package integrity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// ErrSMTRootDiverged is returned when smt_root_state.current_root
// disagrees with the cosigned tree_head's SMTRoot at the same
// TreeSize. Distinct sentinel from ErrDiverged so dimensional
// telemetry can attribute the alarm to the SMT-binding surface
// vs the chronological-log surface.
var ErrSMTRootDiverged = errors.New("integrity/smt: SMT root diverges from witness-cosigned head SMTRoot (panic)")

// SMTRootSnapshot is the in-memory shape of the smt_root_state
// row. Decoupled from store/ so the integrity package keeps its
// import surface narrow.
type SMTRootSnapshot struct {
	CurrentRoot         [32]byte
	CommittedThroughSeq uint64
}

// SMTRootStateReader reads the singleton smt_root_state row. The
// production wiring satisfies this with *store.SMTRootStateStore
// (Read method already returns the same shape).
type SMTRootStateReader interface {
	Read(ctx context.Context) (SMTRootSnapshot, error)
}

// CosignedHeadAtSizeReader fetches a cosigned tree_head at a
// specific TreeSize. Returns (nil, nil) when no head exists at
// that size yet — the detector treats that as "not yet alignable"
// and skips the cycle.
//
// Production wiring: a thin adapter over *store.TreeHeadStore.
// GetBySize that maps the apitypes return into this package's
// shape.
type CosignedHeadAtSizeReader interface {
	GetBySize(ctx context.Context, size uint64) (*apitypes.CosignedTreeHead, error)
}

// SMTDetectorConfig configures NewSMTDetector.
type SMTDetectorConfig struct {
	// SampleInterval is the period between Tick cycles. Default
	// 1 minute. Mirrors integrity.Detector's cadence.
	SampleInterval time.Duration

	// Logger receives diagnostic events. Defaults to slog.Default
	// when nil.
	Logger *slog.Logger
}

// SMTDetector periodically verifies that the SMT root persisted
// at smt_root_state matches the SMTRoot bound into the witness-
// cosigned tree head at the same TreeSize.
type SMTDetector struct {
	state  SMTRootStateReader
	heads  CosignedHeadAtSizeReader
	cfg    SMTDetectorConfig
	logger *slog.Logger

	samplesVerified   atomic.Uint64
	samplesSkipped    atomic.Uint64
	invariantFailures atomic.Uint64
}

// NewSMTDetector constructs a detector wired to the supplied
// readers. Both arguments are required; nil checks happen at
// first Tick for clear panic messages at the actual call site.
func NewSMTDetector(
	state SMTRootStateReader,
	heads CosignedHeadAtSizeReader,
	cfg SMTDetectorConfig,
) *SMTDetector {
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = 1 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SMTDetector{
		state:  state,
		heads:  heads,
		cfg:    cfg,
		logger: cfg.Logger,
	}
}

// Tick runs ONE alignment cycle.
//
// Returns nil on:
//   - successful match (smt_root_state.CurrentRoot == head.SMTRoot)
//   - transient skip (no cosigned head at the current committed_
//     through_seq yet — the witness collection lags one cosignature
//     cadence behind the builder)
//
// Returns ErrSMTRootDiverged on mismatch — the composition root
// panics on it.
//
// Returns a wrapped error on infrastructure failures (DB read
// errors). The Loop treats infra errors as terminal so SRE
// dashboards see the underlying outage; intermittent network
// blips are NOT swallowed.
func (d *SMTDetector) Tick(ctx context.Context) error {
	if d.state == nil || d.heads == nil {
		return errors.New("integrity/smt: Tick requires state + heads readers")
	}
	state, err := d.state.Read(ctx)
	if err != nil {
		return fmt.Errorf("integrity/smt: read smt_root_state: %w", err)
	}
	if state.CommittedThroughSeq == 0 {
		// Pre-first-batch boot. Nothing to verify yet.
		d.samplesSkipped.Add(1)
		d.logger.DebugContext(ctx, "integrity/smt: skip — no batches committed yet")
		return nil
	}
	head, err := d.heads.GetBySize(ctx, state.CommittedThroughSeq)
	if err != nil {
		return fmt.Errorf("integrity/smt: read tree_head at size=%d: %w",
			state.CommittedThroughSeq, err)
	}
	if head == nil {
		// Witness cosignature collection hasn't landed at this
		// TreeSize yet. Common between batches; don't alarm.
		d.samplesSkipped.Add(1)
		d.logger.DebugContext(ctx,
			"integrity/smt: skip — no cosigned head yet at current committed_through_seq",
			"committed_through_seq", state.CommittedThroughSeq)
		return nil
	}
	if head.SMTRoot != state.CurrentRoot {
		d.invariantFailures.Add(1)
		return fmt.Errorf("%w: tree_size=%d state_root=%x head_smt_root=%x",
			ErrSMTRootDiverged,
			state.CommittedThroughSeq,
			state.CurrentRoot[:8],
			head.SMTRoot[:8])
	}
	d.samplesVerified.Add(1)
	d.logger.DebugContext(ctx, "integrity/smt: aligned",
		"tree_size", state.CommittedThroughSeq,
		"smt_root", fmt.Sprintf("%x", state.CurrentRoot[:8]),
	)
	return nil
}

// Loop runs Tick on a ticker until ctx is cancelled or Tick
// returns an error other than ctx cancellation.
//
// Returns ctx.Err() on graceful shutdown; ErrSMTRootDiverged on
// a divergence; or the wrapped infra error on a DB read failure.
func (d *SMTDetector) Loop(ctx context.Context) error {
	ticker := time.NewTicker(d.cfg.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := d.Tick(ctx); err != nil {
				if errors.Is(err, ErrSMTRootDiverged) {
					d.logger.ErrorContext(ctx,
						"integrity/smt: divergence detected",
						"err", err)
				}
				return err
			}
		}
	}
}

// SamplesVerified returns the cumulative count of Tick cycles
// that aligned successfully. Pairs with InvariantFailures +
// SamplesSkipped for SRE rate computation.
func (d *SMTDetector) SamplesVerified() uint64 {
	return d.samplesVerified.Load()
}

// SamplesSkipped returns the cumulative count of Tick cycles
// that bailed out before reaching the comparison (no cosigned
// head at current committed_through_seq).
func (d *SMTDetector) SamplesSkipped() uint64 {
	return d.samplesSkipped.Load()
}

// InvariantFailures returns the cumulative count of Tick cycles
// that detected a divergence. Always at most 1 in production
// (the composition root panics on the FIRST divergence) — the
// counter exists for symmetry with integrity.Detector and for
// unit-test inspection.
func (d *SMTDetector) InvariantFailures() uint64 {
	return d.invariantFailures.Load()
}
