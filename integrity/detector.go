/*
FILE PATH: integrity/detector.go

Detector — the periodic agreement check between the ledger's
WAL and the embedded Tessera log. Read-only verifier; does not
mutate either side.

	Loop (periodic):
	  Sample N random sequences below HWM. For each, compare:
	    WAL.HashAt(seq)        ← what admission recorded
	    Tessera.HashAt(seq)    ← what the Merkle tree commits to
	  Mismatch → return ErrDiverged. Composition root panics.

	  The samples-per-cycle and tick interval are configurable.
	  Production defaults: 3 samples per minute. With a uniform
	  distribution over [1, HWM], divergence detection latency at
	  HWM=10B is roughly HWM / (samples_per_cycle * cycles_per_day).

BOOT RECOVERY:

	No longer this package's concern. The Sequencer drains
	StatePending entries on Run start (sequencer/sequencer.go),
	which subsumes the old Reasserter/Reconcile path with the
	added benefit of also INSERTing entry_index rows.

PANIC SEMANTICS:

	Detector itself never panics. It returns ErrDiverged. The
	composition root in cmd/ledger/main.go is responsible for
	panic-on-fatal — that's the infra-agnostic boundary.
*/
package integrity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"
)

// DetectorConfig configures NewDetector.
type DetectorConfig struct {
	// SampleInterval is the period between Loop sampling cycles.
	// Default 1 minute.
	SampleInterval time.Duration

	// SamplesPerCycle is the number of random sequences sampled
	// per cycle. Default 3. Set to 0 to disable periodic checks
	// (boot reconciliation still runs).
	SamplesPerCycle int

	// Rand is the source of randomness for sample selection.
	// Default: a per-process rng seeded with time.Now().UnixNano().
	// Tests inject deterministic sources.
	Rand *rand.Rand

	// Logger. Defaults to slog.Default if nil.
	Logger *slog.Logger
}

// Detector runs the periodic Loop against a WAL and a
// Tessera-backed Verifier. Read-only — never mutates either side.
type Detector struct {
	wal      WALReader
	verifier Verifier
	cfg      DetectorConfig
	logger   *slog.Logger

	rngMu sync.Mutex // guards rng — math/rand.Rand is not goroutine-safe
}

// NewDetector returns a Detector wired to the supplied surfaces.
// Both arguments are required; nil checks happen at first use
// for clear panic messages.
//
// The Verifier typically comes from a *TesseraAdapter
// (NewTesseraAdapter). The WAL is typically the ledger's
// *wal.Committer.
func NewDetector(
	wal WALReader,
	verifier Verifier,
	cfg DetectorConfig,
) *Detector {
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = 1 * time.Minute
	}
	if cfg.SamplesPerCycle == 0 {
		cfg.SamplesPerCycle = 3
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Detector{
		wal:      wal,
		verifier: verifier,
		cfg:      cfg,
		logger:   cfg.Logger,
	}
}

// SampleVerify runs ONE sampling cycle: pick SamplesPerCycle random
// sequences in [1, HWM] and check WAL.HashAt == Verifier.HashAt for
// each. Returns ErrDiverged on the first mismatch.
//
// Returns nil when HWM is 0 (no shipped entries to sample yet).
func (d *Detector) SampleVerify(ctx context.Context) error {
	if d.wal == nil || d.verifier == nil {
		return errors.New("integrity/detector: SampleVerify requires wal + verifier")
	}
	hwm, err := d.wal.HWM(ctx)
	if err != nil {
		return fmt.Errorf("integrity/detector: read HWM: %w", err)
	}
	if hwm == 0 {
		return nil
	}

	for i := 0; i < d.cfg.SamplesPerCycle; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		seq := d.pickSeq(hwm)

		walHash, err := d.wal.HashAt(ctx, seq)
		if err != nil {
			// Sequence not in WAL — possible if the entry was
			// shipped + GC'd. Skip rather than treating as
			// divergence; the GC retention buffer is the
			// invariant that prevents this in production.
			d.logger.Debug("integrity/detector: sample skipped (WAL miss)",
				"seq", seq, "err", err)
			continue
		}
		tesseraHash, err := d.verifier.HashAt(ctx, seq)
		if err != nil {
			return fmt.Errorf("integrity/detector: verifier seq=%d: %w", seq, err)
		}
		if walHash != tesseraHash {
			return fmt.Errorf("%w: seq=%d wal=%x tessera=%x",
				ErrDiverged, seq, walHash[:], tesseraHash[:])
		}
		d.logger.Debug("integrity/detector: sample ok",
			"seq", seq,
			"hash", fmt.Sprintf("%x", walHash[:8]),
		)
	}
	return nil
}

// Loop runs SampleVerify on a ticker until ctx is cancelled or the
// detector returns ErrDiverged. The composition root reads the
// returned error from a fatal channel and panics on it.
//
// Returns ctx.Err() on graceful shutdown; ErrDiverged on a
// disagreement; or any other Verifier/WAL error encountered.
func (d *Detector) Loop(ctx context.Context) error {
	ticker := time.NewTicker(d.cfg.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := d.SampleVerify(ctx); err != nil {
				if errors.Is(err, ErrDiverged) {
					d.logger.Error("integrity/detector: divergence detected",
						"err", err)
				}
				return err
			}
		}
	}
}

// pickSeq returns a uniformly-random seq in [1, hwm].
func (d *Detector) pickSeq(hwm uint64) uint64 {
	d.rngMu.Lock()
	defer d.rngMu.Unlock()
	// Int63n with hwm > 0; +1 so we land in [1, hwm].
	// hwm can be larger than int63 only at scale we don't reach here
	// (10B << 2^63), but clamp defensively.
	if hwm > 1<<62 {
		hwm = 1 << 62
	}
	return uint64(d.cfg.Rand.Int63n(int64(hwm))) + 1
}
