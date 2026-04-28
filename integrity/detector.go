/*
FILE PATH: integrity/detector.go

Detector — the periodic and boot-time agreement check between the
operator's WAL and the embedded Tessera log. Two surfaces:

  Reconcile (boot, one-shot):
    Iterate WAL inflight breadcrumbs. For each, re-Add to Tessera
    via the Reasserter. The dedup makes this idempotent. Push the
    resulting seq back into the WAL via WALReassertSink.Sequence.

    Tolerates partial-failure: a single re-Add error logs and
    continues so a transient failure on one entry doesn't block
    reconciliation of the rest. The composition root MAY run
    Reconcile on a failed return path, but is NOT required to —
    inflight entries that didn't reconcile this boot will retry
    on the next boot.

  Loop (running, periodic):
    Sample N random sequences below HWM. For each, compare:
      WAL.HashAt(seq)        ← what admission recorded
      Tessera.HashAt(seq)    ← what the Merkle tree commits to
    Mismatch → return ErrDiverged. Composition root panics.

    The samples-per-cycle and tick interval are configurable.
    Production defaults: 3 samples per minute. With a uniform
    distribution over [1, HWM], divergence detection latency at
    HWM=10B is roughly HWM / (samples_per_cycle * cycles_per_day).
    Combine with the boot-time full reconciliation for tight
    guarantees.

PANIC SEMANTICS:
  Detector itself never panics. It returns ErrDiverged. The
  composition root in cmd/operator/main.go is responsible for
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

// Detector orchestrates Reconcile + Loop against a WAL and a
// Tessera-backed Verifier+Reasserter pair.
type Detector struct {
	wal        WALReader
	inflight   InflightIterator
	sink       WALReassertSink
	verifier   Verifier
	reasserter Reasserter
	cfg        DetectorConfig
	logger     *slog.Logger

	rngMu sync.Mutex // guards rng — math/rand.Rand is not goroutine-safe
}

// NewDetector returns a Detector wired to the supplied surfaces.
// All five arguments are required; nil checks happen at first use
// for clear panic messages.
//
// The Verifier and Reasserter typically come from a single
// *TesseraAdapter (NewTesseraAdapter). The WAL and Sink are
// typically the same *wal.Committer; the InflightIterator is a thin
// closure over the committer's IterateInflight method.
func NewDetector(
	wal WALReader,
	inflight InflightIterator,
	sink WALReassertSink,
	verifier Verifier,
	reasserter Reasserter,
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
		wal:        wal,
		inflight:   inflight,
		sink:       sink,
		verifier:   verifier,
		reasserter: reasserter,
		cfg:        cfg,
		logger:     cfg.Logger,
	}
}

// Reconcile runs the boot-time reconciliation. Iterates WAL
// inflight entries; for each, re-Asserts against Tessera and
// transitions the WAL state.
//
// Returns nil even when individual entries fail — partial failure
// is logged and reconciliation continues. Returns a hard error only
// when the iteration itself fails (e.g., Badger transport error).
//
// On exit, the WAL's inflight set has been emptied for any entry
// Tessera accepted. Entries Tessera refused (ErrPhantom-like)
// remain in inflight for the next boot to re-attempt.
func (d *Detector) Reconcile(ctx context.Context) error {
	if d.inflight == nil || d.sink == nil || d.reasserter == nil {
		return errors.New("integrity/detector: Reconcile requires inflight iterator, sink, reasserter")
	}

	var (
		recovered int
		failed    int
		startTime = time.Now()
	)

	err := d.inflight(ctx, func(hash [32]byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		seq, err := d.reasserter.Reassert(ctx, hash)
		if err != nil {
			d.logger.Error("integrity/detector: reassert failed",
				"hash", fmt.Sprintf("%x", hash[:8]),
				"err", err,
			)
			failed++
			return nil // skip this one, keep iterating
		}
		if err := d.sink.Sequence(ctx, hash, seq); err != nil {
			d.logger.Error("integrity/detector: WAL sequence failed",
				"hash", fmt.Sprintf("%x", hash[:8]),
				"seq", seq,
				"err", err,
			)
			failed++
			return nil
		}
		recovered++
		return nil
	})
	if err != nil {
		return fmt.Errorf("integrity/detector: iterate inflight: %w", err)
	}

	d.logger.Info("integrity/detector: reconciliation complete",
		"recovered", recovered,
		"failed", failed,
		"duration", time.Since(startTime),
	)
	return nil
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
