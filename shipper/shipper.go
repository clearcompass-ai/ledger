/*
Package shipper migrates StateSequenced entries from the local WAL
to the production byte store (GCS / S3). Watches the WAL for
sequenced-but-unshipped entries, uploads them with bounded
concurrency, marks them StateShipped, and advances the WAL's
high-water mark through contiguous runs.

PIPELINE STAGES:

  1. scan         — every PollInterval, IterateSequenced(fromSeq=HWM)
                    yields candidate entries. Per-entry meta is
                    consulted to enforce exponential backoff on
                    retried uploads.
  2. dispatch     — entries are pushed onto a bounded work channel.
                    Workers pull from the channel.
  3. ship         — N concurrent workers Read wire bytes from the
                    WAL, WriteEntry to the bytestore, MarkShipped
                    in the WAL, then signal completion.
  4. advance HWM  — single hwmAdvancer goroutine drains completion
                    signals and advances the WAL's HWM only through
                    contiguous runs. Out-of-order completions are
                    held in an in-memory above-HWM set until their
                    predecessor lands.

OUT-OF-ORDER COMPLETION:

  Workers can complete in any order (network jitter, retry timing,
  per-entry size differences). HWM must only advance over a
  contiguous run from HWM+1, otherwise read paths that promise
  "HWM is the highest shipped seq" would lie. The hwmAdvancer
  enforces this invariant with a single-goroutine state machine
  and an in-memory completed-above-HWM set.

BACKOFF + RETRY:

  Upload failure → wal.MarkRetry (Attempts++, LastErrTs=now). The
  scan loop's backoff filter checks LastErrTs + backoff(Attempts);
  entries inside their backoff window are skipped on this scan
  cycle and re-evaluated on the next.

  After MaxAttempts, an entry is marked StateManual. Bytes stay in
  the WAL (no DLQ — no separate storage tier); the operator's
  metrics surface the manual queue for human intervention.

LIFECYCLE:

  Run blocks until ctx is cancelled. The composition root listens
  on a fatal channel so any unrecoverable Shipper error (none in
  the current implementation — all Shipper errors are per-entry
  and logged) propagates to panic.
*/
package shipper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/clearcompass-ai/ledger/wal"
)

// WAL is the WAL surface the Shipper depends on. *wal.Committer
// satisfies it structurally; tests inject fakes.
type WAL interface {
	HWM(ctx context.Context) (uint64, error)
	AdvanceHWM(ctx context.Context, seq uint64) error
	IterateSequenced(ctx context.Context, fromSeq uint64, fn func(wal.SequencedEntry) error) error
	Read(ctx context.Context, hash [32]byte) ([]byte, error)
	MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error)
	MarkShipped(ctx context.Context, hash [32]byte) error
	MarkRetry(ctx context.Context, hash [32]byte) error
	MarkManual(ctx context.Context, hash [32]byte) error
}

// Bytestore is the upload surface. bytestore.Writer satisfies it
// (we deliberately narrow to Writer here — Shipper does not read
// from the bytestore; that's the read-path's job).
type Bytestore interface {
	WriteEntry(ctx context.Context, seq uint64, hash [32]byte, wireBytes []byte) error
}

// Config configures NewShipper.
type Config struct {
	// PollInterval bounds how often the scanner checks for new
	// work when the worker channel drains. Default 1s.
	PollInterval time.Duration

	// MaxInFlight bounds concurrent uploads. Default 4.
	MaxInFlight int

	// MaxAttempts caps per-entry retries. After this many failed
	// upload attempts, the entry is marked StateManual and the
	// shipper stops retrying it. Default 10.
	MaxAttempts uint32

	// BackoffBase is the initial retry delay. Doubles each attempt
	// up to BackoffMax. Default 1s.
	BackoffBase time.Duration

	// BackoffMax caps the exponential backoff. Default 60s.
	BackoffMax time.Duration

	// Logger. Defaults to slog.Default if nil.
	Logger *slog.Logger
}

// Shipper is the sequenced→shipped pipeline.
type Shipper struct {
	wal       WAL
	bytestore Bytestore
	cfg       Config
	logger    *slog.Logger

	completion chan uint64 // worker → hwmAdvancer
	metrics    Metrics
}

// NewShipper wires the pipeline. Both wal and bytestore are
// required. cfg is normalized; zero-valued fields get sensible
// defaults.
func NewShipper(w WAL, bs Bytestore, cfg Config) *Shipper {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 1 * time.Second
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = 4
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 10
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 1 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 60 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Shipper{
		wal:        w,
		bytestore:  bs,
		cfg:        cfg,
		logger:     cfg.Logger,
		completion: make(chan uint64, cfg.MaxInFlight*4),
	}
}

// Metrics returns a snapshot of the shipper's atomic counters.
// Safe to call concurrently with Run.
func (s *Shipper) Metrics() MetricsSnapshot {
	return s.metrics.Snapshot()
}

// Run starts the pipeline and blocks until ctx is cancelled. All
// goroutines (workers + hwmAdvancer + scanner) shut down cleanly
// before Run returns.
//
// Returns ctx.Err() on graceful shutdown.
func (s *Shipper) Run(ctx context.Context) error {
	if s.wal == nil || s.bytestore == nil {
		return errors.New("shipper: WAL and Bytestore both required")
	}

	workCh := make(chan wal.SequencedEntry, s.cfg.MaxInFlight*2)
	var workersWG sync.WaitGroup
	for i := 0; i < s.cfg.MaxInFlight; i++ {
		workersWG.Add(1)
		go s.worker(ctx, workCh, &workersWG)
	}

	advancerDone := make(chan struct{})
	go func() {
		defer close(advancerDone)
		s.hwmAdvancer(ctx)
	}()

	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	// First scan immediately so the shipper picks up backlog at
	// startup without waiting one PollInterval.
	s.scanAndDispatch(ctx, workCh)

scanLoop:
	for {
		select {
		case <-ctx.Done():
			break scanLoop
		case <-ticker.C:
			s.scanAndDispatch(ctx, workCh)
		}
	}

	// Graceful shutdown: close work channel, wait for workers to
	// drain in-flight items, then close completion channel and
	// wait for the advancer.
	close(workCh)
	workersWG.Wait()
	close(s.completion)
	<-advancerDone
	return ctx.Err()
}

// scanAndDispatch performs one cycle of the WAL → workCh pump.
// Yields control as soon as the work channel is full — the next
// tick will resume.
func (s *Shipper) scanAndDispatch(ctx context.Context, workCh chan<- wal.SequencedEntry) {
	hwm, err := s.wal.HWM(ctx)
	if err != nil {
		s.logger.Error("shipper: read HWM", "err", err)
		return
	}

	now := time.Now()
	dispatched := 0
	skippedBackoff := 0

	err = s.wal.IterateSequenced(ctx, hwm, func(e wal.SequencedEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Backoff filter: previously-failed entries wait for
		// LastErrTs + backoff(Attempts) before retrying.
		meta, mErr := s.wal.MetaState(ctx, e.Hash)
		if mErr != nil {
			s.logger.Error("shipper: read meta", "seq", e.Seq, "err", mErr)
			return nil
		}
		if meta.Attempts > 0 {
			retryAt := meta.LastErrTs.Add(s.backoffFor(meta.Attempts))
			if now.Before(retryAt) {
				skippedBackoff++
				return nil
			}
		}

		select {
		case workCh <- e:
			dispatched++
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Worker channel full; stop scanning, the next
			// tick will resume from the same fromSeq.
			return iterStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, iterStop) {
		s.logger.Error("shipper: iterate sequenced", "err", err)
	}
	if dispatched > 0 || skippedBackoff > 0 {
		s.logger.Debug("shipper: scan complete",
			"dispatched", dispatched,
			"skipped_backoff", skippedBackoff,
			"hwm", hwm)
	}
}

// iterStop is returned from the IterateSequenced callback to break
// out of the iteration without surfacing as a real error. Caller
// (scanAndDispatch) checks errors.Is(err, iterStop) and does not log.
var iterStop = errors.New("shipper: iteration paused (workers full)")

// worker pulls SequencedEntry values from workCh and ships each.
// Exits when workCh is closed.
func (s *Shipper) worker(ctx context.Context, workCh <-chan wal.SequencedEntry, wg *sync.WaitGroup) {
	defer wg.Done()
	for entry := range workCh {
		s.shipOne(ctx, entry)
	}
}

// shipOne performs the upload + state transition for a single
// SequencedEntry. Failures fan into MarkRetry / MarkManual; success
// fans into MarkShipped + completion-channel signal for the HWM
// advancer.
func (s *Shipper) shipOne(ctx context.Context, e wal.SequencedEntry) {
	if err := ctx.Err(); err != nil {
		return
	}
	start := time.Now()

	wire, err := s.wal.Read(ctx, e.Hash)
	if err != nil {
		s.logger.Error("shipper: WAL read", "seq", e.Seq, "err", err)
		s.recordFailure(ctx, e)
		return
	}

	if err := s.bytestore.WriteEntry(ctx, e.Seq, e.Hash, wire); err != nil {
		s.logger.Warn("shipper: bytestore upload failed",
			"seq", e.Seq, "err", err)
		s.recordFailure(ctx, e)
		return
	}

	if err := s.wal.MarkShipped(ctx, e.Hash); err != nil {
		// Bytes are already in the bytestore; failing to record
		// shipped state is recoverable on next scan (the entry
		// remains StateSequenced and we'll re-upload — bytestore
		// is content-addressed so this is idempotent).
		s.logger.Error("shipper: MarkShipped", "seq", e.Seq, "err", err)
		s.metrics.markShippedFailures.Add(1)
		return
	}

	s.metrics.shipped.Add(1)
	s.metrics.shipLatencyNanos.Add(time.Since(start).Nanoseconds())
	s.metrics.shipLatencySamples.Add(1)

	// Signal the HWM advancer.
	select {
	case s.completion <- e.Seq:
	case <-ctx.Done():
	}
}

// recordFailure increments the retry counter or transitions the
// entry to StateManual after MaxAttempts.
func (s *Shipper) recordFailure(ctx context.Context, e wal.SequencedEntry) {
	meta, err := s.wal.MetaState(ctx, e.Hash)
	if err != nil {
		s.logger.Error("shipper: read meta on failure", "seq", e.Seq, "err", err)
		return
	}
	if meta.Attempts+1 >= s.cfg.MaxAttempts {
		if err := s.wal.MarkManual(ctx, e.Hash); err != nil {
			s.logger.Error("shipper: MarkManual", "seq", e.Seq, "err", err)
			return
		}
		s.logger.Warn("shipper: entry exhausted retries — marked manual",
			"seq", e.Seq,
			"attempts", meta.Attempts+1)
		s.metrics.manual.Add(1)
		return
	}
	if err := s.wal.MarkRetry(ctx, e.Hash); err != nil {
		s.logger.Error("shipper: MarkRetry", "seq", e.Seq, "err", err)
		return
	}
	s.metrics.retries.Add(1)
}

// backoffFor returns the delay before the (attempt+1)-th try.
// Exponential: base * 2^(attempt-1), capped at BackoffMax.
func (s *Shipper) backoffFor(attempt uint32) time.Duration {
	if attempt == 0 {
		return 0
	}
	d := s.cfg.BackoffBase << (attempt - 1)
	if d <= 0 || d > s.cfg.BackoffMax {
		return s.cfg.BackoffMax
	}
	return d
}

// ─────────────────────────────────────────────────────────────────────
// HWM advancer (separate file for readability; defined here as
// method on Shipper for unit-test access).
// ─────────────────────────────────────────────────────────────────────

// hwmAdvancer drains the completion channel and advances HWM only
// through contiguous runs. Single goroutine — the only writer to
// HWM in the whole system.
func (s *Shipper) hwmAdvancer(ctx context.Context) {
	above := make(map[uint64]struct{})
	for {
		select {
		case <-ctx.Done():
			return
		case seq, ok := <-s.completion:
			if !ok {
				return // channel closed during shutdown
			}
			s.processCompletion(ctx, seq, above)
		}
	}
}

// processCompletion handles a single completion signal: advances
// HWM through the contiguous run starting at HWM+1, holding any
// out-of-order completions in `above` until their predecessor lands.
func (s *Shipper) processCompletion(ctx context.Context, seq uint64, above map[uint64]struct{}) {
	hwm, err := s.wal.HWM(ctx)
	if err != nil {
		s.logger.Error("shipper/hwm: read HWM", "err", err)
		// Stash the seq above so we don't drop it.
		above[seq] = struct{}{}
		return
	}
	if seq <= hwm {
		// Already covered by HWM (e.g., re-ship via test). No-op.
		return
	}
	if seq > hwm+1 {
		// Out-of-order: hold until predecessor lands.
		above[seq] = struct{}{}
		return
	}
	// seq == hwm+1: this is the next contiguous one. Advance through
	// the run.
	newHWM := seq
	for {
		next := newHWM + 1
		if _, ok := above[next]; !ok {
			break
		}
		delete(above, next)
		newHWM = next
	}
	if err := s.wal.AdvanceHWM(ctx, newHWM); err != nil {
		s.logger.Error("shipper/hwm: AdvanceHWM", "newHWM", newHWM, "err", err)
		// Re-stash the unwritten contiguous seqs so the next
		// completion cycle retries.
		for q := seq; q <= newHWM; q++ {
			above[q] = struct{}{}
		}
		return
	}
	s.metrics.hwm.Store(newHWM)
	s.logger.Debug("shipper/hwm: advanced",
		"hwm", newHWM,
		"above_set_size", len(above))
}

// ─────────────────────────────────────────────────────────────────────
// Helper: time formatting for tests
// ─────────────────────────────────────────────────────────────────────

// String returns a human-readable summary for diagnostic logging.
func (s *Shipper) String() string {
	snap := s.Metrics()
	return fmt.Sprintf("shipper{shipped=%d retries=%d manual=%d hwm=%d}",
		snap.Shipped, snap.Retries, snap.Manual, snap.HWM)
}
