/*
FILE PATH:

	lifecycle/shutdown.go

DESCRIPTION:

	Ordered shutdown helper. Each registered step runs sequentially
	with its OWN bounded ctx (per-component timeout, no shared
	budget) so a slow tessera flush can't consume the budget that
	pgxpool.Close needs. After all steps finish, Summary returns
	per-component drain durations + errors for a final Info log.

KEY ARCHITECTURAL DECISIONS:
  - Steps run in REGISTRATION ORDER (not LIFO like Go defers).
    This is the load-bearing invariant: cmd/ledger registers
    steps in the order the I1 spec mandates (http.Shutdown →
    sequencer cancel+wait → shipper cancel+wait → bytestore →
    tessera → WAL → gossipstore → pgxpool → OTel) and Run
    executes that order verbatim.
  - Per-component timeouts (I2). A 30 s "shared" shutdown budget
    is a footgun: if step 3 (http.Shutdown) consumes 28 s,
    steps 4-11 get 2 s combined. Per-component budgets fix this
    structurally — every step gets exactly its allotment, no
    cross-talk.
  - Each step's fn is called via sync.Once so registering AND
    defer-fallback-calling the same step is idempotent. Keeps
    the boot-time panic-safety pattern (defer some.Close())
    compatible with the explicit Run path: whichever fires
    first does the work, the other becomes a no-op.
  - Summary returns a slice ordered by registration so the
    final log line shows the same sequence administrators registered.

OVERVIEW:

	Boot:
	    sc := lifecycle.NewShutdownChain(logger)
	    sc.Add("http-server", 30*time.Second, func(ctx) error {
	        return server.Shutdown(ctx)
	    })
	    sc.Add("sequencer", 10*time.Second, func(ctx) error {
	        seqCancel()
	        sequencerWG.Wait()
	        return nil
	    })
	    ... and so on for shipper, bytestore, tessera, WAL,
	    gossipstore, pgxpool, OTel ...

	Shutdown:
	    sc.Run(context.Background())
	    for _, step := range sc.Summary() {
	        logger.Info("shutdown step",
	            "name", step.Name,
	            "duration", step.Duration,
	            "err", step.Err)
	    }

KEY DEPENDENCIES:
  - context: per-component bounded ctx.
  - sync.Once: idempotent fn.
*/
package lifecycle

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// -------------------------------------------------------------------------------------------------
// 1) Step + chain
// -------------------------------------------------------------------------------------------------

// shutdownStep is one registered step in the chain.
type shutdownStep struct {
	name    string
	timeout time.Duration
	fn      func(ctx context.Context) error

	once     sync.Once
	duration time.Duration
	err      error
	ran      bool
}

// run executes the step's fn with a bounded ctx. Idempotent via
// sync.Once — safe to call from both ShutdownChain.Run and a
// defer fallback in case of boot panic.
func (s *shutdownStep) run() {
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		t0 := time.Now()
		s.err = s.fn(ctx)
		s.duration = time.Since(t0)
		s.ran = true
	})
}

// ShutdownChain orders + executes per-component shutdowns.
type ShutdownChain struct {
	logger *slog.Logger

	mu    sync.Mutex
	steps []*shutdownStep
}

// NewShutdownChain returns a ShutdownChain. logger may be nil
// (in which case step logs are suppressed).
func NewShutdownChain(logger *slog.Logger) *ShutdownChain {
	return &ShutdownChain{logger: logger}
}

// Add registers a step. The fn receives a per-component bounded
// ctx (timeout). Steps run in registration order when Run is
// called.
//
// Returns the step's run function so the caller can also stash
// it in a defer to cover boot-panic paths:
//
//	closer := sc.Add("bytestore", 10*time.Second, byteStore.Close)
//	defer closer()
//
// The defer fires ONLY if Run hasn't already executed the step;
// the sync.Once inside guarantees no double-close.
func (sc *ShutdownChain) Add(name string, timeout time.Duration, fn func(ctx context.Context) error) func() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	step := &shutdownStep{
		name:    name,
		timeout: timeout,
		fn:      fn,
	}
	sc.steps = append(sc.steps, step)
	return step.run
}

// Run executes all registered steps in registration order. Each
// step's bounded ctx applies independently — a slow tessera
// flush can't consume the budget that pgxpool needs. Errors
// from individual steps are logged but do not abort the chain;
// every step gets a chance to drain.
func (sc *ShutdownChain) Run() {
	sc.mu.Lock()
	steps := append([]*shutdownStep{}, sc.steps...)
	sc.mu.Unlock()
	for _, step := range steps {
		if sc.logger != nil {
			sc.logger.Info("shutdown step starting",
				"step", step.name,
				"timeout", step.timeout)
		}
		step.run()
		if sc.logger != nil {
			if step.err != nil {
				sc.logger.Warn("shutdown step errored",
					"step", step.name,
					"duration", step.duration,
					"err", step.err)
			} else {
				sc.logger.Info("shutdown step ok",
					"step", step.name,
					"duration", step.duration)
			}
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Summary surface (I3)
// -------------------------------------------------------------------------------------------------

// ShutdownStepSummary is one row in the final shutdown summary
// log line. Captured for I3 forensic forensic output.
type ShutdownStepSummary struct {
	Name     string
	Duration time.Duration
	Err      error
	Ran      bool
}

// Summary returns the per-step result slice in registration order.
// Steps that didn't run (because Run was never called, or the
// supervisor exited via panic before reaching them) have Ran=false.
func (sc *ShutdownChain) Summary() []ShutdownStepSummary {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	out := make([]ShutdownStepSummary, 0, len(sc.steps))
	for _, s := range sc.steps {
		out = append(out, ShutdownStepSummary{
			Name:     s.name,
			Duration: s.duration,
			Err:      s.err,
			Ran:      s.ran,
		})
	}
	return out
}
