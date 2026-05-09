/*
FILE PATH:

	tests/shutdownchain_test.go

DESCRIPTION:

	Single source of truth for ordered test-harness teardown. Every
	test harness (startTestLedgerWithOpts, startE2ELedger,
	startShutdownLedger, startSoakLedger) registers exactly ONE
	t.Cleanup that calls shutdownChain.Run — never multiple
	Cleanups, never raw cancel() calls scattered across registrations.

WHY:

	t.Cleanup runs LIFO. Splitting teardown across multiple Cleanups
	makes the order an accident of registration history, which is
	fragile to refactor. Worse, if the order is wrong, Tessera's
	background integration goroutine exits (in response to ctx.Done)
	BEFORE tessera.Close has a chance to publish a checkpoint that
	covers all already-issued indices. Any IndexFuture for an entry
	that was issued an index but not yet integrated is then stranded
	— future.Get blocks on a sync.WaitGroup.Wait with no ctx
	parameter (see tessera/internal/future/future.go:52, intentional
	for memory efficiency), so the calling goroutine is pinned for
	the rest of the test process lifetime.

	The fix is the spec-correct ordering: tessera.Close must run
	BEFORE cancel(). tessera.Close calls upstream Shutdown, which
	polls the checkpoint until it commits to the largest already-
	issued index. The integration goroutine MUST be alive during
	this poll (so it can publish the checkpoint), which is why
	cancel() comes after Close, not before.

	NOTE: do NOT try to "fix" this by wrapping ctx with
	context.WithoutCancel at NewEmbeddedAppender — that prevents
	the integration goroutine from EVER stopping (Tessera.Shutdown
	does not terminate the goroutine; it only refuses new Adds and
	polls the checkpoint). The goroutine listens to ctx for
	termination; that contract is documented at upstream NewAppender.

ORDER (matches the spec the production teardown chain enforces in
cmd/ledger/boot/teardown/teardown.go):

	1. server.Shutdown        — refuse new HTTP requests; drain in-flight
	2. tessera.Close          — drain Tessera pending futures; this
	                            unblocks any sequencer AppendLeaf calls
	                            that were waiting on a future
	3. cancel root ctx        — sequencer / shipper / builder loops
	                            see ctx.Done() and exit
	4. wait for goroutines    — bounded by the shutdown budget; the
	                            in-flight calls already returned in
	                            step 2, so wg.Wait completes promptly
	5. walc / walDB / pool    — release WAL + Postgres resources

	cleanTables runs between walDB.Close and pool.Close so the next
	test starts with a clean slate (the helper TRUNCATEs known tables;
	pool must still be open).
*/
package tests

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	optessera "github.com/clearcompass-ai/ledger/tessera"
	"github.com/clearcompass-ai/ledger/wal"
)

// serverShutdowner is the minimal interface satisfied by both
// *http.Server and *api.Server. Lets shutdownChain step 1 work with
// either harness (e2e_shipper_redirect_test.go uses *http.Server;
// startTestLedgerWithOpts wraps with *api.Server).
type serverShutdowner interface {
	Shutdown(ctx context.Context) error
}

// defaultShutdownBudget is the upper bound on how long a single
// shutdownChain.Run is allowed to take. Tessera's checkpoint-poll-
// until-done loop in upstream Shutdown can take a few seconds when
// the integration has just finished a batch; 30s is comfortable
// without masking real hangs.
const defaultShutdownBudget = 30 * time.Second

// shutdownChain is the value-typed orchestrator used by every
// test-harness factory in tests/. Construct, register in a single
// t.Cleanup, call .Run().
//
// Every field is OPTIONAL — nil/empty fields are skipped. This lets
// harnesses with different compositions (read-only reader, full
// builder, e2e-without-builder, etc.) share one helper.
type shutdownChain struct {
	Logger *slog.Logger

	// Step 1: HTTP server. server.Shutdown refuses new requests
	// and drains in-flight ones inside the shutdown budget. The
	// interface accepts both *http.Server and *api.Server.
	Server serverShutdowner

	// Step 2: Tessera. tessera.Close calls upstream Shutdown which
	// drains pending IndexFuture's by polling the integrated
	// checkpoint until it covers the largest issued index.
	Tessera *optessera.EmbeddedAppender

	// Step 3: cancel the root ctx. After step 2 returns, in-flight
	// Tessera calls have all resolved, so the sequencer / shipper /
	// builder goroutines can exit cleanly when ctx.Done() fires.
	Cancel context.CancelFunc

	// Step 4: wait for background goroutines to exit. Each entry is
	// a done channel that the goroutine closes when its Run method
	// returns. Bounded by the shutdown budget.
	GoroutineDone []<-chan struct{}

	// Step 5: release WAL + Postgres resources. walc.Close flushes
	// pending commit batches; walDB.Close releases Badger's file
	// locks; pool.Close drains the pgxpool.
	WALC  *wal.Committer
	WALDB *badger.DB
	Pool  *pgxpool.Pool

	// CleanTables (optional) runs between walDB.Close and pool.Close
	// so the next test starts with empty Postgres state.
	CleanTables func()

	// Budget overrides defaultShutdownBudget. Pass a smaller value
	// for fast tests; pass a larger value for tests that submit
	// large batches whose Tessera batch-flush may not have completed
	// by the time the test ends.
	Budget time.Duration
}

// Run executes the chain in spec order, logging warnings (never
// failing) on per-step errors. Test failures should be asserted on
// the test body's outcomes, not on teardown — teardown's job is to
// avoid leaking goroutines / file descriptors / Postgres connections
// into the next test.
func (s shutdownChain) Run() {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	budget := s.Budget
	if budget <= 0 {
		budget = defaultShutdownBudget
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), budget)
	defer shutdownCancel()

	// Step 1.
	if s.Server != nil {
		if err := s.Server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("shutdownchain: server.Shutdown", "err", err)
		}
	}

	// Step 2 — load-bearing. Close calls upstream Shutdown, which
	// polls the checkpoint until it covers all already-issued
	// indices. Must run BEFORE step 3's cancel() so the integration
	// goroutine is still alive to publish the checkpoint. Skipping
	// or reordering this strands pending IndexFutures — future.Get
	// blocks uninterruptibly on sync.WaitGroup.Wait.
	if s.Tessera != nil {
		if err := s.Tessera.Close(shutdownCtx); err != nil {
			logger.Warn("shutdownchain: tessera.Close", "err", err)
		}
	}

	// Step 3.
	if s.Cancel != nil {
		s.Cancel()
	}

	// Step 4. drain in-flight goroutines, bounded.
	if len(s.GoroutineDone) > 0 {
		var wg sync.WaitGroup
		wg.Add(len(s.GoroutineDone))
		for i, done := range s.GoroutineDone {
			i, done := i, done
			go func() {
				defer wg.Done()
				select {
				case <-done:
				case <-shutdownCtx.Done():
					logger.Warn("shutdownchain: goroutine did not drain in budget",
						"index", i, "budget", budget)
				}
			}()
		}
		wg.Wait()
	}

	// Step 5.
	if s.WALC != nil {
		if err := s.WALC.Close(); err != nil {
			logger.Warn("shutdownchain: walc.Close", "err", err)
		}
	}
	if s.WALDB != nil {
		if err := s.WALDB.Close(); err != nil {
			logger.Warn("shutdownchain: walDB.Close", "err", err)
		}
	}
	if s.CleanTables != nil {
		s.CleanTables()
	}
	if s.Pool != nil {
		s.Pool.Close()
	}
}
