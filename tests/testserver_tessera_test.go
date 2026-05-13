/*
FILE PATH:

	tests/testserver_tessera_test.go

DESCRIPTION:

	Real-Tessera-vs-stub branch helpers for the integration-test
	harness. Split out of testserver_setup_test.go to keep both
	files under the per-file LoC ceiling.

KEY ARCHITECTURAL DECISIONS:
  - tesseraSlots is the single struct every caller-facing
    production role (admission TesseraAppender, builder
    MerkleAppender, InclusionProver, ConsistencyProver) reads
    from. There is exactly one switch (opts.UseRealTessera) and
    exactly one filling for every slot.
  - The real path mirrors cmd/ledger/main.go's six-line wiring
    (GenerateEphemeralSigner → posix.New → NewEmbeddedAppender →
    NewPOSIXTileBackend → NewTileReader → NewTesseraAdapter)
    exactly, so a production-side bug in any of those calls is
    visible to the integration test on the next run.
  - Cleanup-aware. The returned closer drains background
    batchers + the checkpoint signer goroutine. Stub path
    returns a no-op closer for uniform calling code.

KEY DEPENDENCIES:
  - github.com/transparency-dev/tessera/storage/posix: POSIX
    driver. Lifecycle is the EmbeddedAppender's; nothing extra
    to close on the driver.
  - github.com/clearcompass-ai/ledger/tessera: every wrapper
    type the production main.go uses.
*/
package tests

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	uptessera "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	tposixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"

	"github.com/clearcompass-ai/ledger/api"
	opbuilder "github.com/clearcompass-ai/ledger/builder"
	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) tesseraSlots — bundle of the four production roles
// -------------------------------------------------------------------------------------------------

// tesseraSlots is the result of buildTesseraForTests. The caller
// wires each slot into the corresponding production dependency
// struct in startTestLedgerWithOpts.
type tesseraSlots struct {
	admission   api.TesseraAppender
	builder     opbuilder.MerkleAppender
	inclusion   api.InclusionProver
	consistency api.ConsistencyProver

	// Real-only handles. nil under stub path; populated when
	// opts.UseRealTessera is true.
	embedded   *optessera.EmbeddedAppender
	tileReader *optessera.TileReader
	tileRoot   string

	// closer drains the embedded Tessera's pending integrations
	// and shuts the checkpoint signer goroutine. Stub path
	// returns a no-op closer for uniform calling code.
	closer func(ctx context.Context) error
}

// -------------------------------------------------------------------------------------------------
// 2) buildTesseraForTests — the single decision point
// -------------------------------------------------------------------------------------------------

// buildTesseraForTests fills tesseraSlots with a real
// tessera.EmbeddedAppender backed by t.TempDir(). The previous
// stub branch is gone; per architectural review tests must
// exercise the production-shape Tessera stack so the cosigned-
// checkpoint file write is part of every test's contract.
//
// The bool opts.UseRealTessera is retained for backward source
// compatibility with existing callers but is now ignored — every
// call returns the production-shape slots.
func buildTesseraForTests(
	t *testing.T,
	ctx context.Context,
	opts testLedgerOpts,
	logger *slog.Logger,
) *tesseraSlots {
	t.Helper()
	return buildRealTesseraSlots(t, ctx, opts, logger)
}

// buildRealTesseraSlots wires the production-shape Tessera stack.
// Mirrors cmd/ledger/main.go:904+ exactly:
//
//	signer → driver → embedded → backend → tileReader → adapter
//
// Any drift between this six-line sequence and production wiring
// instantly fails CI on the next scenarios run.
func buildRealTesseraSlots(
	t *testing.T,
	ctx context.Context,
	opts testLedgerOpts,
	logger *slog.Logger,
) *tesseraSlots {
	t.Helper()

	tileRoot := opts.TileRoot
	if tileRoot == "" {
		var err error
		tileRoot, err = os.MkdirTemp("", "test-real-tessera-")
		if err != nil {
			t.Fatalf("buildRealTesseraSlots: tmp dir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(tileRoot) })
	}

	origin := opts.Origin
	if origin == "" {
		origin = testLogDID
	}
	checkpointInterval := opts.CheckpointInterval
	if checkpointInterval == 0 {
		checkpointInterval = 500 * time.Millisecond
	}
	batchSize := opts.BatchSize
	if batchSize == 0 {
		batchSize = 4
	}
	batchMaxAge := opts.BatchMaxAge
	if batchMaxAge == 0 {
		batchMaxAge = 100 * time.Millisecond
	}

	signer, _, err := optessera.GenerateEphemeralSigner("test-" + origin)
	if err != nil {
		t.Fatalf("buildRealTesseraSlots: GenerateEphemeralSigner: %v", err)
	}
	driver, err := posix.New(ctx, posix.Config{Path: tileRoot})
	if err != nil {
		t.Fatalf("buildRealTesseraSlots: posix.New: %v", err)
	}
	_ = uptessera.Driver(driver) // compile-time conformance.

	// ANTISPAM (dedup) — load-bearing for the sequencer's drainOnce
	// race tolerance. Without it, drainOnce N+1 re-picks-up a hash
	// whose stage-1 worker from cycle N is still in flight; the
	// re-spawned worker's AppendLeaf gets a FRESH seq (Tessera with
	// nil antispam treats every Add as new), entry_index gets a
	// status=2 ghost row at the fresh seq, and the shipper's
	// hwmAdvancer contiguity invariant breaks at the first ghost.
	//
	// Reproducer: tessera/antispam_off_reproducer_test.go.
	// Production-shape harness: tests/witnessed_harness_test.go:141.
	antispamPath := filepath.Join(tileRoot, "antispam")
	antispam, asErr := tposixantispam.NewAntispam(ctx, antispamPath, tposixantispam.AntispamOpts{})
	if asErr != nil {
		t.Fatalf("buildRealTesseraSlots: tposixantispam.NewAntispam(%s): %v", antispamPath, asErr)
	}

	// CTX LIFETIME: Tessera's background tasks (integration loop,
	// follower-stats, updateStats) listen to THIS ctx for termination.
	// shutdownChain.Run (registered as a single t.Cleanup by the
	// caller) calls embedded.Close BEFORE cancelling ctx, so the
	// integration loop is still alive while Shutdown polls the
	// checkpoint. That ordering is what guarantees pending
	// IndexFutures resolve before ctx fires.
	//
	// DO NOT wrap this with context.WithoutCancel — that prevents
	// the goroutines from ever stopping (they don't observe Close;
	// Close only refuses new Adds and polls the checkpoint).
	embedded, err := optessera.NewEmbeddedAppender(ctx, driver, optessera.AppenderOptions{
		Origin:             origin,
		CheckpointInterval: checkpointInterval,
		BatchSize:          batchSize,
		BatchMaxAge:        batchMaxAge,
		Signer:             signer,
		Antispam:           antispam,
	}, logger)
	if err != nil {
		t.Fatalf("buildRealTesseraSlots: NewEmbeddedAppender: %v", err)
	}
	backend, err := optessera.NewPOSIXTileBackend(tileRoot)
	if err != nil {
		_ = embedded.Close(ctx)
		t.Fatalf("buildRealTesseraSlots: NewPOSIXTileBackend: %v", err)
	}
	tileReader := optessera.NewTileReader(backend, 256)
	adapter := optessera.NewTesseraAdapter(ctx, embedded, tileReader, logger)

	return &tesseraSlots{
		admission:   embedded,
		builder:     adapter,
		inclusion:   adapter,
		consistency: adapter,
		embedded:    embedded,
		tileReader:  tileReader,
		tileRoot:    tileRoot,
		closer:      embedded.Close,
	}
}
