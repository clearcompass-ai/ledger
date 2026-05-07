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
	"testing"
	"time"

	uptessera "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"

	"github.com/clearcompass-ai/attesta/core/smt"

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

// buildTesseraForTests fills tesseraSlots based on opts.UseRealTessera.
// This is the only function in the test suite that branches on the
// flag; every other caller reads from the returned slot map.
func buildTesseraForTests(
	t *testing.T,
	ctx context.Context,
	opts testLedgerOpts,
	logger *slog.Logger,
) *tesseraSlots {
	t.Helper()

	if !opts.UseRealTessera {
		stub := &stubMerkleAppender{mt: smt.NewStubMerkleTree()}
		return &tesseraSlots{
			admission:   stub,
			builder:     stub,
			inclusion:   stub,
			consistency: stub,
			closer:      func(_ context.Context) error { return nil },
		}
	}
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

	embedded, err := optessera.NewEmbeddedAppender(ctx, driver, optessera.AppenderOptions{
		Origin:             origin,
		CheckpointInterval: checkpointInterval,
		BatchSize:          batchSize,
		BatchMaxAge:        batchMaxAge,
		Signer:             signer,
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
	adapter := optessera.NewTesseraAdapter(embedded, tileReader, logger)

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
