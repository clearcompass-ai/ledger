// FILE PATH: tests/witnessed_harness_test.go
//
// Test harness that bundles a real tessera.EmbeddedAppender +
// real witness fixture + real witnessclient.HeadSync into a
// single value. Used by ad-hoc tests that build their own
// builder loop without going through startTestLedgerWithOpts —
// scale_test.go, soak_test.go, e2e_graceful_shutdown_test.go,
// e2e_shipper_redirect_test.go.
//
// PHYSICS, NOT MOCKS:
//
//   - Real Tessera EmbeddedAppender writes tile bytes to a
//     fresh t.TempDir() POSIX directory. The cosigned-checkpoint
//     file the BuilderLoop publishes after K-of-N collection
//     lands at <tempdir>/cosigned-checkpoint and remains
//     available for assertion at end-of-test.
//
//   - Real witnessFixture (httptest cosign servers backed by
//     SDK's NewWitnessHandler) processes every cosign POST.
//     The Ledger's HeadSync hits the fixture URLs over real
//     HTTP and persists signatures in the supplied TreeHeadStore.
//
// USAGE:
//
//	h := newWitnessedTestHarness(t, ctx, pool, logger)
//	bl := opbuilder.NewBuilderLoop(loopCfg, pool, tree, leafStore,
//	    nodeCache, reader, fetcher, schema, deltaBuffer, bufferStore,
//	    commitPub, h.Adapter, h.Cosigner, logger)
//	// ... drive the test, assert on h.CosignedCheckpointPath()
package tests

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	uptessera "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"

	"github.com/clearcompass-ai/attesta/crypto/cosign"

	opstore "github.com/clearcompass-ai/ledger/store"
	optessera "github.com/clearcompass-ai/ledger/tessera"
	"github.com/clearcompass-ai/ledger/witnessclient"
)

// witnessedTestHarness packages every piece an ad-hoc test
// needs to wire a production-shape BuilderLoop:
//
//   - Adapter        : *tessera.TesseraAdapter (MerkleAppender)
//   - Embedded       : *tessera.EmbeddedAppender (held for Close)
//   - Cosigner       : *witnessclient.HeadSync (WitnessCosigner)
//   - Fixture        : the underlying httptest witness fixture
//   - TileRoot       : the tempdir Tessera writes to
//
// CleanUp is registered with t.Cleanup; callers do not Close
// anything manually.
type witnessedTestHarness struct {
	Adapter   *optessera.TesseraAdapter
	Embedded  *optessera.EmbeddedAppender
	Cosigner  *witnessclient.HeadSync
	Fixture   *witnessFixture
	NetworkID cosign.NetworkID
	TileRoot  string
}

// CosignedCheckpointPath returns the absolute path the
// EmbeddedAppender writes the cosigned-checkpoint file to. After
// the BuilderLoop's first successful K-of-N collection, the file
// at this path contains a JSON-encoded types.CosignedTreeHead.
// Tests assert on the file's existence as the load-bearing
// proof that the entire pipeline (HTTP cosign → atomic commit →
// CDN write) succeeded end-to-end.
func (h *witnessedTestHarness) CosignedCheckpointPath() string {
	return filepath.Join(h.TileRoot, "cosigned-checkpoint")
}

// newWitnessedTestHarness builds the K=1 default harness. Use
// newWitnessedTestHarnessN for K>1.
func newWitnessedTestHarness(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	logger *slog.Logger,
) *witnessedTestHarness {
	return newWitnessedTestHarnessN(t, ctx, pool, logger, 1, 1)
}

// newWitnessedTestHarnessN builds an N-witness, K-quorum harness.
// witnessCount is the number of httptest cosign servers spawned;
// quorumK is the threshold the HeadSync collector enforces.
//
// The Tessera storage directory is t.TempDir() so every test
// gets a fresh tile tree. CheckpointInterval / BatchSize /
// BatchMaxAge are scaled down for fast tests (matches
// buildRealTesseraSlots defaults).
func newWitnessedTestHarnessN(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	logger *slog.Logger,
	witnessCount int,
	quorumK int,
) *witnessedTestHarness {
	t.Helper()

	netID := nonZeroTestNetworkID()
	tileRoot := t.TempDir()

	// Real Tessera embedded appender, mirroring production wiring.
	signer, _, err := optessera.GenerateEphemeralSigner("test-witnessed-harness")
	if err != nil {
		t.Fatalf("witnessed harness: GenerateEphemeralSigner: %v", err)
	}
	driver, err := posix.New(ctx, posix.Config{Path: tileRoot})
	if err != nil {
		t.Fatalf("witnessed harness: posix.New: %v", err)
	}
	_ = uptessera.Driver(driver)

	publicCheckpointPath := filepath.Join(tileRoot, "cosigned-checkpoint")
	// CTX LIFETIME: see tests/shutdownchain_test.go — Tessera's
	// background ctx is decoupled from the test ctx so embedded.Close
	// is the canonical termination, not ctx-cancel propagation.
	embedded, err := optessera.NewEmbeddedAppender(context.WithoutCancel(ctx), driver, optessera.AppenderOptions{
		Origin:               testLogDID,
		Signer:               signer,
		CheckpointInterval:   100 * time.Millisecond,
		BatchSize:            4,
		BatchMaxAge:          50 * time.Millisecond,
		PublicCheckpointPath: publicCheckpointPath,
	}, logger)
	if err != nil {
		t.Fatalf("witnessed harness: NewEmbeddedAppender: %v", err)
	}

	backend, err := optessera.NewPOSIXTileBackend(tileRoot)
	if err != nil {
		_ = embedded.Close(ctx)
		t.Fatalf("witnessed harness: NewPOSIXTileBackend: %v", err)
	}
	tileReader := optessera.NewTileReader(backend, 256)
	adapter := optessera.NewTesseraAdapter(ctx, embedded, tileReader, logger)

	// Real witness fixture — N httptest cosign servers.
	fixture := newWitnessFixture(t, netID, witnessCount)

	// Real cosign client — Ledger HeadSync against the fixture's
	// URLs. Persists head + sigs to the supplied TreeHeadStore.
	treeHeadStore := opstore.NewTreeHeadStore(pool)
	cosigner, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  fixture.URLs(),
		QuorumK:           quorumK,
		PerWitnessTimeout: 2 * time.Second,
		NetworkID:         netID,
	}, treeHeadStore, logger)
	if err != nil {
		_ = embedded.Close(ctx)
		t.Fatalf("witnessed harness: NewHeadSync: %v", err)
	}

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = embedded.Close(shutdownCtx)
	})

	return &witnessedTestHarness{
		Adapter:   adapter,
		Embedded:  embedded,
		Cosigner:  cosigner,
		Fixture:   fixture,
		NetworkID: netID,
		TileRoot:  tileRoot,
	}
}
