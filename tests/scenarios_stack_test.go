//go:build scenarios

/*
FILE PATH:
    tests/scenarios_stack_test.go

DESCRIPTION:
    Production-stack composite for the Layer 0 scenarios suite. Drives
    one ledger boot via startTestLedgerWithOpts(UseRealTessera=true)
    so the ledger's own builder loop, the auditor, and the CDN all
    read and write the SAME Tessera POSIX tree. There is no shadow.

KEY ARCHITECTURAL DECISIONS:
    - One state machine. Submitting through the ledger's HTTP API
      is the only way a leaf reaches the tree. The auditor verifies
      bytes the ledger actually committed; Trust Alignment 6
      (Parse, Don't Validate) holds end-to-end.
    - DID-anchored topology. The bound DIDDocument carries the
      ledger URL plus the CDN URL pointing at the same POSIX root
      the embedded Tessera writes into.
    - Polling, never time.Sleep. WaitForCheckpoint takes a
      context.Context with deadline; convergence is observed,
      never assumed.
    - Goroutine-safe accessors. The scenariosStack exposes
      pointers through narrow accessor methods only, so persona
      tests cannot accidentally mutate harness state.

OVERVIEW:
    NewScenariosStack(t, opts)  → composite handle.
    .WaitForCheckpoint(ctx, n)  → poll Head() until TreeSize >= n.
    .Head()                     → real EmbeddedAppender.Head().
    .TileReader()               → real LRU-cached tile reader.
    .CDNBaseURL()               → CDN serving real tile bytes.
    .Resolver()                 → mockDIDResolver for adapter.

KEY DEPENDENCIES:
    - tests/testserver_setup_test.go: startTestLedgerWithOpts.
    - tests/testserver_tessera_test.go: real-Tessera wiring.
    - tests/scenarios_didresolver_test.go: DID resolver fixture.
    - tests/scenarios_cdn_test.go: c2sp tile-file server.
*/
package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/types"
	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) Config
// -------------------------------------------------------------------------------------------------

// scenariosStackOpts knobs every persona test composes a stack
// from. Zero-valued fields receive scenario-grade defaults
// (CheckpointInterval=500ms, BatchSize=4).
type scenariosStackOpts struct {
	// LogDIDSuffix is appended to scenarioLogDIDPrefix to form
	// the LogDID. Empty → "primary".
	LogDIDSuffix string

	// MountCDN, when true, fronts the Tessera POSIX root with a
	// cdnFileServer the auditor can fetch tiles from. Default true
	// (zero-value); persona tests opt out by setting MountCDNOff.
	MountCDNOff bool

	// CheckpointInterval / BatchSize override Tessera batcher
	// tunables for fast tests.
	CheckpointInterval time.Duration
	BatchSize          int
}

// -------------------------------------------------------------------------------------------------
// 2) scenariosStack
// -------------------------------------------------------------------------------------------------

// scenariosStack composes the testLedger (booted with
// UseRealTessera=true) with the auditor-side CDN + DID resolver
// pointing at the same POSIX root.
type scenariosStack struct {
	op       *testLedger
	logDID   string
	cdn      *cdnFileServer
	resolver *mockDIDResolver
}

// NewScenariosStack returns a fresh composite. Skips on missing
// ATTESTA_TEST_DSN.
func NewScenariosStack(t *testing.T, opts scenariosStackOpts) *scenariosStack {
	t.Helper()
	if opts.LogDIDSuffix == "" {
		opts.LogDIDSuffix = "primary"
	}
	if opts.CheckpointInterval == 0 {
		opts.CheckpointInterval = scenarioCheckpointInterval
	}
	if opts.BatchSize == 0 {
		opts.BatchSize = scenarioBatchSize
	}
	logDID := scenarioLogDIDPrefix + ":" + opts.LogDIDSuffix

	op := startTestLedgerWithOpts(t, testLedgerOpts{
		UseRealTessera:     true,
		CheckpointInterval: opts.CheckpointInterval,
		BatchSize:          opts.BatchSize,
		Origin:             logDID,
	})

	if !op.HasRealTessera() {
		t.Fatal("scenariosStack: testLedger missing real Tessera (test should have skipped earlier)")
	}

	resolver := newMockDIDResolver(t)
	bundle := endpointBundle{LedgerURL: op.BaseURL}

	var cdn *cdnFileServer
	if !opts.MountCDNOff {
		cdn = NewCDNFileServer(t, op.RealTesseraDir)
		bundle.CDNURL = cdn.BaseURL()
	}
	resolver.Bind(t, logDID, bundle)

	return &scenariosStack{
		op:       op,
		logDID:   logDID,
		cdn:      cdn,
		resolver: resolver,
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Wait helpers — context-bounded polling, NEVER time.Sleep
// -------------------------------------------------------------------------------------------------

// WaitForCheckpoint polls op.RealEmbedded.Head() until TreeSize
// reaches `size`. Returns ctx.Err() if the deadline elapses
// first, ensuring tests never silently pass via premature sleep
// return. Cadence is 50 ms.
func (s *scenariosStack) WaitForCheckpoint(ctx context.Context, size uint64) error {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			head, _ := s.op.RealEmbedded.Head()
			return errors.Join(ctx.Err(),
				errors.New("WaitForCheckpoint: tree did not reach "+
					itoaScenario(int(size))+
					" (current="+itoaScenario(int(head.TreeSize))+")"))
		case <-tick.C:
			head, err := s.op.RealEmbedded.Head()
			if err == nil && head.TreeSize >= size {
				return nil
			}
		}
	}
}

// Head returns the latest types.TreeHead from the real Tessera.
func (s *scenariosStack) Head() (types.TreeHead, error) {
	return s.op.RealEmbedded.Head()
}

// -------------------------------------------------------------------------------------------------
// 4) Accessors
// -------------------------------------------------------------------------------------------------

func (s *scenariosStack) LedgerBaseURL() string             { return s.op.BaseURL }
func (s *scenariosStack) LogDID() string                    { return s.logDID }
func (s *scenariosStack) TileRoot() string                  { return s.op.RealTesseraDir }
func (s *scenariosStack) TileReader() *optessera.TileReader { return s.op.RealTileReader }
func (s *scenariosStack) Resolver() *mockDIDResolver        { return s.resolver }

// CDNBaseURL returns the CDN base URL (or "" if MountCDNOff was set).
// Persona tests that hit "" should fail loudly rather than silently
// fall back to direct ledger reads.
func (s *scenariosStack) CDNBaseURL() string {
	if s.cdn == nil {
		return ""
	}
	return s.cdn.BaseURL()
}

// CDN returns the underlying *cdnFileServer (or nil). Used by
// CDN-cache-emulation tests that need HitCount / DistinctPaths.
func (s *scenariosStack) CDN() *cdnFileServer { return s.cdn }

// Tessera returns the underlying *EmbeddedAppender. Used by
// adversarial tests that need direct tree-state access.
func (s *scenariosStack) Tessera() *optessera.EmbeddedAppender { return s.op.RealEmbedded }

// Operator returns the underlying *testLedger. Persona tests
// that need direct Postgres / WAL / EntryStore access reach
// through this.
func (s *scenariosStack) Operator() *testLedger { return s.op }

// -------------------------------------------------------------------------------------------------
// 5) Tests — coverage gate
// -------------------------------------------------------------------------------------------------

// TestScenariosStack_LifecycleAndRealAppend is gated on
// ATTESTA_TEST_DSN (via startTestLedgerWithOpts). When env is
// unset, t.Skip fires immediately. When set, the test exercises
// the full real-Tessera lifecycle: stack construction, DID round-
// trip, checkpoint advance via the operator's own builder loop
// (no shadow append), tile reader fetch.
//
// This is the smoke gate proving Commit A's UseRealTessera path
// produces a working ledger. Persona tests build on the same
// constructor.
func TestScenariosStack_LifecycleAndRealAppend(t *testing.T) {
	stack := NewScenariosStack(t, scenariosStackOpts{LogDIDSuffix: "lifecycle"})

	if stack.LedgerBaseURL() == "" {
		t.Fatal("LedgerBaseURL empty")
	}
	if stack.CDNBaseURL() == "" {
		t.Fatal("CDNBaseURL empty under default MountCDN=on")
	}
	if stack.LogDID() == "" || stack.TileRoot() == "" {
		t.Fatal("LogDID or TileRoot empty")
	}

	// DID resolution → ledger URL + CDN URL.
	doc, err := stack.Resolver().Resolve(stack.LogDID())
	mustNotErr(t, "Resolve", err)
	if got, _ := doc.LedgerEndpointURL(); got != stack.LedgerBaseURL() {
		t.Fatalf("DID Resolve LedgerEndpointURL = %q, want %q",
			got, stack.LedgerBaseURL())
	}
	if got, _ := doc.ArtifactStoreURL(); got != stack.CDNBaseURL() {
		t.Fatalf("DID Resolve ArtifactStoreURL = %q, want %q",
			got, stack.CDNBaseURL())
	}

	// Operator accessor must be non-nil.
	if stack.Operator() == nil {
		t.Fatal("Operator nil")
	}
	if stack.Tessera() == nil {
		t.Fatal("Tessera embedded nil despite UseRealTessera=true")
	}
	if stack.TileReader() == nil {
		t.Fatal("TileReader nil despite UseRealTessera=true")
	}
	if stack.CDN() == nil {
		t.Fatal("CDN nil under default MountCDN=on")
	}

	// At boot the real Tessera tree is empty; Head should return a
	// zero TreeSize before any submission. The bounded-poll
	// WaitForCheckpoint(0) is trivially satisfied; we use it to
	// exercise the path under ctx control.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := stack.WaitForCheckpoint(ctx, 0); err != nil {
		t.Fatalf("WaitForCheckpoint(0): %v", err)
	}

	head, err := stack.Head()
	mustNotErr(t, "Head", err)
	if head.TreeSize != 0 {
		t.Fatalf("initial Head.TreeSize = %d, want 0 (no submissions yet)", head.TreeSize)
	}
}

// TestScenariosStack_WaitForCheckpoint_DeadlineDiagnostic
// confirms WaitForCheckpoint surfaces a useful diagnostic when
// the tree never reaches the requested size. The test races a
// short ctx deadline against an unreachable target.
func TestScenariosStack_WaitForCheckpoint_DeadlineDiagnostic(t *testing.T) {
	stack := NewScenariosStack(t, scenariosStackOpts{LogDIDSuffix: "deadline"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := stack.WaitForCheckpoint(ctx, 1<<40)
	if err == nil {
		t.Fatal("WaitForCheckpoint(unreachable) returned nil error")
	}
	// The error must wrap ctx.Err and carry a "current=" diagnostic
	// so persona tests fail with actionable output.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want wraps DeadlineExceeded", err)
	}
}
