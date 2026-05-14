/*
FILE PATH: tessera/embedded_appender.go

EmbeddedAppender — wraps the upstream Tessera library in-process.
The ledger imports github.com/transparency-dev/tessera directly
and holds an *tessera.Appender + tessera.LogReader for the
lifetime of the process — no HTTP hop to a separate Tessera
personality binary.

WHY EMBEDDED:

  - One process, one cgroup, one set of failure modes (no network
    hop between ledger and a standalone Tessera personality).
  - Preserves the ledger's existing MerkleAppender interface
    (AppendLeaf + Head). The builder loop and proof_adapter.go
    keep their existing API surface — only the construction site
    in cmd/ledger/main.go changes.
  - Tessera's storage driver is the only thing that varies
    between deployments (POSIX for local dev, GCP for
    production). The ledger passes a tessera.Driver into
    NewEmbeddedAppender; the wrapper itself is driver-agnostic.

CONTRACT:

	AppendLeaf(data []byte) (uint64, error)
	  - Requires len(data) == 32 (SHA-256 entry identity).
	    Hash-only tiles: Tessera sees only the 32-byte identity,
	    never the full wire bytes.
	  - Blocks until Tessera's batching logic assigns a sequence
	    number and the IndexFuture resolves. Typical latency
	    depends on WithCheckpointInterval / WithBatching options
	    passed to upstream NewAppender at construction.

	Head() (types.TreeHead, error)
	  - Reads the latest signed checkpoint via LogReader and
	    parses it. Returns os.ErrNotExist (wrapped) before the
	    first checkpoint is published — the cmd-side wiring at
	    startup tolerates this and re-tries.

	Close(ctx context.Context) error
	  - Calls the shutdown function returned by upstream
	    NewAppender. Ensures any IndexFuture this appender has
	    handed out resolves before returning. MUST be called at
	    ledger shutdown to avoid losing entries that were
	    Add'd but not yet integrated.

INTEGRATION WITH proof_adapter.go:

	cmd/ledger/main.go constructs:

	  backend, _ := NewPOSIXTileBackend(storageDir)
	  tileReader := NewTileReader(backend, cacheSize)
	  embedded, _ := NewEmbeddedAppender(ctx, driver, opts)
	  adapter := NewEmbeddedTesseraAdapter(embedded, tileReader, logger)

	EmbeddedTesseraAdapter mirrors TesseraAdapter's surface
	(AppendLeaf, Head, RawInclusionProof, etc.) but holds an
	*EmbeddedAppender instead of a *Client.

DRIVER CHOICE (out of scope for THIS commit):

	This file does NOT instantiate the storage driver. The caller
	(cmd/ledger/main.go in commit 5/7) builds either:
	  - posix.New(ctx, posix.Config{Path: dir})  — local dev
	  - gcp.New(ctx, gcp.Config{...})            — production
	and passes the resulting tessera.Driver to NewEmbeddedAppender.
*/
package tessera

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"

	"golang.org/x/mod/sumdb/note"

	uptessera "github.com/transparency-dev/tessera"

	"github.com/clearcompass-ai/attesta/types"
)

// AppenderOptions bundles the knobs cmd/ledger/main.go threads
// into NewEmbeddedAppender. Holds tunables that the upstream
// AppendOptions builder pattern requires; isolated here so the
// cmd-side wiring stays small and the defaults are documented in
// one place.
type AppenderOptions struct {
	// Origin is the c2sp.org/tlog-tiles "origin" line written
	// to every checkpoint. SHOULD be a stable identifier for
	// this log (e.g., the ledger's LogDID). Defaults to
	// "attesta-local-dev" when empty — fine for tests, never
	// for production.
	Origin string

	// CheckpointInterval is how often Tessera publishes a new
	// checkpoint. Shorter = lower commit-to-publish latency for
	// witnesses; longer = fewer signature operations. Defaults
	// to 1 second.
	CheckpointInterval time.Duration

	// BatchSize / BatchMaxAge tune the integration batcher. A
	// new batch flushes when either threshold is hit. Defaults:
	// 256 entries, 1 second.
	BatchSize   int
	BatchMaxAge time.Duration

	// Signer is the Ed25519 note.Signer that signs checkpoints.
	// REQUIRED — Tessera refuses to construct an Appender
	// without one. cmd/ledger/main.go loads this from a key
	// file in production or generates an ephemeral one for
	// local dev (with a logged warning).
	Signer note.Signer

	// Antispam is the upstream Tessera Antispam (dedup) adapter.
	// nil = no dedup (every Add allocates a fresh seq, even for
	// duplicates). Production ledgers MUST wire one — without
	// it, integrity.Reasserter on boot would re-Add inflight
	// entries and get NEW seqs instead of the original ones,
	// polluting the log. See README.md "Antispam" for the
	// upstream library's design.
	Antispam uptessera.Antispam

	// AntispamInMemEntries sizes the in-memory dedup cache that
	// fronts the persistent antispam adapter. The recommended
	// floor is the persistent layer's PushbackThreshold × number
	// of admission front-ends. Defaults to
	// uptessera.DefaultAntispamInMemorySize when zero.
	AntispamInMemEntries uint

	// PublicCheckpointPath is the absolute filesystem path the
	// builder loop publishes the K-of-N CosignedTreeHead to after
	// every commit cycle that successfully collects quorum. The
	// CDN serves THIS file as the network's authoritative tree
	// state — auditors fetch it to verify the head is finalized
	// (i.e., a quorum of witnesses signed the same RootHash at
	// this TreeSize). Distinct from upstream Tessera's auto-
	// published `checkpoint` file (which carries only the origin
	// signature and reflects only Tessera's internal integration
	// state).
	//
	// Empty = no public publication; PublishCosignedCheckpoint is
	// a no-op. Acceptable for tests and dev runs; production wiring
	// MUST set a non-empty path.
	PublicCheckpointPath string

	// DrainBudget is how long Close waits AFTER the upstream
	// shutdown function returns AND our internal bg-ctx has been
	// cancelled, before declaring the appender drained.
	//
	// WHY THIS EXISTS
	//
	// Upstream tessera.NewAppender (tessera@v1.0.2/append_lifecycle.go:
	// 278-282) spawns three background goroutines (Follower.Follow,
	// followerStats, integrationStats.updateStats) using bare `go`,
	// with no sync.WaitGroup and no completion signal. The returned
	// shutdown function only drains in-flight Add futures — it does
	// NOT join the background goroutines. After ctx.Cancel they
	// exit asynchronously and silently.
	//
	// Without an upstream Wait function the caller has no way to
	// observe completion. The drain budget is the observational
	// quiesce: we cancel our internal bg-ctx (which upstream's
	// goroutines watch), then sleep up to DrainBudget so the
	// goroutines have a chance to exit before the test's tile-root
	// directory vanishes or the process exits.
	//
	// When upstream gains a Wait(ctx) function — see the PR sketch
	// in tier-1 of the structural fix plan — replace the sleep
	// with an explicit join.
	//
	// Default: 200ms. Tuned to cover the 95th-pct goroutine exit
	// latency observed in single-test reproductions (publish-
	// Checkpoint follower polls at 100ms cadence; one full poll
	// plus margin). Set higher for production shutdown chains
	// that can afford to wait, or zero to disable the drain entirely
	// (the upstream-leak symptoms then surface unfiltered — useful
	// for diagnosing whether a downstream issue is masked).
	DrainBudget time.Duration
}

// DefaultDrainBudget is the post-Close grace window for upstream
// Tessera goroutines to observe ctx cancellation and exit. Tuned
// to cover one full publishCheckpoint poll cycle (100ms) plus
// margin; see AppenderOptions.DrainBudget docstring for rationale.
const DefaultDrainBudget = 200 * time.Millisecond

// applyDefaults fills zero-valued fields with safe defaults so
// callers can pass a partial options struct. Returns the same
// pointer for chaining-style use.
func (o *AppenderOptions) applyDefaults() {
	if o.Origin == "" {
		o.Origin = "attesta-local-dev"
	}
	if o.CheckpointInterval == 0 {
		o.CheckpointInterval = 1 * time.Second
	}
	if o.BatchSize == 0 {
		o.BatchSize = 256
	}
	if o.BatchMaxAge == 0 {
		o.BatchMaxAge = 1 * time.Second
	}
	// DrainBudget=0 is INTENTIONALLY supported (disables drain).
	// Only fill the default when the field is its zero value AND
	// the caller hasn't explicitly opted out via a sentinel — but
	// time.Duration has no negative sentinel, so we accept the
	// trade-off: a caller wanting "no drain" sets DrainBudget=-1
	// (we treat any non-positive value as "skip the sleep").
	if o.DrainBudget == 0 {
		o.DrainBudget = DefaultDrainBudget
	}
}

// EmbeddedAppender wraps upstream tessera primitives in a
// process-local appender + reader. Goroutine-safe — both
// upstream Appender.Add and LogReader methods are.
//
// Lifecycle: construct once at boot, Close once at shutdown.
//
// # BACKGROUND-GOROUTINE LIFECYCLE
//
// The wrapper owns a private context (bgCtx) derived from the
// caller's parentCtx at construction. We pass bgCtx — NOT
// parentCtx — to uptessera.NewAppender, so the three background
// goroutines upstream spawns (Follower.Follow, followerStats,
// integrationStats.updateStats) watch OUR ctx, not the caller's.
//
// On Close we (1) call upstream shutdown to drain Add futures,
// then (2) cancel bgCtx ourselves — deterministically, regardless
// of when the caller cancels parentCtx — then (3) wait up to
// DrainBudget for the upstream goroutines to observe ctx.Done
// and exit. This decouples lifecycle ordering from the caller's
// ctx discipline and silences the post-cleanup file-not-found
// flood that occurs when t.TempDir runs before the goroutines
// notice ctx.Cancel.
//
// goroutineBaseline captures runtime.NumGoroutine() immediately
// before uptessera.NewAppender. After the drain budget we
// re-sample and log the delta as a leak diagnostic. The metric
// is coarse (counts ALL goroutines, not just Tessera's), but a
// persistent non-zero delta across shutdown is the operational
// signal that upstream's background tasks aren't draining.
type EmbeddedAppender struct {
	// upstream resources from tessera.NewAppender — held to
	// drive Add and Head, and to call shutdown at Close.
	appender *uptessera.Appender
	reader   uptessera.LogReader
	shutdown func(ctx context.Context) error

	// bgCancel cancels the private context passed to upstream's
	// NewAppender. Fired in Close after upstream shutdown returns.
	bgCancel context.CancelFunc

	// bgDoneCh is closed when Close has elapsed its drain budget
	// (or the caller's ctx fired, whichever came first). Tests
	// gate t.TempDir-style cleanup on <-Done() so the on-disk
	// state dir survives until upstream goroutines have had a
	// chance to exit.
	bgDoneCh chan struct{}

	// drainBudget is the post-bgCancel grace window. Copied from
	// AppenderOptions.DrainBudget at construction. Non-positive
	// values disable the wait entirely (Close cancels bgCtx and
	// returns immediately).
	drainBudget time.Duration

	// goroutineBaseline is runtime.NumGoroutine() captured BEFORE
	// upstream NewAppender ran. Close compares against the count
	// after drain to flag persistent upstream leaks.
	goroutineBaseline int

	// publicCheckpointPath is the absolute path
	// PublishCosignedCheckpoint writes the JSON-serialised
	// CosignedTreeHead to. Empty = no-op.
	publicCheckpointPath string

	logger *slog.Logger

	closeOnce sync.Once
	closeErr  error
}

// NewEmbeddedAppender constructs an in-process Tessera appender
// over the supplied storage driver. The caller is responsible
// for the driver's lifecycle (POSIX driver has none; GCP driver
// requires explicit cleanup at process shutdown).
//
// REQUIRES opts.Signer to be non-nil. Returns an error rather
// than panicking so cmd/ledger/main.go's failed-construction
// path stays log-and-exit-1 instead of panic-trace.
func NewEmbeddedAppender(
	ctx context.Context,
	driver uptessera.Driver,
	opts AppenderOptions,
	logger *slog.Logger,
) (*EmbeddedAppender, error) {
	if driver == nil {
		return nil, fmt.Errorf("tessera/embedded: driver required")
	}
	if opts.Signer == nil {
		return nil, fmt.Errorf("tessera/embedded: opts.Signer required (use GenerateEphemeralSigner for tests)")
	}
	if logger == nil {
		logger = slog.Default()
	}
	opts.applyDefaults()

	appendOpts := uptessera.NewAppendOptions().
		WithCheckpointSigner(opts.Signer).
		WithCheckpointInterval(opts.CheckpointInterval).
		WithBatching(uint(opts.BatchSize), opts.BatchMaxAge)
	if opts.Antispam != nil {
		inMem := opts.AntispamInMemEntries
		if inMem == 0 {
			inMem = uptessera.DefaultAntispamInMemorySize
		}
		appendOpts = appendOpts.WithAntispam(inMem, opts.Antispam)
	}

	// Derive a private context for upstream's background goroutines.
	// They watch bgCtx instead of the caller's ctx, so Close can
	// signal them deterministically without depending on the caller's
	// cancel ordering. See type EmbeddedAppender docstring for the
	// full lifecycle invariant.
	bgCtx, bgCancel := context.WithCancel(ctx)

	// Sample goroutine count BEFORE upstream NewAppender so the
	// post-Close delta reflects only upstream's contribution to
	// extant goroutines. Approximate — other code in the process
	// can spawn goroutines too — but a persistent non-zero delta
	// across shutdown is the operational leak signal we want.
	goroutineBaseline := runtime.NumGoroutine()

	appender, shutdown, reader, err := uptessera.NewAppender(bgCtx, driver, appendOpts)
	if err != nil {
		bgCancel() // release the derived ctx on construction failure
		return nil, fmt.Errorf("tessera/embedded: NewAppender: %w", err)
	}

	logger.Info("tessera embedded appender ready",
		"origin", opts.Origin,
		"checkpoint_interval", opts.CheckpointInterval,
		"batch_size", opts.BatchSize,
		"batch_max_age", opts.BatchMaxAge,
		"signer", opts.Signer.Name(),
		"drain_budget", opts.DrainBudget,
	)

	ea := &EmbeddedAppender{
		appender:             appender,
		reader:               reader,
		shutdown:             shutdown,
		bgCancel:             bgCancel,
		bgDoneCh:             make(chan struct{}),
		drainBudget:          opts.DrainBudget,
		goroutineBaseline:    goroutineBaseline,
		publicCheckpointPath: opts.PublicCheckpointPath,
		logger:               logger,
	}
	debugTraceAppenderConstructed(logger)
	return ea, nil
}

// AppendLeaf submits a 32-byte entry-identity hash to Tessera and
// blocks until the IndexFuture resolves with the assigned
// sequence number.
//
// STRICT: data MUST be exactly 32 bytes. Anything else is a
// programming error in the caller (the builder's Step 6 always
// passes envelope.EntryIdentity output, which is [32]byte).
//
// Returns the assigned sequence number on success. Errors
// surface verbatim from upstream Tessera.
//
// L4 — caller-supplied ctx threads through to Tessera's Add()
// so a sequencer drain that hits SIGTERM mid-batch cancels the
// in-flight integration future cleanly.
func (e *EmbeddedAppender) AppendLeaf(ctx context.Context, data []byte) (uint64, error) {
	if len(data) != 32 {
		return 0, fmt.Errorf("tessera/embedded: AppendLeaf requires exactly 32 bytes, got %d", len(data))
	}
	// D2 — span. NoOp tracer makes this nearly free; OTLP
	// captures the integration-future wait.
	ctx, span := otel.Tracer("github.com/clearcompass-ai/ledger/tessera").Start(ctx, "tessera.AppendLeaf")
	defer span.End()
	t0 := time.Now() // D3
	idx, err := e.appender.Add(ctx, uptessera.NewEntry(data))()
	if err != nil {
		debugTraceAddFailure(e.logger, data, err)
		span.RecordError(err)
		return 0, fmt.Errorf("tessera/embedded: Add: %w", err)
	}
	recordAppendDuration(ctx, time.Since(t0))
	return idx.Index, nil
}

// Head reads the latest checkpoint and returns the parsed
// TreeHead. Returns os.ErrNotExist (wrapped) before any
// integration cycle has published a checkpoint.
func (e *EmbeddedAppender) Head() (types.TreeHead, error) {
	body, err := e.reader.ReadCheckpoint(context.Background())
	if err != nil {
		// Surface os.ErrNotExist for the first-boot "no
		// checkpoint yet" case so callers can distinguish it
		// from a real read error.
		if errors.Is(err, os.ErrNotExist) {
			return types.TreeHead{}, fmt.Errorf("tessera/embedded: no checkpoint yet: %w", err)
		}
		return types.TreeHead{}, fmt.Errorf("tessera/embedded: read checkpoint: %w", err)
	}
	return parseSignedNoteCheckpoint(body)
}

// Reader exposes the upstream LogReader so cmd-side wiring can
// pass it to other subsystems (e.g., a future LogReader-backed
// TileBackend that bridges to TileReader). Ledger code should
// prefer the high-level methods (AppendLeaf, Head) over reaching
// into the LogReader directly.
func (e *EmbeddedAppender) Reader() uptessera.LogReader {
	return e.reader
}

// PublishCosignedCheckpoint writes the K-of-N CosignedTreeHead to
// the configured public-checkpoint path. The write is atomic
// (write-tmp + rename) so auditors hitting the CDN never observe
// a partial file. Idempotent under retry: republishing a head at
// the same TreeSize replaces the file in place.
//
// Strict STH Finality: the builder loop calls this AFTER its
// atomic Postgres commit AND AFTER witness quorum is collected.
// The path it writes is the network's authoritative tree state —
// distinct from upstream Tessera's `checkpoint` file (origin-sig
// only).
//
// Empty publicCheckpointPath is a graceful no-op (returns nil) so
// dev / test runs without a public path still build cleanly.
// TreeSize == 0 returns an explicit error rather than writing an
// empty checkpoint (production code should never call with a
// zero-size head; defensive).
//
// ctx is honoured for cancellation between the write and rename
// only by best-effort: filesystem syscalls are not ctx-cancellable
// on POSIX. A SIGTERM mid-write may leave the temp file behind;
// reboot startup or a periodic janitor can clean stale `.cosigned-tmp-*`
// entries.
func (e *EmbeddedAppender) PublishCosignedCheckpoint(
	ctx context.Context, head types.CosignedTreeHead,
) error {
	if e.publicCheckpointPath == "" {
		return nil
	}
	if head.TreeSize == 0 {
		return fmt.Errorf("tessera/embedded: refusing to publish cosigned checkpoint with TreeSize=0")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(head)
	if err != nil {
		return fmt.Errorf("tessera/embedded: marshal cosigned head: %w", err)
	}
	if err := atomicWriteFile(e.publicCheckpointPath, body); err != nil {
		return fmt.Errorf("tessera/embedded: write cosigned checkpoint %s: %w",
			e.publicCheckpointPath, err)
	}
	return nil
}

// atomicWriteFile writes data to path via a temp file + rename in
// the same directory. Rename is atomic on POSIX so readers either
// see the old contents or the new contents, never a partial write.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".cosigned-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// Close runs the upstream shutdown function, then cancels the
// private bg-ctx and waits up to DrainBudget for upstream's
// background goroutines (Follower.Follow, followerStats,
// integrationStats.updateStats) to observe ctx.Done and exit.
//
// LIFECYCLE — three steps, in order:
//
//  1. shutdown(ctx) — upstream's drain function. Resolves any
//     in-flight IndexFutures so no Add caller is stranded.
//
//  2. bgCancel() — signals our private context. Upstream's
//     background goroutines watch this ctx (set at construction
//     time, not the caller's ctx). They exit asynchronously.
//
//  3. Wait drainBudget OR ctx.Done — observational quiesce. We
//     can't TRUE-join the upstream goroutines because the upstream
//     NewAppender API doesn't return a WaitGroup or completion
//     channel (see tessera@v1.0.2/append_lifecycle.go:278-282 —
//     bare `go` with no sync primitive). When upstream adds a
//     Wait function, replace this select with an explicit join.
//
// After step 3 we sample runtime.NumGoroutine() and log+metric the
// delta against the construction-time baseline. Persistent non-
// zero values indicate upstream goroutines that didn't drain
// within budget — page the operator, push for the upstream PR.
//
// Caller MUST hold the on-disk tile-root + antispam directories
// stable until <-Done() fires; otherwise upstream goroutines
// racing the close may hit "no such file" errors during their
// own exit-path writes. Tests use tesseraTempDir() to gate
// t.TempDir cleanup on Done; production holds directories for
// the process lifetime so the race doesn't manifest.
//
// Safe to call multiple times; the lifecycle runs exactly once.
func (e *EmbeddedAppender) Close(ctx context.Context) error {
	debugTraceClose(e.logger)
	e.closeOnce.Do(func() {
		// Step 1 — drain in-flight Adds per upstream contract.
		if e.shutdown != nil {
			e.closeErr = e.shutdown(ctx)
		}

		// Step 2 — cancel our private bg-ctx. Upstream's three
		// background goroutines (which were given bgCtx, not
		// the caller's ctx) observe this and begin their exit.
		if e.bgCancel != nil {
			e.bgCancel()
		}

		// Step 3 — wait up to drainBudget for goroutines to exit,
		// OR honor the caller's deadline (whichever comes first).
		// drainBudget<=0 skips the wait entirely (advanced opt-out).
		if e.drainBudget > 0 {
			select {
			case <-time.After(e.drainBudget):
				// Budget elapsed. Goroutines MAY still be running;
				// the leak check below quantifies it.
			case <-ctx.Done():
				// Caller's shutdown deadline fired before drain
				// completed. Honor it.
			}
		}

		// Leak diagnostic — coarse but actionable. Persistent
		// non-zero delta across shutdown is the operator-visible
		// signal that upstream goroutines aren't draining within
		// budget. Wire to OTel via recordCloseDrainResidual.
		residual := runtime.NumGoroutine() - e.goroutineBaseline
		if residual > 0 {
			e.logger.Warn("tessera embedded: goroutines did not drain to baseline within budget",
				"drain_budget", e.drainBudget,
				"goroutine_baseline", e.goroutineBaseline,
				"goroutine_current", e.goroutineBaseline+residual,
				"residual_count", residual,
				"hint", "upstream tessera.NewAppender spawns Follower/followerStats/updateStats with no WaitGroup; non-zero residual under drain budget means these are still running")
		}
		recordCloseDrainResidual(ctx, residual)

		close(e.bgDoneCh)
	})
	return e.closeErr
}

// Done returns a channel closed AFTER Close has completed its
// drain budget (or the caller's ctx fired). Tests gate t.TempDir
// cleanup on this so the on-disk state dir survives until
// upstream goroutines have had a chance to exit.
//
// nil if Close has never been called; safe to range/select on
// a non-nil value any number of times (channel close is
// permanent + concurrent-safe).
func (e *EmbeddedAppender) Done() <-chan struct{} {
	return e.bgDoneCh
}

// GenerateEphemeralSigner returns a freshly-generated Ed25519
// note.Signer suitable for tests and local dev. NEVER use this
// in production — the resulting public key is logged once and
// then lost.
//
// Mirrors tessera-personality/main.go's
// getSignerOrGenerate("attesta-local-dev") helper, lifted here
// so the personality binary can be deleted without losing the
// dev-mode convenience.
func GenerateEphemeralSigner(name string) (note.Signer, string, error) {
	if name == "" {
		name = "attesta-local-dev"
	}
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		return nil, "", fmt.Errorf("tessera/embedded: GenerateKey: %w", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, "", fmt.Errorf("tessera/embedded: NewSigner: %w", err)
	}
	return signer, vkey, nil
}

// Compile-time pin: *EmbeddedAppender satisfies the same shape
// as *Client did on the AppendLeaf+Head surface. The shape
// itself is the ledger's MerkleAppender interface (defined in
// builder/loop.go); we don't import it here to avoid an import
// cycle, but the duck-typed compatibility is the load-bearing
// guarantee.
//
// Concrete check: any method NewEmbeddedAppender must expose to
// be used in place of *Client wrapped by *TesseraAdapter is
// AppendLeaf([]byte) (uint64, error) and Head() (types.TreeHead, error).
// Both are implemented above with matching signatures.
var _ AppenderBackend = (*EmbeddedAppender)(nil)

// ─────────────────────────────────────────────────────────────────
// ReadOnlyAppender — read-only AppenderBackend for cmd/ledger-reader
// ─────────────────────────────────────────────────────────────────

// ErrReadOnly is returned by ReadOnlyAppender.AppendLeaf. The
// read-only ledger never appends; if any code path reaches
// AppendLeaf, that's a programming error and surfaces as a
// loud rejection rather than silently dropping the entry.
var ErrReadOnly = errors.New("tessera: read-only appender — writes not permitted")

// ReadOnlyAppender satisfies AppenderBackend by reading the
// checkpoint from a POSIX directory shared with the writer
// ledger. Used by cmd/ledger-reader so the reader process
// can serve TreeHead and proof requests against the same
// storage the writer holds open via tessera.NewAppender.
//
// Lifecycle: trivial. No upstream Tessera primitives held —
// just a POSIXTileBackend for filesystem reads.
type ReadOnlyAppender struct {
	backend *POSIXTileBackend
}

// NewReadOnlyAppender constructs a read-only appender over the
// supplied POSIX tile backend. The backend's rootDir must point
// at the same directory the writer ledger's embedded Tessera
// is configured for (k8s shared volume, same host, etc.).
func NewReadOnlyAppender(backend *POSIXTileBackend) *ReadOnlyAppender {
	return &ReadOnlyAppender{backend: backend}
}

// AppendLeaf always returns ErrReadOnly. The reader never writes.
func (r *ReadOnlyAppender) AppendLeaf(_ context.Context, _ []byte) (uint64, error) {
	return 0, ErrReadOnly
}

// PublishCosignedCheckpoint always returns ErrReadOnly. The
// read-only ledger never authors checkpoints; only the writer
// ledger's builder loop runs through the
// admit→cosign→commit→publish pipeline.
func (r *ReadOnlyAppender) PublishCosignedCheckpoint(_ context.Context, _ types.CosignedTreeHead) error {
	return ErrReadOnly
}

// Head reads <rootDir>/checkpoint and parses it. Returns the
// same os.ErrNotExist-wrapped error as EmbeddedAppender.Head
// before any checkpoint is published.
func (r *ReadOnlyAppender) Head() (types.TreeHead, error) {
	body, err := r.backend.ReadCheckpoint(context.Background())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return types.TreeHead{}, fmt.Errorf("tessera/readonly: no checkpoint yet: %w", err)
		}
		return types.TreeHead{}, fmt.Errorf("tessera/readonly: read checkpoint: %w", err)
	}
	return parseSignedNoteCheckpoint(body)
}

// Compile-time pin.
var _ AppenderBackend = (*ReadOnlyAppender)(nil)

// ─────────────────────────────────────────────────────────────────
// Signed-note checkpoint parser (shared by EmbeddedAppender and
// ReadOnlyAppender)
// ─────────────────────────────────────────────────────────────────

// parseSignedNoteCheckpoint parses a c2sp.org/tlog-tiles
// checkpoint produced by upstream Tessera. The format is:
//
//	line 0: origin string (e.g., the ledger's LogDID)
//	line 1: tree size as decimal
//	line 2: base64-encoded root hash (32 bytes decoded)
//	line 3: empty (separator before signature block)
//	line 4+: "— <signer> <base64 sig>" (Ed25519 signatures —
//	         tlog-tiles ecosystem consumers verify these; the
//	         ledger does not)
//
// Both EmbeddedAppender.Head and ReadOnlyAppender.Head call this.
// cmd/rebuild-projection also calls it (via the exported alias
// ParseCheckpoint) to recover the tree size before walking tiles.
func parseSignedNoteCheckpoint(data []byte) (types.TreeHead, error) {
	text := string(data)
	lines := strings.Split(text, "\n")

	if len(lines) < 3 {
		return types.TreeHead{}, fmt.Errorf(
			"tessera/embedded: checkpoint has %d lines, need at least 3 (origin, size, hash)", len(lines))
	}

	origin := strings.TrimSpace(lines[0])
	if origin == "" {
		return types.TreeHead{}, fmt.Errorf("tessera/embedded: checkpoint line 0 (origin) is empty")
	}

	treeSizeStr := strings.TrimSpace(lines[1])
	treeSize, err := strconv.ParseUint(treeSizeStr, 10, 64)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf(
			"tessera/embedded: checkpoint line 1 (tree_size) not a valid uint64: %q: %w", treeSizeStr, err)
	}

	rootHashB64 := strings.TrimSpace(lines[2])
	rootBytes, err := base64.StdEncoding.DecodeString(rootHashB64)
	if err != nil {
		// Fallback: try raw standard (no padding).
		rootBytes, err = base64.RawStdEncoding.DecodeString(rootHashB64)
		if err != nil {
			return types.TreeHead{}, fmt.Errorf(
				"tessera/embedded: checkpoint line 2 (root_hash) not valid base64: %q: %w", rootHashB64, err)
		}
	}
	if len(rootBytes) != 32 {
		return types.TreeHead{}, fmt.Errorf(
			"tessera/embedded: checkpoint root hash is %d bytes, expected 32", len(rootBytes))
	}

	var head types.TreeHead
	head.TreeSize = treeSize
	copy(head.RootHash[:], rootBytes)
	return head, nil
}

// ParseCheckpoint is the exported wrapper around the c2sp.org/tlog-tiles
// signed-note checkpoint parser. cmd/rebuild-projection uses it to
// recover the tree size from a tile-store-backed `checkpoint` file
// without needing to wire up the full Tessera reader machinery.
func ParseCheckpoint(data []byte) (types.TreeHead, error) {
	return parseSignedNoteCheckpoint(data)
}
