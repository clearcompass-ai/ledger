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
	"errors"
	"fmt"
	"log/slog"
	"os"
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
}

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
}

// EmbeddedAppender wraps upstream tessera primitives in a
// process-local appender + reader. Goroutine-safe — both
// upstream Appender.Add and LogReader methods are.
//
// Lifecycle: construct once at boot, Close once at shutdown.
type EmbeddedAppender struct {
	// upstream resources from tessera.NewAppender — held to
	// drive Add and Head, and to call shutdown at Close.
	appender *uptessera.Appender
	reader   uptessera.LogReader
	shutdown func(ctx context.Context) error

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

	appender, shutdown, reader, err := uptessera.NewAppender(ctx, driver, appendOpts)
	if err != nil {
		return nil, fmt.Errorf("tessera/embedded: NewAppender: %w", err)
	}

	logger.Info("tessera embedded appender ready",
		"origin", opts.Origin,
		"checkpoint_interval", opts.CheckpointInterval,
		"batch_size", opts.BatchSize,
		"batch_max_age", opts.BatchMaxAge,
		"signer", opts.Signer.Name(),
	)

	return &EmbeddedAppender{
		appender: appender,
		reader:   reader,
		shutdown: shutdown,
		logger:   logger,
	}, nil
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

// Close runs the shutdown function returned by upstream
// NewAppender. Ensures any IndexFuture this appender has handed
// out resolves before Close returns. MUST be called at process
// shutdown — failing to call it risks losing entries that were
// Add'd but not yet integrated.
//
// Safe to call multiple times; the underlying shutdown runs
// exactly once.
func (e *EmbeddedAppender) Close(ctx context.Context) error {
	e.closeOnce.Do(func() {
		if e.shutdown == nil {
			return
		}
		e.closeErr = e.shutdown(ctx)
	})
	return e.closeErr
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
