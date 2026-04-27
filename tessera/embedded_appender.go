/*
FILE PATH: tessera/embedded_appender.go

EmbeddedAppender — wraps the upstream Tessera library in-process,
replacing the HTTP-based *Client. Phase 1B's load-bearing change:
the operator no longer talks HTTP to a separate
tessera-personality binary; it imports
github.com/transparency-dev/tessera directly and holds an
*tessera.Appender + tessera.LogReader for the lifetime of the
process.

WHY EMBEDDED:

  - Eliminates the standalone tessera-personality binary
    (deleted in commit 7/7) and the network hop between operator
    and personality. One process, one cgroup, one set of
    failure modes.
  - Preserves the operator's existing MerkleAppender interface
    (AppendLeaf + Head). The builder loop and proof_adapter.go
    keep their existing API surface — only the construction site
    in cmd/operator/main.go changes.
  - Tessera's storage driver is the only thing that varies
    between deployments (POSIX for local dev, GCP for
    production). The operator passes a tessera.Driver into
    NewEmbeddedAppender; the wrapper itself is driver-agnostic.

CONTRACT:

  AppendLeaf(data []byte) (uint64, error)
    - Requires len(data) == 32 (SHA-256 entry identity per the
      v0.3.0-tessera SDK alignment). Hash-only tiles: Tessera
      sees only the 32-byte identity, never the full wire bytes.
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
      operator shutdown to avoid losing entries that were
      Add'd but not yet integrated.

INTEGRATION WITH proof_adapter.go:

  The existing TesseraAdapter wraps a *Client + *TileReader.
  After Phase 1B, cmd/operator/main.go constructs:

    backend, _   := NewPOSIXTileBackend(storageDir)
    tileReader   := NewTileReader(backend, cacheSize)
    embedded, _  := NewEmbeddedAppender(ctx, driver, opts)
    adapter      := NewEmbeddedTesseraAdapter(embedded, tileReader, logger)

  EmbeddedTesseraAdapter mirrors TesseraAdapter's surface
  (AppendLeaf, Head, RawInclusionProof, etc.) but holds an
  *EmbeddedAppender instead of a *Client.

DRIVER CHOICE (out of scope for THIS commit):

  This file does NOT instantiate the storage driver. The caller
  (cmd/operator/main.go in commit 5/7) builds either:
    - posix.New(ctx, posix.Config{Path: dir})  — local dev
    - gcp.New(ctx, gcp.Config{...})            — production
  and passes the resulting tessera.Driver to NewEmbeddedAppender.
*/
package tessera

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"

	uptessera "github.com/transparency-dev/tessera"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// AppenderOptions bundles the knobs cmd/operator/main.go threads
// into NewEmbeddedAppender. Holds tunables that the upstream
// AppendOptions builder pattern requires; isolated here so the
// cmd-side wiring stays small and the defaults are documented in
// one place.
type AppenderOptions struct {
	// Origin is the c2sp.org/tlog-tiles "origin" line written
	// to every checkpoint. SHOULD be a stable identifier for
	// this log (e.g., the operator's LogDID). Defaults to
	// "ortholog-local-dev" when empty — fine for tests, never
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
	// without one. cmd/operator/main.go loads this from a key
	// file in production or generates an ephemeral one for
	// local dev (with a logged warning).
	Signer note.Signer
}

// applyDefaults fills zero-valued fields with safe defaults so
// callers can pass a partial options struct. Returns the same
// pointer for chaining-style use.
func (o *AppenderOptions) applyDefaults() {
	if o.Origin == "" {
		o.Origin = "ortholog-local-dev"
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
// than panicking so cmd/operator/main.go's failed-construction
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
func (e *EmbeddedAppender) AppendLeaf(data []byte) (uint64, error) {
	if len(data) != 32 {
		return 0, fmt.Errorf("tessera/embedded: AppendLeaf requires exactly 32 bytes, got %d", len(data))
	}
	// Background context: the upstream future will resolve when
	// Tessera's batcher includes this entry in its next
	// integration cycle. Caller-supplied ctx would be safe to
	// thread here, but the operator's call site (builder/loop.go)
	// doesn't currently. Adding it later is a one-line change.
	idx, err := e.appender.Add(context.Background(), uptessera.NewEntry(data))()
	if err != nil {
		return 0, fmt.Errorf("tessera/embedded: Add: %w", err)
	}
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
// TileBackend that bridges to TileReader). Operator code should
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
// getSignerOrGenerate("ortholog-local-dev") helper, lifted here
// so the personality binary can be deleted without losing the
// dev-mode convenience.
func GenerateEphemeralSigner(name string) (note.Signer, string, error) {
	if name == "" {
		name = "ortholog-local-dev"
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
// itself is the operator's MerkleAppender interface (defined in
// builder/loop.go); we don't import it here to avoid an import
// cycle, but the duck-typed compatibility is the load-bearing
// guarantee.
//
// Concrete check: any method NewEmbeddedAppender must expose to
// be used in place of *Client wrapped by *TesseraAdapter is
// AppendLeaf([]byte) (uint64, error) and Head() (types.TreeHead, error).
// Both are implemented above with matching signatures.
var _ interface {
	AppendLeaf(data []byte) (uint64, error)
	Head() (types.TreeHead, error)
} = (*EmbeddedAppender)(nil)
