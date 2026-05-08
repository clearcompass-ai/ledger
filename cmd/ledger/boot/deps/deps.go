// Package deps holds AppDeps — the single struct that carries every
// allocated I/O handle and wired component across the ledger binary's
// three lifecycle phases (alloc, wire, teardown).
//
// FILE PATH:
//
//	cmd/ledger/boot/deps/deps.go
//
// DESCRIPTION:
//
//	One struct to keep the binary's runtime state together, plus a
//	tiny closer-stack that records, in registration order, every
//	resource opened by alloc.Allocate. The boot phases hand the same
//	*AppDeps pointer to each other:
//
//	  ┌── alloc ──┐    ┌── wire ──┐    ┌── teardown ──┐
//	  │ open      │ →  │ compose  │ →  │ run + close  │
//	  │ resources │    │ goroutine│    │ in spec      │
//	  │           │    │ graph    │    │ order        │
//	  └───────────┘    └──────────┘    └──────────────┘
//	         ↓ on err walks                    ↑
//	         closeStack reverse                shutdownChain.Add
//	         (boot-failure unwind)             reads closeStack
//
//	The split eliminates the sync.OnceFunc double-wrapping pattern
//	main.go used to need: closure-defers were panic-safety against
//	the interleaved boot+wiring path. Here, alloc owns its own
//	failure unwind (UnwindReverse), and teardown owns the clean
//	shutdown — the two paths are isolated by phase, so no closer
//	ever needs to defend against being called from two places.
//
// KEY ARCHITECTURAL DECISIONS:
//
//   - One AppDeps. Not feature-decomposed substructs. The whole
//     ledger has roughly 25 I/O handles + wired components; a
//     single struct is auditable in one read. Per-feature substructs
//     would tangle dependencies without making any cleaner.
//
//   - Closers tracked separately. closeStack is a small []namedCloser
//     so teardown can transcribe it into the lifecycle.ShutdownChain
//     in registration order. Adding a closer is the *only* thing
//     alloc does that survives into teardown.
//
//   - Goroutine lifecycles via ctx, not Close. The builder loop,
//     sequencer, shipper, anchor publisher, gossip anti-entropy
//     scanner — all cancel cleanly when the parent ctx fires. They
//     do NOT have Close methods to register; teardown's job is to
//     cancel ctx, then close I/O after goroutines have observed
//     the cancellation. The closeStack is for I/O only.
//
//   - No locking on closeStack. Alloc is single-goroutine (sequential
//     resource opens). Once alloc returns, callers MUST NOT mutate
//     closeStack — wire and teardown only read it. That's enforced
//     by convention (the slice is not exposed; only AppendCloser
//     and TakeClosers are public).
//
//   - AppDeps is concrete, not an interface. Test-doubling is via
//     constructing an AppDeps with fakes in its handle fields,
//     which works because the type is concrete and field access
//     is package-public to the boot subpackages.
package deps

import (
	"context"
	"crypto/ecdsa"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"

	tposixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"

	"github.com/clearcompass-ai/attesta/crypto/cosign"

	"go.opentelemetry.io/otel/metric"

	"github.com/clearcompass-ai/ledger/anchor"
	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/api/middleware"
	"github.com/clearcompass-ai/ledger/builder"
	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/gossipnet"
	"github.com/clearcompass-ai/ledger/gossipstore"
	"github.com/clearcompass-ai/ledger/sequencer"
	"github.com/clearcompass-ai/ledger/shipper"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/tessera"
	"github.com/clearcompass-ai/ledger/wal"
)

// NamedCloser is one entry in the closeStack: a Close function plus
// the spec-order name + per-component timeout the lifecycle.
// ShutdownChain consumes when teardown registers it.
type NamedCloser struct {
	Name    string
	Timeout time.Duration
	Close   func(ctx context.Context) error
}

// AppDeps is the binary's runtime state. Every field is populated by
// alloc.Allocate (resource handles) or wire.Wire (composed
// components). teardown.Register reads from it; main reads from it
// to access the running HTTP server + goroutine join channels.
type AppDeps struct {
	// ── Logger + cancellation ─────────────────────────────────────
	// The process-wide logger. Set by main before any boot phase
	// runs. Each phase reads from it; never reassigned.
	Logger *slog.Logger

	// Fatal is the supervisor's panic-surfacing channel. Background
	// goroutines wired in Phase B send to it on unrecoverable
	// errors; main reads from it in the supervisor select.
	Fatal chan error

	// ── Phase A: I/O handles ──────────────────────────────────────
	// These have a Close method. Each open registers a NamedCloser
	// onto closeStack so Phase C can register it with the
	// ShutdownChain in spec order.

	PgPool          *store.Pool
	WALDB           *badger.DB
	WALCommitter    *wal.Committer
	ByteStore       bytestore.Backend
	TesseraEmbedded *tessera.EmbeddedAppender
	TileBackend     *tessera.POSIXTileBackend
	TileReader      *tessera.TileReader
	Antispam        *tposixantispam.AntispamStorage
	GossipStore     *gossipstore.BadgerStore // nil when gossip disabled
	// BuilderLock is owned exclusively by alloc — the closer
	// captures the local handle directly. Not held on AppDeps
	// because no other phase reads it.
	DBBreaker *store.Breaker

	// ── Phase A: identities + signers (no Close; cross all phases) ─

	// LedgerSignerPriv is the secp256k1 ECDSA key the ledger uses to
	// sign its own commentary entries. LedgerDID is the did:key:z…
	// derived from its public key; it equals cfg.LedgerDID at the
	// composition root.
	LedgerSignerPriv *ecdsa.PrivateKey
	LedgerDID        string
	// TesseraSigner is consumed by tessera.NewEmbeddedAppender at
	// construction; the appender holds the only reference. Not
	// held on AppDeps because no other phase reads it.
	// WitnessSignerPriv is the cosign signing key. nil when
	// witness mode is not active.
	WitnessSignerPriv *ecdsa.PrivateKey

	// NetworkID echoes cfg.NetworkID for downstream consumers
	// (gossip wiring, witness handler) without re-reading config.
	NetworkID cosign.NetworkID

	// ── Phase A: telemetry handles ────────────────────────────────

	// MeterProvider + GossipMeter are nil when LEDGER_METRICS_ENABLE
	// is false. MetricsHandler is nil under the same condition.
	MeterProvider  metric.MeterProvider
	GossipMeter    metric.Meter
	MetricsHandler http.Handler

	// ── Phase B: wired components ─────────────────────────────────

	EntryStore      *store.EntryStore
	CreditStore     *store.CreditStore
	CommitStore     *store.CommitmentStore
	LeafStore       *store.PostgresLeafStore
	NodeCache       *store.PostgresNodeCache
	TreeHeadStore   *store.TreeHeadStore
	DiffController  *middleware.DifficultyController
	BuilderLoop     *builder.BuilderLoop
	Sequencer       *sequencer.Sequencer
	Shipper         *shipper.Shipper
	AnchorPublisher *anchor.Publisher
	GossipBundle    *gossipnet.Bundle       // nil when gossip disabled
	GossipPublisher *gossipnet.STHPublisher // nil when gossip disabled

	// HTTPServer is the *api.Server wrapper — exposes Shutdown +
	// SetReady. Stdlib http.Server lives inside it; teardown calls
	// HTTPServer.Shutdown.
	HTTPServer *api.Server
	// HTTPListener is the netutil.LimitListener-wrapped listener
	// the HTTP server runs on. Held so teardown can close it
	// directly if Shutdown's drain misbehaves.
	HTTPListener net.Listener

	// HTTPTLSEnabled mirrors (cfg.TLSCertFile != "" && cfg.TLSKeyFile
	// != "") so the http-server goroutine knows which Serve method
	// to call without re-reading the original config.
	HTTPTLSEnabled bool

	// PprofServer is nil when pprof is disabled.
	PprofServer *http.Server

	// WG joins every long-running goroutine started in Phase B
	// (HTTP server, builder loop, sequencer, shipper, etc.).
	// teardown waits on this group as part of the
	// "background-goroutines" shutdown step.
	WG sync.WaitGroup

	// ── closeStack — owned by Phase A, transcribed by Phase C ────
	closeStack []NamedCloser
}

// AppendCloser pushes a NamedCloser onto the stack in registration
// order. The stack is consumed by teardown.Register in the same
// order, then drained.
//
// Allocators call this after every successful resource open. The
// caller's pattern is:
//
//	pool, err := store.InitPool(...)
//	if err != nil { return deps.UnwindReverse(...); err }
//	deps.PgPool = pool
//	deps.AppendCloser(deps.NamedCloser("postgres", 30*time.Second, ...))
func (d *AppDeps) AppendCloser(c NamedCloser) {
	d.closeStack = append(d.closeStack, c)
}

// TakeClosers returns the close stack in REGISTRATION order and
// resets it to nil. Called by teardown.Register exactly once. The
// reset matters: it makes a second teardown attempt a no-op (the
// stack is empty) so a panic during teardown can't double-close.
func (d *AppDeps) TakeClosers() []NamedCloser {
	out := d.closeStack
	d.closeStack = nil
	return out
}

// UnwindReverse calls every NamedCloser.Close in REVERSE registration
// order, with the supplied ctx as parent for each per-component
// budget. Used by alloc.Allocate when an open fails part-way through
// — every previously-opened resource is closed before the error
// propagates to main.
//
// Errors from individual closes are logged via deps.Logger (with the
// resource name) but do not abort the unwind. Best-effort: the goal
// is to release fds + flush state, not to surface a clean error.
//
// After UnwindReverse returns, closeStack is reset; subsequent
// teardown.Register calls find nothing to register (correct: alloc
// failure means no shutdown chain ever runs).
func (d *AppDeps) UnwindReverse(ctx context.Context) {
	for i := len(d.closeStack) - 1; i >= 0; i-- {
		c := d.closeStack[i]
		// Per-component bounded ctx: the same budget the
		// ShutdownChain would have used.
		cctx, cancel := context.WithTimeout(ctx, c.Timeout)
		if err := c.Close(cctx); err != nil && d.Logger != nil {
			d.Logger.Warn("alloc unwind: close error",
				"step", c.Name, "error", err)
		}
		cancel()
	}
	d.closeStack = nil
}
