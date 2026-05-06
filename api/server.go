/*
FILE PATH:
    api/server.go

DESCRIPTION:
    HTTP server initialization and route registration. Every
    Attesta ledger endpoint lives under /v1/. Health checks at
    /healthz and /readyz. The server is constructed against an
    explicit Handlers struct (closure-fed dependencies, no
    globals) and exposes ListenAndServe / ListenAndServeTLS /
    Serve / Shutdown for the cmd/ledger orchestrator.

KEY ARCHITECTURAL DECISIONS:
    - net/http standard library only. No framework dependency —
      the handler surface is small and the routing is purely
      method+path so the stdlib mux is sufficient.
    - DoS-immune timeouts. ReadHeaderTimeout caps the headers-
      arrived window (Slowloris defense); IdleTimeout caps the
      keep-alive idle window (long-lived-connection defense).
      ReadTimeout/WriteTimeout cap the full-request lifetimes.
    - Body caps applied via http.MaxBytesReader on every route
      that reads a body. Routes that take no body (GET /healthz,
      GET /readyz, every read endpoint) need no cap. Bounded I/O
      is structural — the memory cost of a malicious peer is
      mathematically capped.
    - Per-request correlation ID middleware wraps the entire mux
      so every handler + every structured log line carries the
      same X-Request-ID for cross-component tracing.
    - Readiness flag is atomic for thread-safe shutdown signalling.
      Pre-drain handshake (flip readiness BEFORE Shutdown) is in
      cmd/ledger/main.go; this file's Shutdown method is the
      Shutdown-after-grace primitive.
    - Optional handlers (WitnessCosign, GossipPost/Feed, read
      endpoints, batch admission, tile-serving) are nil-guarded so
      cmd/ledger-reader and trimmed test harnesses can omit them
      without producing 500s through nil HandlerFuncs.

OVERVIEW:
    NewServer constructs the mux, registers routes (with
    SizeLimit + Auth middleware on write paths), and wraps the
    whole tree in WithRequestID. The resulting *http.Server is
    started by ListenAndServe / ListenAndServeTLS / Serve and
    drained by Shutdown.

KEY DEPENDENCIES:
    - api/middleware: SizeLimit, Auth, WithRequestID — orthogonal
      cross-cutting concerns.
    - sync/atomic: lock-free readiness signal so /readyz never
      contends with the rest of the request flow.
*/
package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/clearcompass-ai/ledger/api/middleware"
)

// -------------------------------------------------------------------------------------------------
// 1) Server Configuration
// -------------------------------------------------------------------------------------------------

// ServerConfig configures the HTTP server.
//
// Every timeout MUST be non-zero in production. Zero means "no
// deadline" in net/http, which is a Slowloris vector. Use
// DefaultServerConfig() at boot and override individual fields
// only with cause.
type ServerConfig struct {
	Addr string

	// ReadTimeout caps the full request-read window: TLS
	// handshake + headers + body.
	ReadTimeout time.Duration

	// ReadHeaderTimeout caps the header-only window. Set tighter
	// than ReadTimeout so a client streaming a large body has the
	// full ReadTimeout budget; a client trickling headers is cut
	// off at ReadHeaderTimeout. This is the primary Slowloris
	// defense.
	ReadHeaderTimeout time.Duration

	// WriteTimeout caps the response-write window from end-of-
	// request-headers to end-of-response.
	WriteTimeout time.Duration

	// IdleTimeout caps the keep-alive idle window between requests
	// on the same connection. Bounds memory tied up by zombie
	// connections.
	IdleTimeout time.Duration

	// ShutdownTimeout is the budget Shutdown gets to drain in-
	// flight requests before forcibly closing.
	ShutdownTimeout time.Duration

	// MaxEntrySize is the per-entry body cap on POST /v1/entries.
	// The middleware wraps r.Body in http.MaxBytesReader at
	// MaxEntrySize+1024 so the entry plus a small framing budget
	// fits but a malicious peer's gigabyte body is rejected.
	MaxEntrySize int64

	// TLSCertFile / TLSKeyFile, when both non-empty, switch the
	// listener to ListenAndServeTLS. Operator deployments that
	// front the binary with a TLS-terminating proxy leave both
	// empty and the server speaks plain HTTP. Standalone (VM /
	// bare-metal / sigsum-witness) deployments populate both.
	TLSCertFile string
	TLSKeyFile  string
}

// DefaultServerConfig returns production-grade defaults. Every
// timeout is non-zero so the returned *http.Server has no
// Slowloris-shaped exposure even before per-route middleware.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:              ":8080",
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   30 * time.Second,
		MaxEntrySize:      1 << 20, // 1 MiB
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Server
// -------------------------------------------------------------------------------------------------

// Server is the ledger HTTP server.
type Server struct {
	httpServer *http.Server
	cfg        ServerConfig
	ready      atomic.Bool
	logger     *slog.Logger
}

// Handlers holds all registered handler functions. Nil fields
// suppress route registration — fine for read-only ledgers
// (cmd/ledger-reader) and trimmed test harnesses.
type Handlers struct {
	// ── Admission (write) ───────────────────────────────────────────
	Submission      http.HandlerFunc // POST /v1/entries — single-entry SCT
	BatchSubmission http.HandlerFunc // POST /v1/entries/batch — async batch SCT array

	// ── Tree heads + Merkle proofs ──────────────────────────────────
	TreeHead        http.HandlerFunc
	TreeInclusion   http.HandlerFunc
	TreeConsistency http.HandlerFunc

	// ── SMT proofs ──────────────────────────────────────────────────
	SMTProof      http.HandlerFunc
	SMTBatchProof http.HandlerFunc
	SMTRoot       http.HandlerFunc

	// ── Index queries ───────────────────────────────────────────────
	CosignatureOf http.HandlerFunc
	TargetRoot    http.HandlerFunc
	SignerDID     http.HandlerFunc
	SchemaRef     http.HandlerFunc
	Scan          http.HandlerFunc

	// ── Admission info ──────────────────────────────────────────────
	Difficulty http.HandlerFunc // GET /v1/admission/difficulty
	MMD        http.HandlerFunc // GET /v1/admission/mmd

	// ── Witness cosign (optional) ───────────────────────────────────
	WitnessCosign http.Handler

	// ── Gossip (optional) ───────────────────────────────────────────
	GossipPost http.Handler
	GossipFeed http.Handler

	// EscrowOverride mounts at POST /v1/escrow-override.
	EscrowOverride http.HandlerFunc

	// Metrics mounts at GET /metrics.
	Metrics http.Handler

	// ── Read endpoints ──────────────────────────────────────────────
	EntryBySequence http.HandlerFunc
	EntryBatch      http.HandlerFunc
	EntryByHash     http.HandlerFunc
	EntryRaw        http.HandlerFunc
	SMTLeaf         http.HandlerFunc
	SMTLeafBatch    http.HandlerFunc
	CommitmentQuery http.HandlerFunc

	// CommitmentLookup serves
	//   GET /v1/commitments/by-split-id/{schema_id}/{hex}
	// the cryptographic-commitment lookup endpoint backed by the
	// pure-CQRS read-side projection (Badger 0x0C).
	CommitmentLookup http.HandlerFunc

	// ── Static-CT tile serving (optional) ───────────────────────────
	// Checkpoint serves GET /checkpoint — the c2sp.org/tlog-tiles
	// signed checkpoint Tessera writes after each integration
	// cycle. Auditors fetch this to anchor inclusion proofs.
	Checkpoint http.HandlerFunc

	// Tile serves GET /tile/{level}/{rest...} — RFC c2sp.org/
	// tlog-tiles hash tiles. The handler dispatches internally
	// when {level} == "entries" to the entry-bundle path so the
	// stdlib mux's pattern coverage stays unambiguous.
	Tile http.HandlerFunc
}

// -------------------------------------------------------------------------------------------------
// 3) Construction
// -------------------------------------------------------------------------------------------------

// NewServer creates the HTTP server with all routes and middleware
// applied. Returns a non-nil *Server even when handlers is the
// zero value (every route is nil-guarded).
func NewServer(
	cfg ServerConfig,
	sessions middleware.SessionLookup,
	handlers Handlers,
	logger *slog.Logger,
) *Server {
	s := &Server{cfg: cfg, logger: logger}
	s.ready.Store(true)

	mux := http.NewServeMux()

	// ── Health checks ──────────────────────────────────────────────────
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.ready.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("shutting down"))
		}
	})

	// ── Submission — full middleware chain ─────────────────────────────
	if handlers.Submission != nil {
		submissionChain := middleware.SizeLimit(
			cfg.MaxEntrySize+1024,
			middleware.Auth(sessions, handlers.Submission),
		)
		mux.Handle("POST /v1/entries", submissionChain)
	}

	// ── Batch submission — async, returns SCTs ─────────────────────────
	if handlers.BatchSubmission != nil {
		batchChain := middleware.SizeLimit(
			AbsoluteMaxBatchPayloadBytes+1024,
			middleware.Auth(sessions, handlers.BatchSubmission),
		)
		mux.Handle("POST /v1/entries/batch", batchChain)
	}

	if handlers.MMD != nil {
		mux.HandleFunc("GET /v1/admission/mmd", handlers.MMD)
	}

	// ── Tree head + proofs (read-only) ─────────────────────────────────
	if handlers.TreeHead != nil {
		mux.HandleFunc("GET /v1/tree/head", handlers.TreeHead)
	}
	if handlers.TreeInclusion != nil {
		mux.HandleFunc("GET /v1/tree/inclusion/{seq}", handlers.TreeInclusion)
	}
	if handlers.TreeConsistency != nil {
		mux.HandleFunc("GET /v1/tree/consistency/{old}/{new}", handlers.TreeConsistency)
	}

	// ── SMT proofs (read-only) ─────────────────────────────────────────
	if handlers.SMTProof != nil {
		mux.HandleFunc("GET /v1/smt/proof/{key}", handlers.SMTProof)
	}
	if handlers.SMTBatchProof != nil {
		// Bounded — SMT batch proofs are JSON request/response.
		mux.Handle("POST /v1/smt/batch_proof",
			middleware.SizeLimit(MaxSMTBatchPayloadBytes+1024, http.HandlerFunc(handlers.SMTBatchProof)))
	}
	if handlers.SMTRoot != nil {
		mux.HandleFunc("GET /v1/smt/root", handlers.SMTRoot)
	}

	// ── Query endpoints (read-only) ────────────────────────────────────
	if handlers.CosignatureOf != nil {
		mux.HandleFunc("GET /v1/query/cosignature_of/{pos}", handlers.CosignatureOf)
	}
	if handlers.TargetRoot != nil {
		mux.HandleFunc("GET /v1/query/target_root/{pos}", handlers.TargetRoot)
	}
	if handlers.SignerDID != nil {
		mux.HandleFunc("GET /v1/query/signer_did/{did}", handlers.SignerDID)
	}
	if handlers.SchemaRef != nil {
		mux.HandleFunc("GET /v1/query/schema_ref/{pos}", handlers.SchemaRef)
	}
	if handlers.Scan != nil {
		mux.HandleFunc("GET /v1/query/scan", handlers.Scan)
	}

	if handlers.Difficulty != nil {
		mux.HandleFunc("GET /v1/admission/difficulty", handlers.Difficulty)
	}

	// ── Witness cosign endpoint ────────────────────────────────────────
	if handlers.WitnessCosign != nil {
		mux.Handle("POST /v1/cosign",
			middleware.SizeLimit(MaxCosignRequestBytes+1024, handlers.WitnessCosign))
	}

	// ── Gossip endpoints (optional) ────────────────────────────────────
	if handlers.GossipPost != nil {
		mux.Handle("POST /v1/gossip",
			middleware.SizeLimit(MaxGossipPostBytes+1024, handlers.GossipPost))
	}
	if handlers.GossipFeed != nil {
		mux.Handle("GET /v1/gossip/sth/latest", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/since", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/by-kind", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/event/{eventID}", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/by-binding/{hash}", handlers.GossipFeed)
	}
	if handlers.EscrowOverride != nil {
		mux.Handle("POST /v1/escrow-override",
			middleware.SizeLimit(MaxEscrowOverrideBytes+1024, http.HandlerFunc(handlers.EscrowOverride)))
	}

	if handlers.Metrics != nil {
		mux.Handle("GET /metrics", handlers.Metrics)
	}

	// ── Entry read endpoints (nil-guarded) ─────────────────────────────
	if handlers.EntryBySequence != nil {
		mux.HandleFunc("GET /v1/entries/{sequence}", handlers.EntryBySequence)
	}
	if handlers.EntryBatch != nil {
		mux.HandleFunc("GET /v1/entries/batch", handlers.EntryBatch)
	}
	if handlers.EntryByHash != nil {
		mux.HandleFunc("GET /v1/entries-hash/{hashHex}", handlers.EntryByHash)
	}
	if handlers.EntryRaw != nil {
		mux.HandleFunc("GET /v1/entries/{sequence}/raw", handlers.EntryRaw)
	}

	if handlers.SMTLeaf != nil {
		mux.HandleFunc("GET /v1/smt/leaf/{key}", handlers.SMTLeaf)
	}
	if handlers.SMTLeafBatch != nil {
		mux.Handle("POST /v1/smt/leaves",
			middleware.SizeLimit(MaxSMTLeavesPayloadBytes+1024, http.HandlerFunc(handlers.SMTLeafBatch)))
	}

	if handlers.CommitmentQuery != nil {
		mux.HandleFunc("GET /v1/commitments", handlers.CommitmentQuery)
	}
	if handlers.CommitmentLookup != nil {
		mux.HandleFunc(
			"GET /v1/commitments/by-split-id/{schema_id}/{hex}",
			handlers.CommitmentLookup,
		)
	}

	// ── Static-CT tile serving (optional) ──────────────────────────────
	// External auditors fetch the canonical c2sp.org/tlog-tiles
	// endpoints to reconstruct inclusion + consistency proofs
	// independently. Path-traversal defense lives inside the
	// handler (api/tile_handler.go).
	if handlers.Checkpoint != nil {
		mux.HandleFunc("GET /checkpoint", handlers.Checkpoint)
	}
	if handlers.Tile != nil {
		// Single dispatcher captures both /tile/{level}/{...} and
		// /tile/entries/{...}. The handler routes internally so we
		// avoid stdlib-mux specificity collisions.
		mux.HandleFunc("GET /tile/{level}/{rest...}", handlers.Tile)
	}

	// -------------------------------------------------------------------------------------------------
	// 4) Cross-cutting middleware
	// -------------------------------------------------------------------------------------------------
	//
	// Every request gets a correlation ID. Wraps the entire mux
	// (after route registration) so health checks, write paths,
	// and read paths all carry the same X-Request-ID surface.
	root := middleware.WithRequestID(mux)

	// -------------------------------------------------------------------------------------------------
	// 5) http.Server with DoS-immune timeouts
	// -------------------------------------------------------------------------------------------------

	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           root,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, // Slowloris cap
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout, // keep-alive zombie cap
		BaseContext:       func(_ net.Listener) context.Context { return context.Background() },
		// TLSConfig is populated by ListenAndServeTLS on first call;
		// plain HTTP leaves it nil.
		TLSConfig: nil,
	}

	return s
}

// -------------------------------------------------------------------------------------------------
// 6) Lifecycle
// -------------------------------------------------------------------------------------------------

// ListenAndServe starts the HTTP server in plaintext mode.
// Blocks until error or shutdown.
//
// Production deployments that terminate TLS in a sidecar / proxy
// (most k8s deployments) call ListenAndServe. Deployments that
// terminate TLS in the binary call ListenAndServeTLS instead.
func (s *Server) ListenAndServe() error {
	s.logger.Info("HTTP server starting", "addr", s.httpServer.Addr, "tls", false)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// ListenAndServeTLS starts the HTTP server with TLS termination
// in the binary. cfg.TLSCertFile / cfg.TLSKeyFile MUST be non-
// empty; otherwise returns an immediate error.
//
// HTTP/2 is explicitly enabled by populating
// TLSConfig.NextProtos with "h2" + "http/1.1" before
// ListenAndServeTLS runs. http.Server's automatic-HTTP/2-over-TLS
// path is conditional on a nil-or-default NextProtos; setting it
// explicitly is the documented opt-in for predictable ALPN
// negotiation across deployment lanes (and lets operators audit
// the wire-protocol surface in code, not in framework defaults).
func (s *Server) ListenAndServeTLS() error {
	if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
		return fmt.Errorf("api/server: ListenAndServeTLS requires TLSCertFile + TLSKeyFile")
	}
	if s.httpServer.TLSConfig == nil {
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
	}
	s.logger.Info("HTTP server starting (TLS)",
		"addr", s.httpServer.Addr,
		"tls", true,
		"alpn", s.httpServer.TLSConfig.NextProtos,
	)
	if err := s.httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// Serve starts the HTTP server on the given listener. The cmd/
// orchestrator uses this when wrapping the listener in
// netutil.LimitListener for a connection cap.
func (s *Server) Serve(ln net.Listener) error {
	s.logger.Info("HTTP server starting", "addr", ln.Addr().String())
	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// ServeTLSWithListener starts the HTTP server with TLS termination
// on the supplied listener — typically a netutil.LimitListener
// wrapping the raw net.Listener so the connection cap applies to
// TLS-terminated traffic too.
//
// HTTP/2 is explicitly enabled by populating TLSConfig.NextProtos
// with "h2" + "http/1.1" before ServeTLS runs. http.Server's
// automatic-HTTP/2-over-TLS path is conditional on a nil-or-
// default NextProtos; setting it explicitly is the documented
// opt-in for predictable ALPN negotiation across deployment lanes
// (and lets operators audit the wire-protocol surface in code,
// not in framework defaults).
func (s *Server) ServeTLSWithListener(ln net.Listener) error {
	if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
		return fmt.Errorf("api/server: ServeTLSWithListener requires TLSCertFile + TLSKeyFile")
	}
	if s.httpServer.TLSConfig == nil {
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
	}
	s.logger.Info("HTTP server starting (TLS)",
		"addr", ln.Addr().String(),
		"tls", true,
		"alpn", s.httpServer.TLSConfig.NextProtos,
	)
	if err := s.httpServer.ServeTLS(ln, s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// SetReady controls the /readyz response. Pass false BEFORE
// Shutdown to flip readiness so load balancers remove the pod
// from rotation, then wait for the pre-drain grace period
// before calling Shutdown. Returns the previous value.
func (s *Server) SetReady(ready bool) bool {
	return s.ready.Swap(ready)
}

// Shutdown gracefully shuts down the server. Drains in-flight
// requests within ctx's deadline; forces close after.
func (s *Server) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	s.logger.Info("HTTP server shutting down")
	return s.httpServer.Shutdown(ctx)
}
