/*
FILE PATH: api/server.go

HTTP server initialization and route registration. All Ortholog operator
endpoints under /v1/. Health checks at /healthz and /readyz.

KEY ARCHITECTURAL DECISIONS:
  - net/http standard library: no framework dependency.
  - Middleware chain: size_limit → auth → handler (for submission).
  - All handlers receive dependencies via closure (no globals).
  - Readiness flag is atomic for thread-safe shutdown signaling.
  - Optional endpoints (WitnessCosign, read endpoints) nil-guarded.

CHANGES FROM PHASE 4 PREP:
  - 5 new handler fields: EntryBySequence, EntryBatch, SMTLeaf, SMTLeafBatch, CommitmentQuery
  - 5 new routes registered with nil guards
  - Both cmd/operator/main.go and cmd/operator-reader/main.go wire these
*/
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Server Configuration
// ─────────────────────────────────────────────────────────────────────────────

// ServerConfig configures the HTTP server.
type ServerConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	MaxEntrySize    int64
}

// DefaultServerConfig returns production defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:            ":8080",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    60 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		MaxEntrySize:    1 << 20, // 1MB
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Server
// ─────────────────────────────────────────────────────────────────────────────

// Server is the operator HTTP server.
type Server struct {
	httpServer *http.Server
	ready      atomic.Bool
	logger     *slog.Logger
}

// Handlers holds all registered handler functions.
type Handlers struct {
	// ── Core endpoints (Phase 2) ────────────────────────────────────
	Submission      http.HandlerFunc
	TreeHead        http.HandlerFunc
	TreeInclusion   http.HandlerFunc
	TreeConsistency http.HandlerFunc
	SMTProof        http.HandlerFunc
	SMTBatchProof   http.HandlerFunc
	SMTRoot         http.HandlerFunc
	CosignatureOf   http.HandlerFunc
	TargetRoot      http.HandlerFunc
	SignerDID       http.HandlerFunc
	SchemaRef       http.HandlerFunc
	Scan            http.HandlerFunc
	Difficulty      http.HandlerFunc

	// ── Phase 4 prep: witness cosign (optional) ─────────────────────
	WitnessCosign http.Handler // nil if not serving as witness

	// ── Full buildout: read endpoints for remote consumers ──────────
	// Entry fetch by position — blocks Phase 5 verifiers.
	EntryBySequence http.HandlerFunc // GET /v1/entries/{sequence}     (JSON metadata)
	EntryBatch      http.HandlerFunc // GET /v1/entries/batch          (JSON list)
	EntryRaw        http.HandlerFunc // GET /v1/entries/{sequence}/raw (wire bytes; 200 inline OR 302 redirect)

	// SMT leaf data — blocks origin_evaluator.
	SMTLeaf      http.HandlerFunc // GET /v1/smt/leaf/{key}
	SMTLeafBatch http.HandlerFunc // POST /v1/smt/leaves

	// Commitment query — blocks fraud_proofs.
	CommitmentQuery http.HandlerFunc // GET /v1/commitments?seq=N
}

// NewServer creates the HTTP server with all routes and middleware applied.
func NewServer(
	cfg ServerConfig,
	db *pgxpool.Pool,
	handlers Handlers,
	logger *slog.Logger,
) *Server {
	s := &Server{logger: logger}
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

	// ── Submission — with full middleware chain ─────────────────────────
	if handlers.Submission != nil {
		submissionChain := middleware.SizeLimit(
			cfg.MaxEntrySize+1024,
			middleware.Auth(db, handlers.Submission),
		)
		mux.Handle("POST /v1/entries", submissionChain)
	}

	// ── Tree head + proofs (read-only) ─────────────────────────────────
	mux.HandleFunc("GET /v1/tree/head", handlers.TreeHead)
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", handlers.TreeInclusion)
	mux.HandleFunc("GET /v1/tree/consistency/{old}/{new}", handlers.TreeConsistency)

	// ── SMT proofs (read-only) ─────────────────────────────────────────
	mux.HandleFunc("GET /v1/smt/proof/{key}", handlers.SMTProof)
	mux.HandleFunc("POST /v1/smt/batch_proof", handlers.SMTBatchProof)
	mux.HandleFunc("GET /v1/smt/root", handlers.SMTRoot)

	// ── Query endpoints (read-only) ────────────────────────────────────
	mux.HandleFunc("GET /v1/query/cosignature_of/{pos}", handlers.CosignatureOf)
	mux.HandleFunc("GET /v1/query/target_root/{pos}", handlers.TargetRoot)
	mux.HandleFunc("GET /v1/query/signer_did/{did}", handlers.SignerDID)
	mux.HandleFunc("GET /v1/query/schema_ref/{pos}", handlers.SchemaRef)
	mux.HandleFunc("GET /v1/query/scan", handlers.Scan)

	// ── Admission info (read-only) ─────────────────────────────────────
	mux.HandleFunc("GET /v1/admission/difficulty", handlers.Difficulty)

	// ── Witness cosign endpoint (optional) ─────────────────────────────
	if handlers.WitnessCosign != nil {
		mux.Handle("POST /v1/cosign", handlers.WitnessCosign)
	}

	// ── Entry read endpoints (nil-guarded for backward compat) ─────────
	// GET /v1/entries/{sequence} — single entry by position.
	// GET /v1/entries/batch — batch read for fraud proof replay.
	// Note: GET /v1/entries/{sequence} doesn't conflict with
	// POST /v1/entries — different HTTP methods + path structure.
	if handlers.EntryBySequence != nil {
		mux.HandleFunc("GET /v1/entries/{sequence}", handlers.EntryBySequence)
	}
	if handlers.EntryBatch != nil {
		mux.HandleFunc("GET /v1/entries/batch", handlers.EntryBatch)
	}
	if handlers.EntryRaw != nil {
		// /raw subroute: wire bytes via WAL inline OR bytestore 302 redirect.
		// Registered with explicit /{sequence}/raw path so the {sequence}
		// pattern above doesn't shadow it.
		mux.HandleFunc("GET /v1/entries/{sequence}/raw", handlers.EntryRaw)
	}

	// ── SMT leaf read endpoints ────────────────────────────────────────
	if handlers.SMTLeaf != nil {
		mux.HandleFunc("GET /v1/smt/leaf/{key}", handlers.SMTLeaf)
	}
	if handlers.SMTLeafBatch != nil {
		mux.HandleFunc("POST /v1/smt/leaves", handlers.SMTLeafBatch)
	}

	// ── Commitment query ───────────────────────────────────────────────
	if handlers.CommitmentQuery != nil {
		mux.HandleFunc("GET /v1/commitments", handlers.CommitmentQuery)
	}

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		BaseContext:  func(_ net.Listener) context.Context { return context.Background() },
	}

	return s
}

// ListenAndServe starts the HTTP server. Blocks until error or shutdown.
func (s *Server) ListenAndServe() error {
	s.logger.Info("HTTP server starting", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// Serve starts the HTTP server on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	s.logger.Info("HTTP server starting", "addr", ln.Addr().String())
	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	s.logger.Info("HTTP server shutting down")
	return s.httpServer.Shutdown(ctx)
}
