/*
FILE PATH: api/server.go

HTTP server initialization and route registration. All Ortholog
operator endpoints live under /v1/. Health checks at /healthz and
/readyz.

KEY ARCHITECTURAL DECISIONS:
  - net/http standard library: no framework dependency.
  - Middleware chain: SizeLimit → Auth → handler for submission paths.
  - All handlers receive dependencies via closure (no globals).
  - Readiness flag is atomic for thread-safe shutdown signaling.
  - Optional endpoints (WitnessCosign, read endpoints, batch
    submission) are nil-guarded so binaries that don't serve them
    (cmd/operator-reader, lightweight test harnesses) can omit
    the wiring without producing a 500 or panicking through a
    nil HandlerFunc.

ROUTE TABLE (write side, with middleware):
  - POST /v1/entries          — single-entry SCT/MMD admission.
  - POST /v1/entries/batch    — async batch admission; returns SCT
                                array. Bounded at
                                AbsoluteMaxBatchPayloadBytes.

ROUTE TABLE (read side, no middleware):
  - GET  /v1/entries/{seq}            — JSON metadata
  - GET  /v1/entries/{seq}/raw        — wire bytes (200 inline /
                                        302 redirect to bytestore)
  - GET  /v1/entries/batch?...        — JSON list of metadata
  - GET  /v1/entries-hash/{hashHex}   — hash-keyed lookup; surfaces
                                        the SCT inflight state
  - GET  /v1/admission/mmd            — operator's promised MMD
  - GET  /v1/admission/difficulty     — Mode B PoW difficulty
  - GET  /v1/tree/head[?size=N]       — cosigned tree head
  - GET  /v1/tree/inclusion/{seq}     — Merkle inclusion proof
  - GET  /v1/tree/consistency/{old}/{new}
  - GET  /v1/smt/proof/{key}          — SMT membership/non-mem proof
  - POST /v1/smt/batch_proof          — batch SMT proof
  - GET  /v1/smt/root                 — current SMT root
  - GET  /v1/smt/leaf/{key}           — SMT leaf data
  - POST /v1/smt/leaves               — batch leaf data
  - GET  /v1/query/cosignature_of/{pos}
  - GET  /v1/query/target_root/{pos}
  - GET  /v1/query/signer_did/{did}
  - GET  /v1/query/schema_ref/{pos}
  - GET  /v1/query/scan?start&count
  - GET  /v1/commitments?seq=N        — derivation commitment lookup
  - POST /v1/cosign                   — witness cosign endpoint
                                        (only when WitnessCosign set)
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

// Handlers holds all registered handler functions. Nil fields
// suppress route registration — fine for read-only operators
// (cmd/operator-reader) and trimmed-down test harnesses.
type Handlers struct {
	// ── Admission (write) ───────────────────────────────────────────
	Submission      http.HandlerFunc // POST /v1/entries        — single-entry SCT
	BatchSubmission http.HandlerFunc // POST /v1/entries/batch  — async batch SCT array

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
	Difficulty http.HandlerFunc // GET /v1/admission/difficulty — Mode B PoW difficulty
	MMD        http.HandlerFunc // GET /v1/admission/mmd        — Maximum Merge Delay

	// ── Witness cosign (optional) ───────────────────────────────────
	WitnessCosign http.Handler // nil unless serving as a witness

	// ── Gossip (optional) ───────────────────────────────────────────
	// GossipPost mounts at POST /v1/gossip; peers publish signed
	// events here. nil disables the publish path; the feed
	// endpoints can still be served if GossipFeed is set.
	GossipPost http.Handler

	// GossipFeed mounts at GET /v1/gossip/{since,sth/latest,event,
	// by-kind}. Audit consumers + peer operators pull catchup
	// events here. nil disables read-side gossip; the publish
	// path can still be served if GossipPost is set.
	GossipFeed http.Handler

	// EscrowOverride mounts at POST /v1/escrow-override. Accepts
	// a {escrow_id, decision_hash, effective} body, runs K-of-N
	// witness cosignature collection, and broadcasts the
	// authorization as a KindEscrowOverrideAuth gossip event.
	// nil disables the endpoint (gossip disabled, witness mode
	// disabled, or no signer configured).
	EscrowOverride http.HandlerFunc

	// Metrics mounts at GET /metrics — the Prometheus scrape
	// endpoint. nil disables the endpoint (OPERATOR_METRICS_ENABLE
	// is false; default).
	Metrics http.Handler

	// ── Read endpoints (entry fetch + SMT leaf + commitments) ───────
	EntryBySequence http.HandlerFunc // GET /v1/entries/{sequence}      (JSON metadata)
	EntryBatch      http.HandlerFunc // GET /v1/entries/batch           (JSON list)
	EntryByHash     http.HandlerFunc // GET /v1/entries-hash/{hashHex}  (WAL-aware metadata; surfaces SCT pending state)
	EntryRaw        http.HandlerFunc // GET /v1/entries/{sequence}/raw  (wire bytes; 200 inline OR 302 redirect)

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

	// ── Batch submission — async, returns SCTs ─────────────────────────
	// SizeLimit cap mirrors api/batch.go::AbsoluteMaxBatchPayloadBytes
	// (64 MiB hard ceiling). The handler itself enforces a tighter
	// per-deployment cap derived from MaxEntrySize × MaxBatchSize.
	if handlers.BatchSubmission != nil {
		batchChain := middleware.SizeLimit(
			AbsoluteMaxBatchPayloadBytes+1024,
			middleware.Auth(db, handlers.BatchSubmission),
		)
		mux.Handle("POST /v1/entries/batch", batchChain)
	}

	// ── SCT/MMD: MMD info ───────────────────────────────────────────
	// Consumers verify the operator's promised redemption window
	// against this endpoint before trusting an SCT.
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
		mux.HandleFunc("POST /v1/smt/batch_proof", handlers.SMTBatchProof)
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

	// ── Admission info (read-only) ─────────────────────────────────────
	if handlers.Difficulty != nil {
		mux.HandleFunc("GET /v1/admission/difficulty", handlers.Difficulty)
	}

	// ── Witness cosign endpoint (optional) ─────────────────────────────
	if handlers.WitnessCosign != nil {
		mux.Handle("POST /v1/cosign", handlers.WitnessCosign)
	}

	// ── Gossip endpoints (optional) ────────────────────────────────────
	// POST /v1/gossip      — peer publish (signed events)
	// GET  /v1/gossip/sth/latest, /v1/gossip/since,
	//      /v1/gossip/by-kind, /v1/gossip/event/{eventID}
	//                       — audit pull (CDN-cacheable)
	if handlers.GossipPost != nil {
		mux.Handle("POST /v1/gossip", handlers.GossipPost)
	}
	if handlers.GossipFeed != nil {
		mux.Handle("GET /v1/gossip/sth/latest", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/since", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/by-kind", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/event/{eventID}", handlers.GossipFeed)
	}
	if handlers.EscrowOverride != nil {
		mux.HandleFunc("POST /v1/escrow-override", handlers.EscrowOverride)
	}

	// ── Prometheus scrape endpoint (optional) ──────────────────────────
	// GET /metrics serves the SDK's MeterProvider Prometheus output.
	// Mounted only when MetricsEnable=true at boot.
	if handlers.Metrics != nil {
		mux.Handle("GET /metrics", handlers.Metrics)
	}

	// ── Entry read endpoints (nil-guarded for read-only operators) ─────
	// GET /v1/entries/{sequence} — single entry by position.
	// GET /v1/entries/batch — batch read for fraud-proof replay.
	// Method+path routing guarantees these don't collide with
	// POST /v1/entries (admission) or POST /v1/entries/batch (async
	// batch admission) registered above.
	if handlers.EntryBySequence != nil {
		mux.HandleFunc("GET /v1/entries/{sequence}", handlers.EntryBySequence)
	}
	if handlers.EntryBatch != nil {
		mux.HandleFunc("GET /v1/entries/batch", handlers.EntryBatch)
	}
	if handlers.EntryByHash != nil {
		// Hash-keyed lookup. POST /v1/entries returns a
		// SignedCertificateTimestamp without a sequence number; SCT
		// recipients poll this endpoint to confirm sequencing
		// (state transitions pending → sequenced as the background
		// Sequencer drains the WAL).
		//
		// URL is /v1/entries-hash/{hashHex} (NOT /v1/entries-hash/...)
		// to avoid a Go 1.22+ mux pattern conflict with
		// /v1/entries/{sequence}/raw — both would otherwise match
		// /v1/entries-hash/raw and neither is strictly more specific.
		mux.HandleFunc("GET /v1/entries-hash/{hashHex}", handlers.EntryByHash)
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
