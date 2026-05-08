//go:build p4
// +build p4

// Package p4 hosts production-realism + chaos tests for the ledger.
//
// FILE PATH: tests/p4/harness.go
//
// SCOPE:
//
//   - P4.2 — Advisory-lock split-brain (one DSN, two builder-lock
//     contenders; second must be denied within
//     DefaultBuilderLockAcquireTimeout, then granted on release).
//   - P4.3 — 2-replica failover (kill active, standby resumes WAL +
//     Tessera; tree-integrity continuity).
//   - P4.4 — Witness offline matrix (K-of-N cells; the "Backpressure
//     Stall" semantics will land here once the implementation is in).
//   - P4.5 — Cryptographic integrity master test (cross-API
//     consistency + tile walk + equivocation detection + restart
//     resumption).
//   - P4.1 — Multi-persona concurrent load (auditor / indexer / fraud
//     bot / peer ledger / browser auditor goroutine pools running
//     against a live admission load).
//
// BUILD GATE:
//
// All tests in this package use //go:build p4 so the default
// `go test ./...` run never invokes them. P4 runs require a real
// Postgres (and, depending on the test, a Tessera POSIX dir, witness
// stub HTTP servers, gossip peers). Opt-in via:
//
//	ATTESTA_TEST_DSN=postgres://… \
//	  go test -tags=p4 -count=1 -v ./tests/p4/
//
// Or via scripts/run-p4.sh which auto-provisions Postgres when the
// DSN is unset.
//
// PRINCIPLES THIS PACKAGE PINS:
//
//   - Ledger Principle 5  ("melt-proof") — load shedding under
//     spike + degraded peer conditions.
//   - Ledger Principle 12 ("two clocks") — commit-clock is
//     blocking + alerting; transparency-clock is fan-out.
//   - Ledger Principle 14 ("graceful teardowns") — SIGTERM →
//     drain → restart preserves data integrity.
//   - Alignment 2 ("decentralized threshold witnessing") — STH is
//     unfinalized until K-of-N collected.
//
// ARCHITECTURAL NOTE:
//
// We run two ledger contenders IN-PROCESS (two distinct *pgxpool.Pool
// instances against the same DSN) rather than fork two OS processes.
// pg_advisory_lock is session-scoped; two pgxpool.Pools resolve to
// distinct Postgres backend sessions, so the lock contention is the
// same as it would be across two binaries. Faster, easier to debug,
// no os/exec orchestration. If a future test needs OS-process
// fidelity (e.g., signal handling), it can opt up.
package p4

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ledger/store"
)

// requirePostgres returns a connected pool against ATTESTA_TEST_DSN
// or skips the calling test if the env var is unset. The returned
// pool is migrated and ready for fixture writes.
//
// pgxpool.New itself never blocks on a healthy Postgres — but we
// use a 5-second connection-timeout here so a misconfigured DSN
// fails the test immediately rather than at the first pool.Acquire.
func requirePostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN unset; skipping P4 test (use scripts/run-p4.sh)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("p4: pgxpool.New: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("p4: RunMigrations: %v", err)
	}
	return pool
}

// freshPool returns a brand-new *pgxpool.Pool against the same DSN,
// for tests that need TWO independent connection pools (e.g., the
// advisory-lock split-brain). Each pool gets its own backend
// sessions; pg_advisory_lock is session-scoped so contention here
// matches the cross-binary case.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN unset; skipping P4 test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("p4: freshPool: %v", err)
	}
	return pool
}

// silentLogger returns an slog.Logger that discards all output.
// P4 tests assert on counter / channel state, not on log content;
// keeping logger output out of the test stream makes failure
// diagnostics easier to read.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
