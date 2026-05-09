// Package teardown implements Phase C of the ledger binary's lifecycle:
// transcribe the closeStack alloc + wire registered onto AppDeps into
// the lifecycle.ShutdownChain, in spec order, with the additional
// runtime steps wire produced (HTTP server, pprof server, goroutine
// drain, key-material zero-out, OTel meter/tracer flush).
//
// FILE PATH:
//
//	cmd/ledger/boot/teardown/teardown.go
//
// DESCRIPTION:
//
//	Register is the single entry point. It DOES NOT execute the
//	chain — main calls chain.Run() once the supervisor's select on
//	ctx.Done() / fatal completes. That separation lets main place
//	the pre-drain handshake (set readiness=false; sleep grace
//	period) BEFORE chain.Run, which the chain itself doesn't model.
//
//	The chain runs steps in REGISTRATION order with per-component
//	timeouts. Errors from individual steps are logged but do not
//	abort the chain (lifecycle.ShutdownChain semantics).
//
// KEY ARCHITECTURAL DECISIONS:
//
//   - Spec order is hard-coded here, not implicit in alloc's open
//     order. This is the authoritative shutdown spec; alloc's open
//     order matches by convention but the audit point is here.
//
//   - Runtime steps (HTTP server, pprof, WG drain, key zero-out)
//     are interleaved with the alloc closers via the
//     d.TakeClosers() inventory: HTTP + pprof + WG-drain run BEFORE
//     any alloc closer fires (background goroutines must finish
//     before their underlying I/O closes), then the alloc closers
//     run in their reverse-of-allocation order, then key zero-out
//     runs after PG/WAL/Tessera are gone, then OTel meter/tracer
//     flush last.
//
//   - The closeStack is consumed (TakeClosers resets to nil) so a
//     defensive teardown.Register call after a panic during teardown
//     can't double-register.
package teardown

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/deps"
	"github.com/clearcompass-ai/ledger/lifecycle"
)

// Register populates chain with the spec-order shutdown sequence.
// Returns the same chain for fluent use; main calls chain.Run() at
// the end of the supervisor select.
//
// Spec order:
//
//  1. http-server (drain in-flight requests)
//
//  2. pprof-server (close diagnostic listener)
//
//  3. background-goroutines (wg.Wait — sequencer/shipper/builder/
//     gossip observers all drain)
//
//  4. alloc closers in REVERSE registration order (newest first):
//     gossip-bundle-closeable(s) → gossip-store → tessera-antispam →
//     bytestore → tessera-embedded → wal-db → wal-committer →
//     builder-advisory-lock → postgres → otel-meter → otel-tracer
//
//     The closeStack already records this reverse order: alloc
//     pushed in registration order, TakeClosers returns in
//     registration order, and we register them with the chain in
//     reverse.
//
//  5. zero-key-material (after PG/WAL/Tessera have flushed; before
//     OTel meter so the step's duration is observable)
//
// Steps 1-3 are wire-produced runtime steps; step 4 is alloc-produced.
// Step 5 is teardown-owned (no allocator opens key material).
func Register(chain *lifecycle.ShutdownChain, d *deps.AppDeps) *lifecycle.ShutdownChain {
	// 1. HTTP server: 30s drain budget covers the slow-client tail of
	//    any in-flight long-poll readers.
	chain.Add("http-server", 30*time.Second, func(ctx context.Context) error {
		if d.HTTPServer == nil {
			return nil
		}
		return d.HTTPServer.Shutdown(ctx)
	})

	// 2. pprof server (optional).
	if d.PprofServer != nil {
		ps := d.PprofServer
		chain.Add("pprof-server", 5*time.Second, func(ctx context.Context) error {
			err := ps.Shutdown(ctx)
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		})
	}

	// 3. Background goroutines: drain BEFORE the I/O closers fire.
	//    Bounded by the per-component timeout so a wedged goroutine
	//    can't block downstream resource closes.
	chain.Add("background-goroutines", 30*time.Second, func(ctx context.Context) error {
		return waitGroupBounded(ctx, &d.WG)
	})

	// 4. Alloc closers in reverse registration order.
	//    TakeClosers returns in REGISTRATION order; we walk it
	//    backwards so newest-opened closes first.
	closers := d.TakeClosers()
	for i := len(closers) - 1; i >= 0; i-- {
		c := closers[i]
		chain.Add(c.Name, c.Timeout, c.Close)
	}

	// 5. Defensive zero-out of in-memory key material.
	chain.Add("zero-key-material", 1*time.Second, func(ctx context.Context) error {
		if d.LedgerSignerPriv != nil && d.LedgerSignerPriv.D != nil {
			d.LedgerSignerPriv.D.SetInt64(0)
		}
		return nil
	})

	return chain
}

// waitGroupBounded blocks until wg.Wait returns OR ctx fires. Used by
// the "background-goroutines" step so a wedged goroutine can't block
// downstream resource closes past the per-component timeout.
func waitGroupBounded(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
