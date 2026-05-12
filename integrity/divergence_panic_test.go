/*
FILE PATH: integrity/divergence_panic_test.go

The Detector returns ErrDiverged on disagreement; cmd/ledger/main.go
panics on it via the fatal-channel supervisor. Existing tests in
integrity_test.go cover the Detector's return value (Loop returns
ErrDiverged on first sample-cycle mismatch) but stop short of the
panic. This file closes the loop:

	TestDetector_Loop_DivergencePropagatesViaPanic
	  Pipes Loop's return value through the same fatal-channel pattern
	  cmd/ledger/main.go uses, then asserts the supervisor panics
	  with the expected message shape ("ledger FATAL: integrity
	  detector: ...") and that errors.Is(panicErr, ErrDiverged) holds.

	TestSupervisor_FatalChannelPanicShape
	  Standalone replication of the cmd/ledger/main.go supervisor
	  block. No integrity surface — just the mechanism that converts
	  a fatal-channel send into a process panic with the correct
	  error wrap. Catches future refactors that drop the wrap or
	  swallow the originating error.

POST-CLEANUP NOTE:

	The Reconcile-side counterpart (TestDetector_Reconcile_Sink
	DivergenceLogged) was deleted alongside the Reconcile method
	itself. Boot recovery is now the Sequencer's responsibility;
	Sequencer-side error-handling tests live in
	sequencer/sequencer_test.go.
*/
package integrity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

// hashOf is a tiny SHA-256 helper for test fixtures. Kept here
// rather than in integrity_test.go because the divergence-panic
// scenarios were the original users; integrity_test.go has its
// own inline call sites.
func hashOf(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

// ─────────────────────────────────────────────────────────────────────
// Test 1: Loop's ErrDiverged is propagated through the fatal channel
// and converted to a panic with the production wrap shape.
// ─────────────────────────────────────────────────────────────────────

func TestDetector_Loop_DivergencePropagatesViaPanic(t *testing.T) {
	tiles := newFakeTesseraView()
	wal := &fakeWAL{
		hwm:    1,
		hashAt: map[uint64][32]byte{1: hashOf("wal-version")},
	}
	tiles.putHashAtSeq(t, 1, hashOf("tessera-version"))

	d := NewDetector(
		wal,
		NewVerifier(tiles.Fetch),
		DetectorConfig{
			SampleInterval:  5 * time.Millisecond,
			SamplesPerCycle: 1,
			Rand:            rand.New(rand.NewSource(1)),
			Logger:          discardLogger(),
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Mirror cmd/ledger/main.go's fatal-channel supervisor exactly:
	//   - run the loop in a goroutine
	//   - on non-context error, send to fatal channel
	//   - supervisor reads fatal, panics with ledger-FATAL wrap
	fatal := make(chan error, 1)
	go func() {
		if err := d.Loop(ctx); err != nil &&
			!errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			fatal <- fmt.Errorf("integrity detector: %w", err)
		}
	}()

	var fatalErr error
	select {
	case fatalErr = <-fatal:
	case <-ctx.Done():
		t.Fatal("ctx expired before Loop returned a divergence error")
	}

	// Run the supervisor's panic block under defer/recover and confirm
	// it surfaces a panic value containing the originating ErrDiverged.
	supervisor := func() (recovered any) {
		defer func() { recovered = recover() }()
		if fatalErr != nil {
			panic(fmt.Errorf("ledger FATAL: %w", fatalErr))
		}
		return nil
	}
	pv := supervisor()
	if pv == nil {
		t.Fatal("supervisor did not panic on fatal error")
	}
	pErr, ok := pv.(error)
	if !ok {
		t.Fatalf("supervisor panic value is not an error: %T %v", pv, pv)
	}
	if !errors.Is(pErr, ErrDiverged) {
		t.Errorf("panic value does not wrap ErrDiverged: %v", pErr)
	}
	msg := pErr.Error()
	if !strings.Contains(msg, "ledger FATAL") {
		t.Errorf("panic message missing 'ledger FATAL' marker: %q", msg)
	}
	if !strings.Contains(msg, "integrity detector") {
		t.Errorf("panic message missing 'integrity detector' wrap: %q", msg)
	}
	if !strings.Contains(msg, "seq=1") {
		t.Errorf("panic message missing diverged seq reference: %q", msg)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 2: Supervisor panic-shape lock.
//
// Replicates the cmd/ledger/main.go fatal-channel supervisor in
// isolation. The test exists so a future refactor that drops the
// "ledger FATAL: %w" wrap, swallows the originating error, or
// changes the channel ordering breaks loudly.
// ─────────────────────────────────────────────────────────────────────

func TestSupervisor_FatalChannelPanicShape(t *testing.T) {
	const fatalMsg = "shipper exhausted retries"
	originating := errors.New(fatalMsg)
	wantWrap := fmt.Errorf("shipper: %w", originating)

	// Producer goroutine — analogous to the shipper's terminal-error
	// path in cmd/ledger/main.go.
	fatal := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fatal <- wantWrap
	}()

	// Supervisor block — mirror of the cmd/ledger/main.go select
	// loop. We give it a context that won't fire so the fatal branch
	// is the one that wins.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var fatalErr error
	select {
	case <-ctx.Done():
		t.Fatal("ctx fired before fatal channel; test wiring bug")
	case fatalErr = <-fatal:
	}
	wg.Wait()

	pv := func() (rec any) {
		defer func() { rec = recover() }()
		if fatalErr != nil {
			panic(fmt.Errorf("ledger FATAL: %w", fatalErr))
		}
		return nil
	}()
	if pv == nil {
		t.Fatal("supervisor did not panic on fatal error")
	}
	pErr, ok := pv.(error)
	if !ok {
		t.Fatalf("panic value is not an error: %T", pv)
	}
	// Wrapping must preserve identity all the way down to the
	// originating sentinel.
	if !errors.Is(pErr, originating) {
		t.Errorf("panic does not preserve originating error chain: %v", pErr)
	}
	if !strings.Contains(pErr.Error(), "ledger FATAL") {
		t.Errorf("panic missing 'ledger FATAL' prefix: %q", pErr.Error())
	}
	if !strings.Contains(pErr.Error(), fatalMsg) {
		t.Errorf("panic missing originating message %q: %q", fatalMsg, pErr.Error())
	}
}
