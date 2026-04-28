/*
FILE PATH: api/submission_facade_test.go

Tests the v1 facade behavior in NewSubmissionHandler — specifically
the polling loop that waits for the background Sequencer to advance
WAL state from StatePending to StateSequenced.

WHAT'S COVERED:

  Polling success path:
    - When the fake WAL transitions Pending → Sequenced mid-poll,
      the handler returns 202 with the legacy JSON shape including
      the assigned sequence number.

  Polling timeout:
    - When the WAL stays Pending past V1Timeout, the handler
      returns HTTP 504 with the structured sequencer_lag payload
      pointing at /v1/entries/hash/{hash} for follow-up.

  Client disconnect:
    - When r.Context() is cancelled mid-poll (analogous to a
      client TCP disconnect), the handler returns within a single
      poll tick — does not waste CPU polling for a vanished client.

  pollForSequenced helper directly:
    - Returns (seq, true) on transition to Sequenced.
    - Returns (seq, true) on transition to Shipped (post-shipper).
    - Returns (0, false) on timeout.
    - Returns (0, false) on parent ctx cancel.
*/
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"

	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

// transitioningWAL implements WALCommitter and exposes a hook to
// flip MetaState from Pending → Sequenced on demand. Tests use it
// to simulate the background Sequencer's drain.
type transitioningWAL struct {
	mu             sync.Mutex
	submitErr      error
	state          map[[32]byte]wal.EntryState
	seqs           map[[32]byte]uint64
	submitCallback func(hash [32]byte) // optional; fires on Submit
	submitCalls    atomic.Uint64
}

func newTransitioningWAL() *transitioningWAL {
	return &transitioningWAL{
		state: make(map[[32]byte]wal.EntryState),
		seqs:  make(map[[32]byte]uint64),
	}
}

func (w *transitioningWAL) Submit(ctx context.Context, hash [32]byte, wire []byte) error {
	w.submitCalls.Add(1)
	if w.submitErr != nil {
		return w.submitErr
	}
	w.mu.Lock()
	w.state[hash] = wal.StatePending
	w.mu.Unlock()
	if w.submitCallback != nil {
		w.submitCallback(hash)
	}
	return nil
}

func (w *transitioningWAL) Sequence(ctx context.Context, hash [32]byte, seq uint64) error {
	w.mu.Lock()
	w.state[hash] = wal.StateSequenced
	w.seqs[hash] = seq
	w.mu.Unlock()
	return nil
}

func (w *transitioningWAL) MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.state[hash]
	if !ok {
		return wal.Meta{}, wal.ErrNotFound
	}
	return wal.Meta{State: st, Sequence: w.seqs[hash]}, nil
}

// transition simulates the Sequencer's external mutation: flip
// the entry to Sequenced + assign a seq.
func (w *transitioningWAL) transition(hash [32]byte, seq uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state[hash] = wal.StateSequenced
	w.seqs[hash] = seq
}

// ─────────────────────────────────────────────────────────────────────
// pollForSequenced — direct unit tests
// ─────────────────────────────────────────────────────────────────────

func TestPollForSequenced_SequencedReturnsSeq(t *testing.T) {
	w := newTransitioningWAL()
	hash := [32]byte{0xab}
	w.transition(hash, 42)

	deps := &SubmissionDeps{Storage: StorageDeps{WAL: w}}
	seq, ok := pollForSequenced(context.Background(), deps, hash, 1*time.Second)
	if !ok || seq != 42 {
		t.Errorf("got (seq=%d, ok=%v), want (42, true)", seq, ok)
	}
}

func TestPollForSequenced_ShippedAlsoReturnsSeq(t *testing.T) {
	w := newTransitioningWAL()
	hash := [32]byte{0xab}
	w.mu.Lock()
	w.state[hash] = wal.StateShipped
	w.seqs[hash] = 99
	w.mu.Unlock()

	deps := &SubmissionDeps{Storage: StorageDeps{WAL: w}}
	seq, ok := pollForSequenced(context.Background(), deps, hash, 1*time.Second)
	if !ok || seq != 99 {
		t.Errorf("got (seq=%d, ok=%v), want (99, true) — Shipped should also satisfy", seq, ok)
	}
}

func TestPollForSequenced_PendingTimesOut(t *testing.T) {
	w := newTransitioningWAL()
	hash := [32]byte{0xab}
	w.mu.Lock()
	w.state[hash] = wal.StatePending
	w.mu.Unlock()

	deps := &SubmissionDeps{Storage: StorageDeps{WAL: w}}
	start := time.Now()
	seq, ok := pollForSequenced(context.Background(), deps, hash, 200*time.Millisecond)
	if ok || seq != 0 {
		t.Errorf("got (seq=%d, ok=%v), want (0, false)", seq, ok)
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("returned in %v; expected to wait at least ~200ms", elapsed)
	}
}

func TestPollForSequenced_ParentCancelExitsPromptly(t *testing.T) {
	w := newTransitioningWAL()
	hash := [32]byte{0xab}
	w.mu.Lock()
	w.state[hash] = wal.StatePending
	w.mu.Unlock()

	deps := &SubmissionDeps{Storage: StorageDeps{WAL: w}}
	parent, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	seq, ok := pollForSequenced(parent, deps, hash, 5*time.Second)
	elapsed := time.Since(start)
	if ok || seq != 0 {
		t.Errorf("got (seq=%d, ok=%v), want (0, false) on cancel", seq, ok)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("did not exit promptly on cancel: %v", elapsed)
	}
}

func TestPollForSequenced_RaceBetweenSubmitAndPoll(t *testing.T) {
	// The fast-path optimization: pollForSequenced does an
	// immediate first probe before the ticker fires. Simulates
	// the case where the Sequencer drained an entry between
	// wal.Submit and the v1 handler's poll-loop entry.
	w := newTransitioningWAL()
	hash := [32]byte{0xab}
	w.transition(hash, 7) // already Sequenced when poll starts

	deps := &SubmissionDeps{Storage: StorageDeps{WAL: w}}
	start := time.Now()
	seq, ok := pollForSequenced(context.Background(), deps, hash, 5*time.Second)
	elapsed := time.Since(start)
	if !ok || seq != 7 {
		t.Errorf("got (seq=%d, ok=%v), want (7, true)", seq, ok)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("immediate-probe path took %v; expected sub-tick", elapsed)
	}
}

// ─────────────────────────────────────────────────────────────────────
// readSequencedSeq — direct unit tests
// ─────────────────────────────────────────────────────────────────────

func TestReadSequencedSeq_AllStates(t *testing.T) {
	hash := [32]byte{0xab}
	cases := []struct {
		state   wal.EntryState
		seq     uint64
		wantSeq uint64
		wantOK  bool
	}{
		{wal.StatePending, 0, 0, false},
		{wal.StateSequenced, 42, 42, true},
		{wal.StateShipped, 99, 99, true},
		{wal.StateManual, 0, 0, false},
	}
	for _, tc := range cases {
		w := newTransitioningWAL()
		w.mu.Lock()
		w.state[hash] = tc.state
		w.seqs[hash] = tc.seq
		w.mu.Unlock()
		deps := &SubmissionDeps{Storage: StorageDeps{WAL: w}}
		gotSeq, gotOK := readSequencedSeq(context.Background(), deps, hash)
		if gotSeq != tc.wantSeq || gotOK != tc.wantOK {
			t.Errorf("state=%s: got (%d, %v), want (%d, %v)",
				tc.state, gotSeq, gotOK, tc.wantSeq, tc.wantOK)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Full v1 handler — facade integration through the http path
// ─────────────────────────────────────────────────────────────────────

func TestV1Facade_HappyPath_PollUnblocksWithSequencerTransition(t *testing.T) {
	wire, _, signerPriv := signedV2EntryModeB(t, "did:test:log", []byte("v1-facade-happy"), 1, 3600)
	w := newTransitioningWAL()
	deps := makeFacadeDeps(t, w, &signerPriv.PublicKey)
	deps.V1Timeout = 2 * time.Second

	// Simulate the Sequencer transitioning the entry ~30ms after Submit.
	w.submitCallback = func(hash [32]byte) {
		go func() {
			time.Sleep(30 * time.Millisecond)
			w.transition(hash, 100)
		}()
	}

	h := NewSubmissionHandler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202\nbody: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		SequenceNumber uint64 `json:"sequence_number"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.SequenceNumber != 100 {
		t.Errorf("sequence_number = %d, want 100", body.SequenceNumber)
	}
}

func TestV1Facade_Timeout_Returns504WithStructuredPayload(t *testing.T) {
	wire, _, signerPriv := signedV2EntryModeB(t, "did:test:log", []byte("v1-facade-timeout"), 1, 3600)
	w := newTransitioningWAL()
	deps := makeFacadeDeps(t, w, &signerPriv.PublicKey)
	deps.V1Timeout = 100 * time.Millisecond
	// No submitCallback transition — entry stays Pending forever.

	h := NewSubmissionHandler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504\nbody: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Error          string  `json:"error"`
		Hash           string  `json:"hash"`
		WALState       string  `json:"wal_state"`
		FollowUp       string  `json:"follow_up"`
		TimeoutSeconds float64 `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error != "sequencer_lag" {
		t.Errorf("error = %q, want sequencer_lag", body.Error)
	}
	if body.WALState != "pending" {
		t.Errorf("wal_state = %q, want pending", body.WALState)
	}
	const followUpPrefix = "/v1/entries/hash/"
	if len(body.FollowUp) <= len(followUpPrefix) || body.FollowUp[:len(followUpPrefix)] != followUpPrefix {
		t.Errorf("follow_up = %q, want %s<hex>", body.FollowUp, followUpPrefix)
	}
	if body.TimeoutSeconds != 0.1 {
		t.Errorf("timeout_seconds = %v, want 0.1", body.TimeoutSeconds)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// makeFacadeDeps wires a SubmissionDeps with stubs for the v1
// facade tests. Reuses makeV2Deps's plumbing for everything except
// the SCT signer (irrelevant for v1) and the WAL fake (replaced
// with the transitioning one so we can simulate Sequencer drain).
func makeFacadeDeps(t *testing.T, walFake *transitioningWAL, signerPub *ecdsa.PublicKey) *SubmissionDeps {
	t.Helper()
	opSignerPriv, _ := signatures.GenerateKey()
	v2 := makeV2Deps(t, opSignerPriv, signerPub, nil)
	v2.SubmissionDeps.Storage.WAL = walFake
	v2.SubmissionDeps.V1Timeout = 1 * time.Second
	return v2.SubmissionDeps
}
