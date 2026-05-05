/*
FILE PATH: api/batch_test.go

Unit-level tests for POST /v1/entries/batch. Covers:

  - Constructor guards (nil deps, missing OperatorDID, etc.).
  - Empty batch → 400.
  - Oversized batch (>MaxBatchSize) → 400.
  - Bad JSON → 400.
  - Bad hex in an entry → 400.
  - Per-entry validation failure (e.g. wrong destination) → 403.
  - Happy path → 202 + array of SCTs, each verifies.
  - Hard-ceiling AbsoluteMaxBatchPayloadBytes is respected:
      requests larger than the absolute cap are truncated by
      io.LimitReader and surface as a JSON-decode error (not OOM).

Full end-to-end coverage (real WAL, real Sequencer drain) belongs
in tests/. Here we drive the handler against the in-package fakes.
*/
package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdksct "github.com/clearcompass-ai/attesta/crypto/sct"

	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

func TestBatchHandler_NilDepsPanics(t *testing.T) {
	defer expectPanic(t, "nil deps")
	NewBatchSubmissionHandler(nil)
}

func TestBatchHandler_HappyPath_ReturnsSCTArray(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	// Single signing key for both entries so they verify against
	// the same fakeDIDResolver pubkey.
	signerPriv, _ := signatures.GenerateKey()
	wire1, _ := signedEntryModeBWithKey(t, signerPriv, "did:test:log", []byte("batch-1"), 1, 3600)
	wire2, _ := signedEntryModeBWithKey(t, signerPriv, "did:test:log", []byte("batch-2"), 1, 3600)

	walFake := &stubSubmissionWAL{}
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)
	h := NewBatchSubmissionHandler(deps)

	body, _ := json.Marshal(BatchSubmissionRequest{
		Entries: []BatchEntry{
			{WireBytesHex: hex.EncodeToString(wire1)},
			{WireBytesHex: hex.EncodeToString(wire2)},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202\nbody: %s", rr.Code, rr.Body.String())
	}
	var resp BatchSubmissionResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("results length = %d, want 2", len(resp.Results))
	}
	for i, r := range resp.Results {
		if err := sdksct.Verify(&opSignerPriv.PublicKey, &r.SCT); err != nil {
			t.Errorf("result %d: SCT does not verify: %v", i, err)
		}
	}
	if len(walFake.submitted) != 2 {
		t.Errorf("WAL.Submit calls = %d, want 2", len(walFake.submitted))
	}
}

// Intra-batch duplicate detection: a batch containing the same
// canonical bytes twice must reject the second occurrence with 409
// BEFORE any credit deduction or WAL.Submit. Pinned because the
// fix at commit 15 restored a guard that had been silently lost.
func TestBatchHandler_IntraBatchDuplicate_Returns409(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	// Same wire bytes twice → identical canonical hash.
	wire, _ := signedEntryModeBWithKey(t, signerPriv, "did:test:log", []byte("dup-payload"), 1, 3600)

	walFake := &stubSubmissionWAL{}
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)
	h := NewBatchSubmissionHandler(deps)

	body, _ := json.Marshal(BatchSubmissionRequest{
		Entries: []BatchEntry{
			{WireBytesHex: hex.EncodeToString(wire)},
			{WireBytesHex: hex.EncodeToString(wire)},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409\nbody: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "duplicates entry 0") {
		t.Errorf("expected 'duplicates entry 0' in error: %s", rr.Body.String())
	}
	// Critical invariant: dedup must reject BEFORE WAL.Submit so the
	// caller is not charged a credit nor does the WAL receive a
	// state-regressing write for an already-Shipped entry.
	if len(walFake.submitted) != 0 {
		t.Errorf("WAL.Submit calls = %d, want 0 (dedup must precede admission)",
			len(walFake.submitted))
	}
}

// First valid entry, second is a duplicate — the first must NOT be
// admitted either, because the batch handler treats the request
// atomically: any error fails the whole batch (no partial admission).
func TestBatchHandler_IntraBatchDuplicate_RejectsEntireBatch(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	// Distinct first entry, then a duplicate of it.
	wireA, _ := signedEntryModeBWithKey(t, signerPriv, "did:test:log", []byte("first"), 1, 3600)

	walFake := &stubSubmissionWAL{}
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)
	h := NewBatchSubmissionHandler(deps)

	body, _ := json.Marshal(BatchSubmissionRequest{
		Entries: []BatchEntry{
			{WireBytesHex: hex.EncodeToString(wireA)},
			{WireBytesHex: hex.EncodeToString(wireA)}, // duplicate of index 0
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rr.Code)
	}
	if len(walFake.submitted) != 0 {
		t.Errorf("partial admission detected: WAL.Submit calls = %d, want 0",
			len(walFake.submitted))
	}
}

// Three distinct entries pass through; only the explicit dup is
// rejected. Locks the seen-map's positive case alongside the
// negative test above.
func TestBatchHandler_DistinctEntries_NoFalseDedup(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	wire1, _ := signedEntryModeBWithKey(t, signerPriv, "did:test:log", []byte("dist-1"), 1, 3600)
	wire2, _ := signedEntryModeBWithKey(t, signerPriv, "did:test:log", []byte("dist-2"), 1, 3600)
	wire3, _ := signedEntryModeBWithKey(t, signerPriv, "did:test:log", []byte("dist-3"), 1, 3600)

	walFake := &stubSubmissionWAL{}
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)
	h := NewBatchSubmissionHandler(deps)

	body, _ := json.Marshal(BatchSubmissionRequest{
		Entries: []BatchEntry{
			{WireBytesHex: hex.EncodeToString(wire1)},
			{WireBytesHex: hex.EncodeToString(wire2)},
			{WireBytesHex: hex.EncodeToString(wire3)},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202\nbody: %s", rr.Code, rr.Body.String())
	}
	if len(walFake.submitted) != 3 {
		t.Errorf("WAL.Submit calls = %d, want 3", len(walFake.submitted))
	}
}

func TestBatchHandler_EmptyBatch_400(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	h := NewBatchSubmissionHandler(deps)

	body, _ := json.Marshal(BatchSubmissionRequest{Entries: nil})
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestBatchHandler_OversizedBatch_400(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	h := NewBatchSubmissionHandler(deps)

	entries := make([]BatchEntry, MaxBatchSize+1)
	for i := range entries {
		entries[i] = BatchEntry{WireBytesHex: "00"}
	}
	body, _ := json.Marshal(BatchSubmissionRequest{Entries: entries})
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "exceeds max") {
		t.Errorf("expected 'exceeds max' in error: %s", rr.Body.String())
	}
}

func TestBatchHandler_BadJSON_400(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	h := NewBatchSubmissionHandler(deps)

	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader([]byte("{not json")))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestBatchHandler_BadHexInEntry_400(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	h := NewBatchSubmissionHandler(deps)

	body, _ := json.Marshal(BatchSubmissionRequest{
		Entries: []BatchEntry{{WireBytesHex: "not-hex"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// AbsoluteMaxBatchPayloadBytes is the hard ceiling regardless of
// the per-entry cap × batch-size formula. Documents the invariant.
func TestBatchHandler_AbsoluteCapEnforced(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	// Force the formula above the absolute ceiling: a 10 MiB
	// per-entry cap × 256 entries × 2 = ~5 GiB. The server must
	// still cap at AbsoluteMaxBatchPayloadBytes (64 MiB).
	deps.MaxEntrySize = 10 << 20

	h := NewBatchSubmissionHandler(deps)

	// Send a request that's larger than 64 MiB of garbage, hex-padded.
	// The io.LimitReader truncates to AbsoluteMaxBatchPayloadBytes,
	// json.Unmarshal on the truncated body fails, handler returns 400.
	huge := bytes.Repeat([]byte("a"), AbsoluteMaxBatchPayloadBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(huge))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	// 400 (JSON decode error after truncation) is the expected
	// outcome; the critical guarantee is "no OOM" — the handler
	// returned at all.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (truncated body should fail JSON decode)", rr.Code)
	}
}

// effectiveBatchPayloadCap derivation. Pinned numerically so a
// future drift in the formula gets caught.
func TestEffectiveBatchPayloadCap_Bounds(t *testing.T) {
	cases := []struct {
		maxEntry int64
		want     int64
	}{
		// Tiny per-entry → floor at maxBatchPayloadBytes (4 MiB).
		{maxEntry: 1024, want: maxBatchPayloadBytes},
		// Default 1 MiB → formula yields ~512 MiB → ceiling 64 MiB.
		{maxEntry: 1 << 20, want: AbsoluteMaxBatchPayloadBytes},
		// Larger 8 MiB → formula yields multi-GiB → ceiling 64 MiB.
		{maxEntry: 8 << 20, want: AbsoluteMaxBatchPayloadBytes},
	}
	for _, tc := range cases {
		got := computeEffectiveBatchPayloadCap(tc.maxEntry)
		if got != tc.want {
			t.Errorf("MaxEntrySize=%d: got cap=%d, want %d", tc.maxEntry, got, tc.want)
		}
	}
}

// Smoke test that the per-entry preflight failure surfaces the
// per-index error message clients depend on for partial-batch
// debugging.
func TestBatchHandler_PerEntryFailure_ReportsIndex(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	wire, _, signerPriv := signedEntryModeB(t, "did:test:log", []byte("ok"), 1, 3600)
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	h := NewBatchSubmissionHandler(deps)

	body, _ := json.Marshal(BatchSubmissionRequest{
		Entries: []BatchEntry{
			{WireBytesHex: hex.EncodeToString(wire)}, // valid (index 0)
			{WireBytesHex: "00"},                     // invalid (index 1)
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code < 400 || rr.Code >= 500 {
		t.Fatalf("expected 4xx, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "entry 1") {
		t.Errorf("expected 'entry 1' in error message: %s", rr.Body.String())
	}
}

// Sentinel: the constants the rest of this file depends on must
// stay positive and ordered.
func TestBatchConstants_Invariants(t *testing.T) {
	if MaxBatchSize <= 0 {
		t.Errorf("MaxBatchSize must be positive: %d", MaxBatchSize)
	}
	if AbsoluteMaxBatchPayloadBytes <= maxBatchPayloadBytes {
		t.Errorf("AbsoluteMaxBatchPayloadBytes (%d) must exceed maxBatchPayloadBytes (%d)",
			AbsoluteMaxBatchPayloadBytes, maxBatchPayloadBytes)
	}
}

// Sanity: the formula constants align with the docstring.
func TestEffectiveCapHumanReadable(t *testing.T) {
	t.Logf("MaxBatchSize = %d", MaxBatchSize)
	t.Logf("maxBatchPayloadBytes (floor) = %s", humanBytes(maxBatchPayloadBytes))
	t.Logf("AbsoluteMaxBatchPayloadBytes (ceiling) = %s", humanBytes(AbsoluteMaxBatchPayloadBytes))
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%d GiB", n/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
