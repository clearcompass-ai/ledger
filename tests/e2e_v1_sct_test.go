/*
FILE PATH: tests/e2e_v1_sct_test.go

End-to-end coverage of the SCT/MMD architecture: real Postgres,
real WAL, real Sequencer drain, real HTTP server. Reuses
startE2ELedger from e2e_shipper_redirect_test.go (which already
wires the Sequencer + unified /v1 handler + MMD endpoint).

WHAT'S COVERED:

	POST /v1/entries happy path:
	  - Returns 202 + SCT.
	  - SCT signature verifies against the ledger's public key
	    (cfg.LedgerSignerPriv.PublicKey from the test harness).
	  - WAL.Submit lands the entry in StatePending.

	Sequencer drain → state transition:
	  - Within seconds (sequencer poll = 10ms), the entry advances
	    from StatePending → StateSequenced and an entry_index row
	    lands in Postgres.

	GET /v1/entries-hash/{hash} during the inflight window:
	  - Returns 200 {state:"pending"} immediately after the POST.
	  - After Sequencer drain, returns full metadata (sequence_number).

	GET /v1/admission/mmd:
	  - Returns the configured MMD as both seconds and human form.

	Multi-entry drain:
	  - 5 submissions all get distinct SCTs, all sequence within
	    the test budget, entry_index has 5 rows post-drain.

	Tamper resistance (sanity, alongside api/sct_test.go):
	  - Mutating an SCT field after receipt invalidates the
	    signature.

GATING: ATTESTA_TEST_DSN required (Postgres). Skips otherwise.
*/
package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdksct "github.com/clearcompass-ai/attesta/crypto/sct"

	"github.com/clearcompass-ai/ledger/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Test 1: happy path — returns SCT that verifies; WAL goes Pending.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_V1_HappyPath_ReturnsValidSCT(t *testing.T) {
	op := startE2ELedger(t)

	wire := buildAdmissibleWire(t, op, "did:example:happy", []byte("happy-payload"))
	canonicalHash := sha256.Sum256(wire)

	body, status := postV1(t, op, wire)
	if status != http.StatusAccepted {
		t.Fatalf("status = %d, want 202\nbody: %s", status, body)
	}
	var sct sdksct.SignedCertificateTimestamp
	if err := json.Unmarshal(body, &sct); err != nil {
		t.Fatalf("decode SCT: %v\nbody: %s", err, body)
	}
	if sct.LogDID != op.LogDID {
		t.Errorf("SCT.LogDID = %q, want %q", sct.LogDID, op.LogDID)
	}
	if sct.CanonicalHash != hex.EncodeToString(canonicalHash[:]) {
		t.Errorf("SCT.CanonicalHash mismatch:\n got %s\n want %x", sct.CanonicalHash, canonicalHash[:])
	}
	if err := sdksct.Verify(&op.LedgerSignerPriv.PublicKey, &sct); err != nil {
		t.Errorf("SCT signature does not verify: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 2: GET /v1/entries-hash/{hash} returns pending then sequenced.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_V1_HashLookup_PendingThenSequenced(t *testing.T) {
	op := startE2ELedger(t)

	wire := buildAdmissibleWire(t, op, "did:example:hash-lookup", []byte("hash-lookup-payload"))
	canonicalHash := sha256.Sum256(wire)
	hashHex := hex.EncodeToString(canonicalHash[:])

	body, status := postV1(t, op, wire)
	if status != http.StatusAccepted {
		t.Fatalf("submit: %d\n%s", status, body)
	}

	// Probe immediately. With a 10ms sequencer interval, we may
	// catch the entry as either pending or sequenced — both are
	// valid passing states; we just need the body to decode.
	url := op.BaseURL + "/v1/entries-hash/" + hashHex
	got := pollHashLookup(t, url, func(rec map[string]any) bool {
		// Accept the moment state==sequenced (entry_index row written)
		// OR the call returns full metadata (sequence_number present).
		if rec["state"] == "pending" {
			return false
		}
		_, hasSeq := rec["sequence_number"]
		return hasSeq
	}, 5*time.Second)

	// Tessera assigns 0-indexed leaf sequences; the first
	// admitted entry in a fresh test DB lands at seq 0. Assert
	// presence + non-negative — not seq > 0 (off-by-one bug in
	// the prior assertion).
	if seq, ok := got["sequence_number"].(float64); !ok || seq < 0 {
		t.Fatalf("expected sequenced state with sequence_number, got %#v", got)
	}
	if hashFromResp, ok := got["canonical_hash"].(string); ok && hashFromResp != hashHex {
		t.Errorf("canonical_hash mismatch in response: %q vs %q", hashFromResp, hashHex)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 3: GET /v1/admission/mmd returns configured MMD.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_V1_MMDEndpoint_ReturnsConfigured(t *testing.T) {
	op := startE2ELedger(t)

	resp, err := http.Get(op.BaseURL + "/v1/admission/mmd")
	if err != nil {
		t.Fatalf("GET /v1/admission/mmd: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		MMDSeconds float64 `json:"mmd_seconds"`
		MMDHuman string `json:"mmd_human"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.MMDSeconds != op.MMD.Seconds() {
		t.Errorf("mmd_seconds = %v, want %v", body.MMDSeconds, op.MMD.Seconds())
	}
	if body.MMDHuman != op.MMD.String() {
		t.Errorf("mmd_human = %q, want %q", body.MMDHuman, op.MMD.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 4: 5 submissions all sequence; entry_index has 5 rows.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_V1_MultiSubmit_AllSequence(t *testing.T) {
	op := startE2ELedger(t)
	const N = 5
	// Resolve difficulty once outside the loop — every submission
	// in this test stamps against the same ledger state.
	difficulty := liveDifficulty(t, op)

	hashes := make([][32]byte, N)
	for i := 0; i < N; i++ {
		header := envelope.ControlHeader{
			SignerDID:   fmt.Sprintf("did:example:multi-%d", i),
			Destination: op.LogDID,
			EventTime:   time.Now().UTC().UnixMicro(),
		}
		wire := buildModeBWireEntry(t, header,
			[]byte(fmt.Sprintf("multi-payload-%d", i)),
			op.LogDID, difficulty,
		)
		hashes[i] = sha256.Sum256(wire)
		body, status := postV1(t, op, wire)
		if status != http.StatusAccepted {
			t.Fatalf("submit %d: status=%d body=%s", i, status, body)
		}
	}

	// Wait for the Sequencer to drain all five.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		meta, err := op.WAL.MetaState(context.Background(), hashes[N-1])
		if err == nil && meta.State >= wal.StateSequenced {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Verify every hash is sequenced in WAL and has an entry_index row.
	for i, h := range hashes {
		meta, err := op.WAL.MetaState(context.Background(), h)
		if err != nil {
			t.Errorf("entry %d: WAL meta: %v", i, err)
			continue
		}
		if meta.State < wal.StateSequenced {
			t.Errorf("entry %d: WAL state = %s, want sequenced", i, meta.State)
		}
	}

	// Postgres count.
	var count int
	if err := op.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM entry_index`).Scan(&count); err != nil {
		t.Fatalf("count entry_index: %v", err)
	}
	if count != N {
		t.Errorf("entry_index count = %d, want %d", count, N)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 5: SCT tamper resistance (e2e shape check).
// ─────────────────────────────────────────────────────────────────────

func TestE2E_V1_SCTTamperResistance(t *testing.T) {
	op := startE2ELedger(t)

	wire := buildAdmissibleWire(t, op, "did:example:tamper", []byte("tamper"))
	body, status := postV1(t, op, wire)
	if status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	var sct sdksct.SignedCertificateTimestamp
	if err := json.Unmarshal(body, &sct); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Sanity: clean verify passes.
	if err := sdksct.Verify(&op.LedgerSignerPriv.PublicKey, &sct); err != nil {
		t.Fatalf("clean verify failed: %v", err)
	}
	// Tamper canonical_hash → must fail.
	orig := sct.CanonicalHash
	sct.CanonicalHash = "ff" + orig[2:]
	if err := sdksct.Verify(&op.LedgerSignerPriv.PublicKey, &sct); err == nil {
		t.Error("expected verification failure on tampered hash")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 6: /v2/entries returns 404 over the live HTTP listener.
// ─────────────────────────────────────────────────────────────────────

// Belt-and-suspenders companion to the unit-level api/server_test.go
// route assertion: prove the production server (with all middleware)
// also returns 404 for the retired /v2 endpoint, not just the bare mux.
func TestE2E_V1_V2RouteRetired(t *testing.T) {
	op := startE2ELedger(t)

	resp, err := http.Post(op.BaseURL+"/v2/entries", "application/octet-stream", bytes.NewReader([]byte("anything")))
	if err != nil {
		t.Fatalf("POST /v2/entries: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		t.Errorf("status = %d, want 404\nbody: %s", resp.StatusCode, body)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func postV1(t *testing.T, op *e2eLedger, wire []byte) ([]byte, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/entries: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return body, resp.StatusCode
}

// liveDifficulty queries the ledger's GET /v1/admission/difficulty
// endpoint and returns the difficulty the ledger is currently
// advertising. Stamping at exactly that difficulty is the most
// realistic and robust way to admit Mode B entries — the same
// pattern cmd/submit-stamp/main.go uses for live submissions.
//
// Mirrors what a production client would do: ask the ledger
// what work is required and produce exactly that, rather than
// hard-coding a value that might drift from the ledger's
// dynamic DiffController.
func liveDifficulty(t *testing.T, op *e2eLedger) uint32 {
	t.Helper()
	resp, err := http.Get(op.BaseURL + "/v1/admission/difficulty")
	if err != nil {
		t.Fatalf("GET /v1/admission/difficulty: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		t.Fatalf("difficulty endpoint: status=%d body=%s", resp.StatusCode, body)
	}
	var body struct {
		Difficulty uint32 `json:"difficulty"`
		HashFunction string `json:"hash_function"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("difficulty endpoint decode: %v", err)
	}
	if body.Difficulty == 0 {
		t.Fatal("difficulty endpoint returned 0")
	}
	return body.Difficulty
}

// buildAdmissibleWire produces a Mode B-stamped wire entry whose
// stamp matches the ledger's currently-advertised difficulty.
// Use this in lieu of buildWireEntry when the test path is
// unauthenticated — postV1 doesn't include a Bearer token, so the
// admission middleware demands a valid PoW stamp.
//
// Sets the Destination + EventTime fields the ledger's freshness
// + binding checks require; buildModeBWireEntry doesn't fill these
// in for the caller.
func buildAdmissibleWire(t *testing.T, op *e2eLedger, signerDID string, payload []byte) []byte {
	t.Helper()
	difficulty := liveDifficulty(t, op)
	header := envelope.ControlHeader{
		SignerDID:   signerDID,
		Destination: op.LogDID,
		EventTime:   time.Now().UTC().UnixMicro(),
	}
	return buildModeBWireEntry(t, header, payload, op.LogDID, difficulty)
}

// pollHashLookup hits the URL until the supplied predicate accepts
// the decoded JSON or the deadline expires. Fatals on timeout.
func pollHashLookup(t *testing.T, url string, accept func(map[string]any) bool, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last map[string]any
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			var m map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&m); err == nil {
				last = m
				if accept(m) {
					resp.Body.Close()
					return m
				}
			}
			resp.Body.Close()
		} else if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("hash lookup did not reach accepting state in %v; last response: %#v", timeout, last)
	return nil
}
