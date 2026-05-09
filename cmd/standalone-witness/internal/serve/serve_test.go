// FILE PATH: cmd/standalone-witness/internal/serve/serve_test.go
//
// Unit tests for the cosign HTTP wrapper + monotonicity guard.
//
// Tests use httptest.NewRecorder + raw http.Request construction
// rather than spinning a server — the guard middleware is a pure
// transformation on (request, response writer), so a recorder
// proves the contract end-to-end without exec'ing a process.
//
// PHYSICS:
//
//   - The SDK's NewWitnessHandler is the inner handler. We do
//     not mock it — we drive a real signer and parse the real
//     wire response.
//   - The guard's lastSignedSize state lives in a closure inside
//     newMonotonicityGuard. We exercise it across multiple POSTs
//     against the SAME built handler to test the state machine.
package serve

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// testNetID returns a deterministic non-zero NetworkID. The SDK
// rejects requests under any NetworkID not in AllowedNetworks, so
// every test request must carry exactly this value.
func testNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(0x40 | (i & 0x3F))
	}
	return n
}

// testKey returns a fresh ECDSA private key suitable for
// cosign.NewECDSAWitnessSigner. Used in every test that builds a
// real handler.
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("signatures.GenerateKey: %v", err)
	}
	return priv
}

// silentLogger discards all output; tests don't need handler-level
// chatter, only request/response state.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// ─────────────────────────────────────────────────────────────────
// Build (constructor) tests
// ─────────────────────────────────────────────────────────────────

func TestBuild_RejectsNilWitnessKey(t *testing.T) {
	_, err := Build(Config{
		WitnessKey: nil,
		NetworkID:  testNetID(),
	})
	if err == nil {
		t.Fatal("Build with nil WitnessKey: expected error, got nil")
	}
}

// Note: a zero NetworkID is NOT rejected at construction time —
// the SDK's NewWitnessHandler only checks len(AllowedNetworks)>0,
// and Build wraps the NetworkID into a 1-entry map regardless of
// value. Zero-NetworkID rejections fire at request time inside
// the canonical-message preamble. See Trust Alignment 11.

func TestBuild_HappyPath(t *testing.T) {
	h, err := Build(Config{
		WitnessKey: testKey(t),
		NetworkID:  testNetID(),
		Logger:     silentLogger(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if h == nil {
		t.Fatal("Build returned (nil, nil)")
	}
}

func TestBuildSigner_RejectsNilSigner(t *testing.T) {
	_, err := BuildSigner(nil, Config{NetworkID: testNetID()})
	if err == nil {
		t.Fatal("BuildSigner with nil signer: expected error")
	}
}

// ─────────────────────────────────────────────────────────────────
// Monotonicity guard — the load-bearing tests
// ─────────────────────────────────────────────────────────────────

// postCosign drives the handler with a fresh tree-head request at
// `size` and returns the recorded response.
func postCosign(t *testing.T, h http.Handler, netID cosign.NetworkID, size uint64) *httptest.ResponseRecorder {
	t.Helper()
	body := buildTreeHeadRequestSimple(t, netID, size)
	req := httptest.NewRequest(http.MethodPost, cosign.DefaultCosignPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// buildTreeHeadRequestSimple uses the SDK's wire encoder via a
// real types.TreeHead value. The serve package itself doesn't
// import types (it only handles bytes), so we construct the
// request body directly per the wire spec.
func buildTreeHeadRequestSimple(t *testing.T, netID cosign.NetworkID, size uint64) []byte {
	t.Helper()
	root := [32]byte{0xCC, 0xDD, 0xEE, 0xFF, byte(size)}
	// WireTreeHeadPayload shape: {root_hash: hex, tree_size: int}.
	innerPayload, err := json.Marshal(struct {
		RootHash string `json:"root_hash"`
		TreeSize uint64 `json:"tree_size"`
	}{
		RootHash: hex.EncodeToString(root[:]),
		TreeSize: size,
	})
	if err != nil {
		t.Fatalf("marshal inner payload: %v", err)
	}
	body, err := json.Marshal(cosign.WireRequest{
		Purpose:   cosign.PurposeTreeHead,
		Payload:   innerPayload,
		NetworkID: cosign.NetworkIDToWire(netID),
		HashAlgo:  cosign.HashAlgoToWire(cosign.HashAlgoSHA256),
	})
	if err != nil {
		t.Fatalf("marshal WireRequest: %v", err)
	}
	return body
}

// TestMonotonicityGuard_AcceptsAscendingTreeSize: two POSTs with
// strictly ascending tree_size both succeed. Pins the happy path.
func TestMonotonicityGuard_AcceptsAscendingTreeSize(t *testing.T) {
	netID := testNetID()
	h, err := Build(Config{WitnessKey: testKey(t), NetworkID: netID, Logger: silentLogger()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	rec1 := postCosign(t, h, netID, 100)
	if rec1.Code != http.StatusOK {
		t.Fatalf("size=100: got %d (%s), want 200", rec1.Code, rec1.Body.String())
	}

	rec2 := postCosign(t, h, netID, 200)
	if rec2.Code != http.StatusOK {
		t.Fatalf("size=200: got %d (%s), want 200", rec2.Code, rec2.Body.String())
	}
}

// TestMonotonicityGuard_RejectsRollback: a POST with tree_size
// strictly LESS than the previously-signed size returns 409.
// This is the LOAD-BEARING witness-side defense against rollback.
func TestMonotonicityGuard_RejectsRollback(t *testing.T) {
	netID := testNetID()
	h, err := Build(Config{WitnessKey: testKey(t), NetworkID: netID, Logger: silentLogger()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if rec := postCosign(t, h, netID, 200); rec.Code != http.StatusOK {
		t.Fatalf("priming size=200: got %d, want 200", rec.Code)
	}

	rec := postCosign(t, h, netID, 100)
	if rec.Code != http.StatusConflict {
		t.Fatalf("rollback size=100 after 200: got %d (%s), want 409 Conflict",
			rec.Code, rec.Body.String())
	}

	// The 409 body is a WireError-shaped JSON; confirm it parses.
	var werr cosign.WireError
	if jerr := json.Unmarshal(rec.Body.Bytes(), &werr); jerr != nil {
		t.Fatalf("rollback response not WireError JSON: %v\nbody=%s",
			jerr, rec.Body.String())
	}
	if werr.Error == "" {
		t.Errorf("rollback WireError.Error is empty; expected diagnostic message")
	}
}

// TestMonotonicityGuard_AcceptsEqualTreeSize: a POST with the
// SAME tree_size as the previous successful sign succeeds. Pins
// the idempotent-retry contract — a Ledger that retries the same
// cosign request must not be locked out.
func TestMonotonicityGuard_AcceptsEqualTreeSize(t *testing.T) {
	netID := testNetID()
	h, err := Build(Config{WitnessKey: testKey(t), NetworkID: netID, Logger: silentLogger()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if rec := postCosign(t, h, netID, 50); rec.Code != http.StatusOK {
		t.Fatalf("first POST size=50: got %d", rec.Code)
	}
	if rec := postCosign(t, h, netID, 50); rec.Code != http.StatusOK {
		t.Fatalf("retry size=50: got %d (%s); idempotent retry must succeed",
			rec.Code, rec.Body.String())
	}
}

// TestMonotonicityGuard_RejectsNonPostMethod: a GET against the
// handler hits the SDK's method check and returns 405. The guard
// middleware must NOT advance state for non-POST methods.
func TestMonotonicityGuard_RejectsNonPostMethod(t *testing.T) {
	netID := testNetID()
	h, err := Build(Config{WitnessKey: testKey(t), NetworkID: netID, Logger: silentLogger()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, cosign.DefaultCosignPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: got %d (%s), want 405", rec.Code, rec.Body.String())
	}

	// State invariant: a subsequent valid POST at size=1 still
	// succeeds, proving the GET didn't pollute lastSignedSize.
	if rec := postCosign(t, h, netID, 1); rec.Code != http.StatusOK {
		t.Errorf("POST size=1 after rejected GET: got %d; "+
			"GET must not advance the guard's state", rec.Code)
	}
}

// TestMonotonicityGuard_StateAdvancesEvenOnSDKReject: per the
// guard's documented "optimistic advance" semantics, state moves
// forward as soon as the guard accepts the size, even if the
// inner SDK handler later rejects (e.g., wrong network). This
// test asserts that contract: a request with a wrong network_id
// passes the guard (which only checks size) but is rejected by
// the SDK; subsequent rollbacks at that size are no-ops.
func TestMonotonicityGuard_StateAdvancesEvenOnSDKReject(t *testing.T) {
	netID := testNetID()
	wrongNetID := cosign.NetworkID{0xFF, 0xEE}

	h, err := Build(Config{WitnessKey: testKey(t), NetworkID: netID, Logger: silentLogger()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// POST size=300 with wrong network — guard advances to 300,
	// SDK rejects with 403.
	if rec := postCosign(t, h, wrongNetID, 300); rec.Code == http.StatusOK {
		t.Fatal("wrong-network POST: expected SDK rejection (403)")
	}

	// Now rollback to 200 should be 409 (guard advanced to 300
	// despite SDK reject).
	if rec := postCosign(t, h, netID, 200); rec.Code != http.StatusConflict {
		t.Errorf("rollback to 200 after guard-advanced-to-300: got %d, want 409",
			rec.Code)
	}
}

// guardConfig captures init values; a dedicated unit test for
// newMonotonicityGuard via a fake inner handler is omitted because
// the public Build API is the only consumer and the tests above
// cover its state-machine contract end to end.
