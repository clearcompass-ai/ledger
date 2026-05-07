/*
FILE PATH: tests/http_integration_test.go

HTTP integration tests. Every test makes real HTTP calls to a real ledger
server backed by real Postgres. No interface mocks.

POST-WAVE-1.5 CHANGES:
  - Wire format is protocol v5. Preamble bytes updated.
  - header.AdmissionProof now points to *envelope.AdmissionProofBody (wire
    type), not *types.AdmissionProof (API type).
  - Mode B verification uses ProofFromWire adapter.
  - VerifyStamp takes 8 args including currentEpoch + acceptanceWindow.

VET-COMPLIANCE NOTE:

	Every http.Get / http.Client.Do call checks err before defer resp.Body.Close().
	If a request errors, resp is nil and a deferred Close would panic — `go vet`
	catches this with the "using resp before checking for errors" diagnostic.
	All such call sites route through doRequest / httpGet helpers.

Run: ATTESTA_TEST_DSN="postgres://..." go test ./tests/ -v -count=1 -run TestHTTP
*/
package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/admission"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// Wire format constants
//
// Pre-v0.1.1 of the SDK, these were local guesses (Mode B was wrongly assumed
// to be wire byte 2 because of "0=absent, 1=ModeA, 2=ModeB" framing). The SDK
// now exports the canonical values via types.WireByteModeB and
// admission.WireByteHashSHA256, with a regression test that locks the
// encoding. Use those directly at construction sites; no local re-aliasing.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Wire format helpers
// ─────────────────────────────────────────────────────────────────────────────

// buildWireEntry creates a entry signed with the shared test
// keypair. Used for Mode A (authenticated) submissions where the
// compute stamp isn't needed. Under the multi-sig section is
// appended INSIDE envelope.Serialize, so the wire bytes ARE the
// canonical bytes — no separate MustAppendSignature step.
//
// The test server is configured with DIDResolver: nil (wire-format-
// integrity-only mode) per testserver_test.go:166, so the signature is not crypto-
// verified end-to-end; we just need it to be structurally well-formed
// so envelope.Serialize / Deserialize round-trip cleanly. makeEntry
// gives us exactly that. The ledger now wires
// did.NewECDSAKeyResolver (SDK), so signatures are verified
// cryptographically against the resolved public key — we route
// through makeAdmissibleEntry which translates synthetic
// 'did:example:alice' labels to deterministic did:key:z...
// identifiers and signs with the matching keypair.
func buildWireEntry(t *testing.T, header envelope.ControlHeader, payload []byte) []byte {
	t.Helper()
	return mustSerialize(makeAdmissibleEntry(t, header, payload))
}

// buildModeBWireEntry creates a v5 entry with a valid compute stamp for Mode B.
// Brute-forces the nonce so that the stamp verifies against the canonical hash
// using the post-Wave-1.5 admission API (StampParams + 8-arg VerifyStamp).
//
// At difficulty 16 with SHA-256 this typically takes ~65ms.
//
// IMPORTANT: header.AdmissionProof is *envelope.AdmissionProofBody (the wire
// format type), NOT *types.AdmissionProof (the API form). The two types are
// deliberately distinct — wire format omits TargetLog (implicit) and includes
// Hash; API form has TargetLog and omits Hash. The ledger translates between
// them via admission.ProofFromWire.
func buildModeBWireEntry(t *testing.T, header envelope.ControlHeader, payload []byte, logDID string, difficulty uint32) []byte {
	t.Helper()

	// Use the test epoch so the ledger (which computes the same epoch
	// via currentTestEpoch math) accepts our stamp. If we used time.Now
	// directly, a tick across the hour boundary could cause flaky failures.
	stampEpoch := currentTestEpoch()

	// Wire-format type. Ledger deserializes this from entry header bytes.
	// Wire bytes come from the SDK's exported aliases (v0.1.1+) — locked
	// against typed-constant drift by wire_encoding_test.go in the SDK.
	header.AdmissionProof = &envelope.AdmissionProofBody{
		Mode:       types.WireByteModeB,
		Difficulty: uint8(difficulty),
		HashFunc:   admission.WireByteHashSHA256,
		Epoch:      stampEpoch,
		Nonce:      0, // updated each iteration
	}

	//  chicken-and-egg: the stamp target is
	// envelope.EntryIdentity = sha256(Serialize(entry)), and Serialize
	// embeds the signatures section. So changing the nonce changes
	// SigningPayload changes the signature changes Serialize output.
	// We sign on every iteration. ECDSA SignEntry over a 32-byte hash
	// is ~50µs; at difficulty=8 the search expects ~256 iterations,
	// well within the test budget.
	//
	// Resolve the SignerDID label once before the loop so the same
	// keypair is used across iterations and admission verifies the
	// signature against the matching did:key.
	signer := resolveSyntheticSigner(header.SignerDID)
	header.SignerDID = signer.did
	for nonce := uint64(0); nonce < 20_000_000; nonce++ {
		header.AdmissionProof.Nonce = nonce
		entry, err := envelope.NewUnsignedEntry(header, payload)
		if err != nil {
			t.Fatalf("NewUnsignedEntry: %v", err)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(entry))
		sig, err := signatures.SignEntry(signingHash, signer.priv)
		if err != nil {
			t.Fatalf("SignEntry: %v", err)
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: signer.did,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		}}
		// Skip entry.Validate inside the hot loop — it re-runs the
		// signing-section encode that Serialize is about to do. We'll
		// be returning Serialize's output anyway, so any structural
		// rejection will surface there with the same panic message.
		canonical := mustSerialize(entry)
		entryHash := sha256.Sum256(canonical)

		// Translate wire→API for verification (same path the ledger
		// takes at request handling time).
		apiProof := admission.ProofFromWire(header.AdmissionProof, logDID)

		err = admission.VerifyStamp(
			apiProof,
			entryHash,
			logDID,
			difficulty,
			admission.HashSHA256,
			nil, // Argon2idParams not needed for SHA-256
			currentTestEpoch(),
			uint64(testEpochAcceptanceWindow),
		)
		if err == nil {
			// canonical is already the wire bytes — no separate
			// signature-append step under .
			return canonical
		}
	}
	t.Fatal("could not find valid nonce within 20M iterations")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helpers (vet-compliant: always check err before defer)
// ─────────────────────────────────────────────────────────────────────────────

// doRequest is the safe replacement for `resp, _ := http.X(...); defer resp.Body.Close()`.
// It performs the request, fails the test on transport error, and returns the
// response with the caller responsible for Close. Centralizing this pattern
// keeps the per-test code short and prevents future vet regressions.
func doRequest(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP %s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

// httpGet is the safe replacement for `resp, _ := http.Get(url); defer resp.Body.Close()`.
func httpGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // tests are short-lived
	if err != nil {
		t.Fatalf("HTTP GET %s: %v", url, err)
	}
	return resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Poll helper — replaces flaky time.Sleep
// ─────────────────────────────────────────────────────────────────────────────

// pollQueryResults polls GET /v1/query/signer_did/{did} until expectedCount
// results arrive or timeout. Returns the parsed results.
func pollQueryResults(t *testing.T, baseURL, signerDID string, expectedCount int, timeout time.Duration) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	queryURL := fmt.Sprintf("%s/v1/query/signer_did/%s", baseURL, signerDID)

	for time.Now().Before(deadline) {
		resp, err := http.Get(queryURL) //nolint:noctx
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var results []map[string]any
		json.NewDecoder(resp.Body).Decode(&results)
		resp.Body.Close()

		if len(results) >= expectedCount {
			return results
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d results from signer %s (waited %s)", expectedCount, signerDID, timeout)
	return nil
}

// submitEntry POSTs a wire entry with auth, waits for sequencing,
// and returns a map with the SCT fields plus sequence_number,
// canonical_hash, and log_time pulled from /v1/entries-hash/{hash}
// once the Sequencer has drained.
//
// Returning the merged shape preserves the legacy
// {sequence_number, canonical_hash, log_time, signer_did}
// expectations that pre-SCT integration tests depend on, while
// honoring the new asynchronous /v1 contract.
//
// Fails the test if status != 202 or if sequencing doesn't
// complete inside the polling budget.
func submitEntry(t *testing.T, baseURL, token string, wire []byte) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("POST", baseURL+"/v1/entries", bytes.NewReader(wire))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp := doRequest(t, req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", resp.StatusCode, body)
	}
	var sct map[string]any
	if err := json.Unmarshal(body, &sct); err != nil {
		t.Fatalf("decode SCT: %v\nbody: %s", err, body)
	}
	hashHex, _ := sct["canonical_hash"].(string)
	if hashHex == "" {
		t.Fatalf("SCT missing canonical_hash: %s", body)
	}

	// Poll the hash-lookup endpoint until Sequencer drains.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		lookup, err := http.Get(baseURL + "/v1/entries-hash/" + hashHex)
		if err == nil && lookup.StatusCode == http.StatusOK {
			var rec map[string]any
			if decErr := json.NewDecoder(lookup.Body).Decode(&rec); decErr == nil {
				lookup.Body.Close()
				if _, hasSeq := rec["sequence_number"]; hasSeq {
					// Merge SCT fields with the indexed record so
					// callers see the union — sequence_number,
					// signer_did, etc. from the index plus the
					// SCT fields callers may also need.
					for k, v := range sct {
						if _, exists := rec[k]; !exists {
							rec[k] = v
						}
					}
					return rec
				}
				continue
			}
			lookup.Body.Close()
		} else if lookup != nil {
			lookup.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("hash-lookup did not return sequence_number within budget for hash %s", hashHex)
	return nil
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. Submission — Mode A (authenticated with session token)
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Submission_ModeA_HappyPath(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-a", "did:example:exchange-a", 100)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:mode-a-submitter",
	}, []byte("mode-a-payload"))

	result := submitEntry(t, op.BaseURL, "tok-a", wire)

	seq := result["sequence_number"].(float64)
	if seq < 1 {
		t.Fatalf("sequence_number should be >= 1, got %v", seq)
	}
	hash := result["canonical_hash"].(string)
	if len(hash) != 64 {
		t.Fatalf("canonical_hash should be 64-char hex, got %d", len(hash))
	}
	logTimeStr := result["log_time"].(string)
	if _, err := time.Parse(time.RFC3339Nano, logTimeStr); err != nil {
		t.Fatalf("log_time should be RFC3339Nano: %v", err)
	}
	t.Logf("Mode A accepted: seq=%.0f hash=%s", seq, hash[:16])
}

func TestHTTP_Submission_ModeA_MultipleEntries(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-multi", "did:example:exchange-multi", 100)

	var seqs []float64
	for i := 0; i < 5; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:multi-submitter",
		}, []byte(fmt.Sprintf("entry-%d", i)))
		result := submitEntry(t, op.BaseURL, "tok-multi", wire)
		seqs = append(seqs, result["sequence_number"].(float64))
	}

	// Verify monotonically increasing sequences.
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("sequences not monotonic: %v", seqs)
		}
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Submission — Mode B (unauthenticated with compute stamp)
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Submission_ModeB_ValidStamp(t *testing.T) {
	op := startTestLedger(t)

	// Build entry with valid compute stamp (no auth token).
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:mode-b-submitter",
	}, []byte("mode-b-stamped-payload"), testLogDID, 16)

	// POST without Authorization header.
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	resp := doRequest(t, req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("Mode B with valid stamp: expected 202, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	json.Unmarshal(body, &result)
	t.Logf("Mode B accepted: SCT version=%v hash=%s", result["version"], result["canonical_hash"].(string)[:16])
}

func TestHTTP_Submission_ModeB_NoStamp_403(t *testing.T) {
	op := startTestLedger(t)

	// Entry without AdmissionProof, no auth token → 403.
	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:no-stamp",
	}, []byte("no-stamp"))

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	// No Authorization header.
	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Mode B without stamp: expected 403, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Submission_ModeB_WrongLogDID_403(t *testing.T) {
	op := startTestLedger(t)

	// Stamp bound to a different log DID.
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:wrong-log",
	}, []byte("wrong-log-payload"), "did:attesta:different-log", 16)

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("stamp bound to wrong log: expected 403, got %d: %s", resp.StatusCode, body)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Middleware Chain — Auth, Size, Credits, Protocol Version
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Middleware_InvalidToken_401(t *testing.T) {
	op := startTestLedger(t)
	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:auth-test"}, []byte("auth"))
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer invalid-nonexistent-token")
	resp := doRequest(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_ExpiredToken_401(t *testing.T) {
	op := startTestLedger(t)
	_, _ = op.Pool.Exec(context.Background(),
		`INSERT INTO sessions (token, exchange_did, expires_at) VALUES ($1, $2, $3)`,
		"tok-expired", "did:example:expired-exchange", time.Now().UTC().Add(-1*time.Hour),
	)
	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:expired"}, []byte("expired"))
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-expired")
	resp := doRequest(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for expired, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_OversizeBody_413(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-big", "did:example:exchange-big", 100)

	// Build a body that exceeds MaxEntrySize. Tier-2 BUG #3 alignment:
	// the handler now propagates *http.MaxBytesError as a typed 413
	// instead of silently truncating and producing a downstream 422
	// "deserialize" error with no attribution. The SizeLimit
	// middleware fires first at MaxEntrySize+1024 and writes 413; the
	// handler-side MaxBytesReader at MaxEntrySize+512 is the
	// defense-in-depth fallback for direct (test) calls.
	oversized := make([]byte, (1<<20)+2048)
	oversized[0] = 0x00
	oversized[1] = 0x05 // structurally-valid wire-version preamble byte

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(oversized))
	req.Header.Set("Authorization", "Bearer tok-big")
	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("oversize body: expected 413, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_NoCredits_402(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-broke", "did:example:exchange-broke", 0)
	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:broke"}, []byte("need-credits"))
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-broke")
	resp := doRequest(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 402, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_MalformedBody_422(t *testing.T) {
	op := startTestLedger(t)
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader([]byte("garbage")))
	resp := doRequest(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("malformed body: expected 422, got %d: %s", resp.StatusCode, body)
	}
}

// TestHTTP_Middleware_WrongProtocolVersion_422 verifies the ledger rejects
// any wire protocol version other than v5 (current, post-Wave-1.5).
//
// Wire format protocol version is stored in bytes 0-1 of the entry as a
// big-endian uint16. The ledger's submission handler reads this in Step 1
// and rejects with 422 if it does not equal 5.
func TestHTTP_Middleware_WrongProtocolVersion_422(t *testing.T) {
	op := startTestLedger(t)

	// Build a valid v5 wire entry then overwrite protocol version to v2
	// (a value the ledger will refuse).
	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:v2"}, []byte("v2"))
	wire[0] = 0x00
	wire[1] = 0x02 // Protocol version 2 instead of v5 — must be rejected.

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("v2 entry: expected 422, got %d: %s", resp.StatusCode, body)
	}
}

// TestHTTP_Middleware_FutureProtocolVersion_422 confirms forward-compatibility
// rejection: a v6 entry (which doesn't exist yet) must also be refused.
// Catches the failure mode where the ledger might silently accept anything
// "5 or higher" instead of strict equality.
func TestHTTP_Middleware_FutureProtocolVersion_422(t *testing.T) {
	op := startTestLedger(t)

	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:v6"}, []byte("v6"))
	wire[0] = 0x00
	wire[1] = 0x06 // Protocol version 6 — does not exist; must be rejected.

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("v6 entry: expected 422, got %d: %s", resp.StatusCode, body)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Credit Deduction Verification
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_CreditDeduction(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-credit", "did:example:exchange-credit", 10)

	// Check initial balance.
	bal0, _ := op.CreditStore.Balance(context.Background(), "did:example:exchange-credit")
	if bal0 != 10 {
		t.Fatalf("initial balance should be 10, got %d", bal0)
	}

	// Submit 3 entries.
	for i := 0; i < 3; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:credit-test",
		}, []byte(fmt.Sprintf("credit-entry-%d", i)))
		submitEntry(t, op.BaseURL, "tok-credit", wire)
	}

	// Check balance decreased by exactly 3.
	bal1, _ := op.CreditStore.Balance(context.Background(), "did:example:exchange-credit")
	if bal1 != 7 {
		t.Fatalf("balance after 3 submissions: expected 7, got %d", bal1)
	}

	// Submit 7 more → balance 0.
	for i := 3; i < 10; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:credit-test",
		}, []byte(fmt.Sprintf("credit-entry-%d", i)))
		submitEntry(t, op.BaseURL, "tok-credit", wire)
	}

	bal2, _ := op.CreditStore.Balance(context.Background(), "did:example:exchange-credit")
	if bal2 != 0 {
		t.Fatalf("balance after 10 submissions: expected 0, got %d", bal2)
	}

	// 11th submission → 402.
	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:credit-test",
	}, []byte("credit-entry-overflow"))
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-credit")
	resp := doRequest(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("exhausted credits: expected 402, got %d: %s", resp.StatusCode, body)
	}

	t.Logf("credit deduction verified: 10→7→0→402")
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. End-to-End Round-Trip with Sequence Ordering
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_EndToEnd_SubmitAndQueryBack(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-e2e", "did:example:exchange-e2e", 100)

	signerDID := "did:example:e2e-roundtrip-alice"
	const N = 5

	// Submit N entries, collect submission sequence numbers.
	var submitSeqs []float64
	for i := 0; i < N; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: signerDID,
		}, []byte(fmt.Sprintf("e2e-payload-%d", i)))
		result := submitEntry(t, op.BaseURL, "tok-e2e", wire)
		submitSeqs = append(submitSeqs, result["sequence_number"].(float64))
	}

	// Poll until builder processes all entries (no flaky sleep).
	results := pollQueryResults(t, op.BaseURL, signerDID, N, 5*time.Second)
	if len(results) != N {
		t.Fatalf("expected %d entries, got %d", N, len(results))
	}

	// Verify sequence numbers are sequential and match submission order.
	var querySeqs []float64
	for _, r := range results {
		querySeqs = append(querySeqs, r["sequence_number"].(float64))
	}
	sort.Float64s(querySeqs)

	for i := 1; i < len(querySeqs); i++ {
		if querySeqs[i] != querySeqs[i-1]+1 {
			t.Fatalf("sequence gap: %v", querySeqs)
		}
	}

	// Verify all results have correct signer_did.
	for i, r := range results {
		if r["signer_did"] != signerDID {
			t.Fatalf("result %d: signer_did %v != %s", i, r["signer_did"], signerDID)
		}
	}

	t.Logf("end-to-end: submitted %d, queried %d, sequences %v", N, len(results), querySeqs)
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. 409 Duplicate Detection
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Duplicate_409(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-dup", "did:example:exchange-dup", 100)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:duplicate-test",
	}, []byte("unique-payload-for-dup-test"))

	// First → 202.
	submitEntry(t, op.BaseURL, "tok-dup", wire)

	// Second with same bytes → 409.
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-dup")
	resp := doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("duplicate: expected 409, got %d: %s", resp.StatusCode, body)
	}

	var errResp map[string]string
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] == "" {
		t.Fatal("409 should have error message")
	}
	t.Logf("duplicate rejected: %s", errResp["error"])
}

// ═════════════════════════════════════════════════════════════════════════════
// 6b. Batch admission — duplicate detection (intra-batch + historical)
// ═════════════════════════════════════════════════════════════════════════════

// Two identical entries in the same batch must be rejected with
// 409 BEFORE either is admitted — atomic batch semantics, no
// partial credit deduction.
func TestHTTP_BatchSubmission_IntraBatchDuplicate_409(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-batch-dup", "did:example:batch-dup", 100)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:batch-intra-dup",
	}, []byte("batch-intra-dup-payload"))

	body := map[string]any{
		"entries": []map[string]any{
			{"wire_bytes_hex": hex.EncodeToString(wire)},
			{"wire_bytes_hex": hex.EncodeToString(wire)}, // dup of index 0
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer tok-batch-dup")
	resp := doRequest(t, req)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("intra-batch duplicate: expected 409, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(string(respBody), "duplicates entry 0") {
		t.Errorf("expected 'duplicates entry 0' in error: %s", respBody)
	}
}

// A hash already admitted in a prior request must be rejected
// with 409 when re-submitted via the batch endpoint. Mirrors
// TestHTTP_Duplicate_409 (single-entry path) but for batch.
func TestHTTP_BatchSubmission_HistoricalDuplicate_409(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-batch-hist-dup", "did:example:batch-hist-dup", 100)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:batch-hist-dup-test",
	}, []byte("batch-hist-dup-payload"))

	// First single-entry submission seeds entry_index.
	submitEntry(t, op.BaseURL, "tok-batch-hist-dup", wire)

	// Now POST a one-entry batch with the same canonical hash —
	// must hit FetchByHash and 409 before any credit deduction.
	body := map[string]any{
		"entries": []map[string]any{
			{"wire_bytes_hex": hex.EncodeToString(wire)},
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer tok-batch-hist-dup")
	resp := doRequest(t, req)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("historical batch duplicate: expected 409, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(string(respBody), "existing sequence") {
		t.Errorf("expected 'existing sequence' in error: %s", respBody)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. EntryResponse Shape (verifies no internal fields leak)
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_EntryResponseShape(t *testing.T) {
	op := startTestLedger(t)
	op.seedSession(t, "tok-shape", "did:example:exchange-shape", 100)

	signerDID := "did:example:shape-test-signer"
	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: signerDID,
	}, []byte("shape-test-payload"))
	submitEntry(t, op.BaseURL, "tok-shape", wire)

	// Poll for result (replaces flaky sleep).
	results := pollQueryResults(t, op.BaseURL, signerDID, 1, 5*time.Second)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}

	r := results[0]

	// Required fields.
	for _, f := range []string{"sequence_number", "canonical_hash", "log_time", "signer_did", "canonical_bytes"} {
		if _, ok := r[f]; !ok {
			t.Fatalf("missing required field: %s", f)
		}
	}

	// Value checks.
	if r["signer_did"] != signerDID {
		t.Fatalf("signer_did: got %v, want %s", r["signer_did"], signerDID)
	}
	hash := r["canonical_hash"].(string)
	if len(hash) != 64 {
		t.Fatalf("canonical_hash should be 64 hex, got %d", len(hash))
	}
	seq := r["sequence_number"].(float64)
	if seq < 1 {
		t.Fatalf("sequence_number should be >= 1, got %v", seq)
	}

	t.Logf("shape verified: seq=%.0f hash=%s signer=%s", seq, hash[:16], signerDID)
}

// ═════════════════════════════════════════════════════════════════════════════
// 8. Difficulty + Health Endpoints
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_DifficultyEndpoint(t *testing.T) {
	op := startTestLedger(t)
	resp := httpGet(t, op.BaseURL+"/v1/admission/difficulty")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	diff := result["difficulty"].(float64)
	if diff < 8 || diff > 24 {
		t.Fatalf("difficulty out of range: %v", diff)
	}
	if result["hash_function"] != "sha256" {
		t.Fatalf("hash_function: %v", result["hash_function"])
	}
	if _, ok := result["timestamp"]; !ok {
		t.Fatal("missing timestamp")
	}
	if resp.Header.Get("Cache-Control") == "" {
		t.Fatal("missing Cache-Control header")
	}
	t.Logf("difficulty=%v hash=%v cache=%s", diff, result["hash_function"], resp.Header.Get("Cache-Control"))
}

func TestHTTP_HealthCheck(t *testing.T) {
	op := startTestLedger(t)
	resp := httpGet(t, op.BaseURL+"/healthz")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body: %q", body)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 9. Mode B — Stale Epoch Rejection (SDK-2 acceptance window)
// ═════════════════════════════════════════════════════════════════════════════

// TestHTTP_Submission_ModeB_StaleEpoch_403 mints a stamp with an epoch many
// windows in the past, then submits it. The ledger's VerifyStamp must
// reject it because its currentEpoch math will compute a much higher number,
// putting the stamp outside the [current-window, current+window] band.
//
// This is the regression test for the SDK-2 epoch acceptance window contract.
// Without enforcement, a stamp could be reused indefinitely.
func TestHTTP_Submission_ModeB_StaleEpoch_403(t *testing.T) {
	op := startTestLedger(t)

	// Build a stamp manually with a stale epoch (100 hours in the past).
	staleEpoch := currentTestEpoch() - 100

	header := envelope.ControlHeader{
		SignerDID: "did:example:stale-epoch",
	}
	header.AdmissionProof = &envelope.AdmissionProofBody{
		Mode:       types.WireByteModeB,
		Difficulty: 8, // low difficulty for fast nonce search
		HashFunc:   admission.WireByteHashSHA256,
		Epoch:      staleEpoch,
		Nonce:      0,
	}

	// Brute force a valid nonce against the stale epoch. Same 	// chicken-and-egg as buildModeBWireEntry — sign per iteration so
	// EntryIdentity reflects the stamp target the ledger computes.
	//
	// Resolve the SignerDID label once before the loop so admission's
	// DIDResolver returns the matching public key.
	signer := resolveSyntheticSigner(header.SignerDID)
	header.SignerDID = signer.did
	var wire []byte
	for nonce := uint64(0); nonce < 5_000_000; nonce++ {
		header.AdmissionProof.Nonce = nonce
		entry, err := envelope.NewUnsignedEntry(header, []byte("stale-payload"))
		if err != nil {
			t.Fatalf("NewUnsignedEntry: %v", err)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(entry))
		sig, err := signatures.SignEntry(signingHash, signer.priv)
		if err != nil {
			t.Fatalf("SignEntry: %v", err)
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: signer.did,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		}}
		canonical := mustSerialize(entry)
		entryHash := sha256.Sum256(canonical)

		// Verify against the stale epoch with window=0 (exact match) to
		// confirm the nonce is valid for THAT epoch — not the ledger's.
		apiProof := admission.ProofFromWire(header.AdmissionProof, testLogDID)
		if admission.VerifyStamp(
			apiProof, entryHash, testLogDID, 8,
			admission.HashSHA256, nil,
			staleEpoch, 0, // window=0 → exact match required
		) == nil {
			wire = canonical
			break
		}
	}
	if wire == nil {
		t.Fatal("could not mint stale-epoch stamp within 5M nonces")
	}

	// Submit the stale-epoch stamp.
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	resp := doRequest(t, req)
	defer resp.Body.Close()

	// Ledger should reject as out-of-window.
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("stale-epoch stamp: expected 403, got %d: %s", resp.StatusCode, body)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Suppress unused imports
// ═════════════════════════════════════════════════════════════════════════════

var _ = binary.BigEndian
