//go:build scenarios

/*
FILE PATH:
    tests/scenarios_auditor_full_test.go

DESCRIPTION:
    Layer 0 — Persona 1 (Standalone Auditor, end-to-end). The smoke
    gate for the entire scenarios suite. After the Commit B collapse
    of the shadow-Tessera hack, the auditor's view of the tree is
    populated exclusively by HTTP submissions through the ledger's
    own /v1/entries handler — same writer for the ledger and the
    auditor, no second state machine.

KEY ARCHITECTURAL DECISIONS:
    - No shadow append. Every leaf reaches the tree via
      ledger.SubmissionHandler → wal.Submit → builder loop →
      tessera.NewTesseraAdapter.AppendLeaf. The auditor reads
      tile bytes the ledger actually wrote (Trust Alignment 6:
      Parse, Don't Validate).
    - Polling, never time.Sleep. WaitForTreeSize / pollHashLookup
      both ride on bounded ctx deadlines.
    - DID-anchored. Every endpoint the auditor uses is resolved
      through did.DIDEndpointAdapter from the bound DIDDocument
      (Trust Alignment 3).
    - Multi-scenario t.Run blocks so a regression in one path
      does not mask other passing paths. Boot is shared because
      spinning up real Tessera POSIX + Postgres + httptest.Server
      is the bulk of the wall-clock cost (~500ms — 2s on cold
      cache); each sub-scenario contributes hundreds of ms.

OVERVIEW:
    TestPersona1_AuditorFull
      EndpointResolution_RoundTrip
        → adapter returns the harness-bound LedgerURL + CDNURL
          verbatim.
      Submit_To_TileBytes_RoundTrip
        → build admissible wire → POST /v1/entries → poll
          /v1/entries-hash/{hash} for sequence → WaitForTreeSize
          → ReadLevel0Tile → hash bytes present in tile.
      Tree_GrowsMonotonically
        → submit two more entries; observe TreeSize strictly
          increasing across the run; tree never shrinks.
      DefensiveCopy_Resolver
        → mutating doc.Service on a returned DIDDocument does
          NOT corrupt the resolver's stored doc.

KEY DEPENDENCIES:
    - tests/scenarios_stack_test.go: NewScenariosStack with real
      Tessera under the hood.
    - tests/scenarios_auditor_test.go: NewAuditor.
    - tests/e2e_v1_sct_test.go: buildModeBWireEntry + pollHashLookup
      helpers (re-used to avoid duplicating wire construction).
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
)

// -------------------------------------------------------------------------------------------------
// 1) Top-level test
// -------------------------------------------------------------------------------------------------

// TestPersona1_AuditorFull boots the production stack once and
// runs every sub-scenario in sequence. Each is independent: a
// failure in one does not mask others.
func TestPersona1_AuditorFull(t *testing.T) {
	stack := NewScenariosStack(t, scenariosStackOpts{LogDIDSuffix: "persona1"})
	a := NewAuditor(t, stack.Resolver().AuditorAdapter(), stack.TileReader(), stack)

	t.Run("EndpointResolution_RoundTrip", func(t *testing.T) {
		runP1EndpointResolution(t, stack, a)
	})
	t.Run("Submit_To_TileBytes_RoundTrip", func(t *testing.T) {
		runP1SubmitToTileRoundtrip(t, stack, a)
	})
	t.Run("Tree_GrowsMonotonically", func(t *testing.T) {
		runP1TreeGrowsMonotonically(t, stack, a)
	})
	t.Run("DefensiveCopy_Resolver", func(t *testing.T) {
		runP1DefensiveCopyResolver(t, stack)
	})
}

// -------------------------------------------------------------------------------------------------
// 2) Endpoint resolution round-trip
// -------------------------------------------------------------------------------------------------

func runP1EndpointResolution(t *testing.T, stack *scenariosStack, a *auditor) {
	t.Helper()
	logDID := stack.LogDID()

	gotLedger, err := a.ResolveLedgerEndpoint(logDID)
	mustNotErr(t, "ResolveLedgerEndpoint", err)
	if gotLedger != stack.LedgerBaseURL() {
		t.Fatalf("ResolveLedgerEndpoint = %q, want %q", gotLedger, stack.LedgerBaseURL())
	}

	gotCDN, err := a.ResolveCDNEndpoint(logDID)
	mustNotErr(t, "ResolveCDNEndpoint", err)
	if gotCDN != stack.CDNBaseURL() {
		t.Fatalf("ResolveCDNEndpoint = %q, want %q", gotCDN, stack.CDNBaseURL())
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Submit → tile bytes → leaf-hash present
// -------------------------------------------------------------------------------------------------

// runP1SubmitToTileRoundtrip drives the canonical "submit one
// entry, wait for the tile, find the leaf hash" round-trip
// against the real ledger HTTP surface.
//
// Steps:
//  1. Build a Mode-B-stamped wire entry; canonical hash is
//     SHA-256(wire).
//  2. POST /v1/entries → SCT body. The SCT carries the canonical
//     hash; the ledger has fsync'd to WAL but not yet sequenced.
//  3. Poll /v1/entries-hash/{hash} until the entry transitions
//     from "pending" to "sequenced" with a sequence_number.
//  4. WaitForTreeSize(sct_seq+1) on the auditor — bounded by a
//     10s context so MMD-shape latency is absorbed but never
//     silently inflated.
//  5. Read the level-0 tile at floor(seq / 256). Assert the
//     canonical-hash bytes appear in the tile (RFC 6962 entry
//     identity == SHA-256(wire)).
func runP1SubmitToTileRoundtrip(t *testing.T, stack *scenariosStack, a *auditor) {
	t.Helper()

	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID:   "did:example:persona1-roundtrip",
		Destination: stack.LogDID(),
		EventTime:   time.Now().UTC().UnixMicro(),
	}, []byte("persona1-payload"), stack.LogDID(), difficulty)

	canonical := persona1HashWire(wire)
	sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
	if got := sct.CanonicalHash; got != hex.EncodeToString(canonical[:]) {
		t.Fatalf("SCT.CanonicalHash mismatch: got %s want %x", got, canonical[:])
	}

	seq := persona1WaitForSequence(t, stack.LedgerBaseURL(), canonical, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	head, err := a.WaitForTreeSize(ctx, seq+1)
	mustNotErr(t, "WaitForTreeSize", err)
	if head.TreeSize < seq+1 {
		t.Fatalf("head.TreeSize = %d, want >= %d", head.TreeSize, seq+1)
	}

	tile, err := a.ReadLevel0Tile(ctx, seq/256)
	mustNotErr(t, "ReadLevel0Tile", err)
	if !bytes.Contains(tile, canonical[:]) {
		t.Fatalf("level-0 tile (size=%d) missing canonical hash %x", len(tile), canonical[:8])
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Tree grows monotonically across multiple HTTP submissions
// -------------------------------------------------------------------------------------------------

// runP1TreeGrowsMonotonically asserts the tree's TreeSize strictly
// increases under successive HTTP submissions and never shrinks.
// Pins L3 and the L1 rollback-detection invariant.
func runP1TreeGrowsMonotonically(t *testing.T, stack *scenariosStack, a *auditor) {
	t.Helper()
	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	startHead, err := a.WaitForTreeSize(ctx, 0)
	mustNotErr(t, "WaitForTreeSize start", err)

	for i := 0; i < 2; i++ {
		wire := buildModeBWireEntry(t, envelope.ControlHeader{
			SignerDID:   fmt.Sprintf("did:example:persona1-grow-%d", i),
			Destination: stack.LogDID(),
			EventTime:   time.Now().UTC().UnixMicro(),
		}, []byte(fmt.Sprintf("grow-payload-%d", i)), stack.LogDID(), difficulty)
		sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
		_ = persona1WaitForSequence(t, stack.LedgerBaseURL(),
			persona1MustDecodeHex(t, sct.CanonicalHash), 5*time.Second)
	}

	endHead, err := a.WaitForTreeSize(ctx, startHead.TreeSize+2)
	mustNotErr(t, "WaitForTreeSize end", err)
	if endHead.TreeSize <= startHead.TreeSize {
		t.Fatalf("tree size did not grow: start=%d end=%d", startHead.TreeSize, endHead.TreeSize)
	}
	if endHead.TreeSize < startHead.TreeSize {
		t.Fatalf("tree size shrank: start=%d end=%d", startHead.TreeSize, endHead.TreeSize)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Defensive copy on the DID resolver
// -------------------------------------------------------------------------------------------------

func runP1DefensiveCopyResolver(t *testing.T, stack *scenariosStack) {
	t.Helper()
	logDID := stack.LogDID()

	doc1, err := stack.Resolver().Resolve(logDID)
	mustNotErr(t, "Resolve A", err)
	originalCount := len(doc1.Service)
	if originalCount == 0 {
		t.Fatal("doc.Service empty — harness misconfigured")
	}
	doc1.Service = nil

	doc2, err := stack.Resolver().Resolve(logDID)
	mustNotErr(t, "Resolve B", err)
	if len(doc2.Service) != originalCount {
		t.Fatalf("post-mutation Service count = %d, want %d (defensive copy broken)",
			len(doc2.Service), originalCount)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) HTTP helpers — local to Persona 1, no e2eOperator dependency
// -------------------------------------------------------------------------------------------------

// persona1Difficulty fetches the ledger's currently-advertised
// PoW difficulty from /v1/admission/difficulty.
func persona1Difficulty(t *testing.T, baseURL string) uint32 {
	t.Helper()
	resp, err := http.Get(baseURL + "/v1/admission/difficulty")
	mustNotErr(t, "GET difficulty", err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		t.Fatalf("difficulty status=%d body=%s", resp.StatusCode, body)
	}
	var body struct {
		Difficulty uint32 `json:"difficulty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("difficulty decode: %v", err)
	}
	if body.Difficulty == 0 {
		t.Fatal("difficulty endpoint returned 0")
	}
	return body.Difficulty
}

// persona1Submit POSTs wire to /v1/entries and returns the
// decoded SCT. Fatals on any non-202 response.
func persona1Submit(t *testing.T, baseURL string, wire []byte) sdksct.SignedCertificateTimestamp {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/entries", bytes.NewReader(wire))
	mustNotErr(t, "new request", err)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	mustNotErr(t, "POST /v1/entries", err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", resp.StatusCode, body)
	}
	var sct sdksct.SignedCertificateTimestamp
	if err := json.Unmarshal(body, &sct); err != nil {
		t.Fatalf("decode SCT: %v body=%s", err, body)
	}
	return sct
}

// persona1WaitForSequence polls /v1/entries-hash/{hash} with the
// supplied bounded timeout until the entry transitions to a state
// carrying a sequence_number. Returns the assigned sequence.
func persona1WaitForSequence(t *testing.T, baseURL string, hash [32]byte, timeout time.Duration) uint64 {
	t.Helper()
	url := baseURL + "/v1/entries-hash/" + hex.EncodeToString(hash[:])
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if resp.StatusCode == http.StatusOK {
			var rec map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&rec); err == nil {
				if seq, ok := rec["sequence_number"].(float64); ok {
					resp.Body.Close()
					return uint64(seq)
				}
			}
		}
		resp.Body.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("persona1WaitForSequence: hash %x… not sequenced within %v", hash[:8], timeout)
	return 0
}

// persona1HashWire computes SHA-256(wire) — the canonical hash
// the ledger uses as entry identity.
func persona1HashWire(wire []byte) [32]byte {
	return sha256.Sum256(wire)
}

// persona1MustDecodeHex parses a 64-char hex string into [32]byte.
// Fatals on any malformed input — every input here is from the
// SCT body the ledger just signed, so the failure modes are
// "harness broken", not "system under test broken".
func persona1MustDecodeHex(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	mustNotErr(t, "hex.Decode", err)
	if len(b) != 32 {
		t.Fatalf("decoded len=%d, want 32", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
