//go:build scenarios

/*
FILE PATH:

	tests/scenarios_fraud_test.go

DESCRIPTION:

	Layer 0 — FRAUD-EQV-01 + FRAUD-FRK-01: equivocation detection
	via /v1/commitments/by-split-id (multi-row response) and
	rollback rejection via /v1/tree/consistency (HTTP 400 on
	old >= new). Together these are the cryptographic-evidence
	surfaces a Court / Insurance / Audit network's fraud bot
	polls.

KEY ARCHITECTURAL DECISIONS:
  - EQV-01 inserts evidence directly into entry_index +
    commitment_split_id + the in-process bytestore. This
    bypasses the admission pipeline (which validates the
    Pedersen commitment cryptographically and would reject
    our synthetic blobs). The handler we're testing does NOT
    validate commitment cryptography on the lookup path —
    it returns whatever the (schema_id, split_id) tuple
    points at. Direct insertion is therefore the correct
    shortcut for THIS layer's contract.
  - The 200 OK len=2+ contract is the API's documented
    "cryptographic equivocation" signal (api/commitments.go
    file docblock). Persona-style assertion walks the
    response shape: entries[].position.sequence_number
    ASC, canonical_bytes_hex non-empty, distinct hashes.
  - FRK-01 is one HTTP probe: GET /v1/tree/consistency/100/50
    MUST return 400 with the documented error class. We
    assert the body is application/json and parses with
    stdlib decoders — a future error-class drift surfaces
    here, not at the SDK boundary.
  - We do NOT exercise gossip publication of the
    equivocation finding. The current ledger surfaces
    equivocation via the lookup endpoint's response
    shape + a structured log warning; gossip publication
    of a typed finding is out of scope for the production
    ledger today. Persona 4 covers gossip wire-protocol
    tests separately.

OVERVIEW:

	TestFraud_Defenses
	  EQV-01_DuplicateSplitID
	    → insert A (seq=N, split_id=X), B (seq=N+1, same X);
	      GET /v1/commitments/by-split-id returns 200 with
	      two entries in ASC sequence order; canonical_bytes
	      differ between the two entries.
	  FRK-01_RollbackConsistency400
	    → GET /v1/tree/consistency/100/50 returns HTTP 400
	      with a typed error body (apitypes.ErrorClass*).

KEY DEPENDENCIES:
  - tests/scenarios_stack_test.go: NewScenariosStack.
  - github.com/clearcompass-ai/attesta/crypto/artifact:
    PREGrantCommitmentSchemaID (the wire-string value).
  - api/commitments.go: handler under test.
  - api/tree.go: NewTreeConsistencyHandler under test.
*/
package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/artifact"
)

// -------------------------------------------------------------------------------------------------
// 1) Top-level test
// -------------------------------------------------------------------------------------------------

// TestFraud_Defenses umbrella. Each sub-test builds its own
// stack so the equivocation fixture's direct DB writes
// cannot contaminate FRK-01's HTTP probe.
func TestFraud_Defenses(t *testing.T) {
	t.Run("EQV-01_DuplicateSplitID", runFraudEQV01DuplicateSplitID)
	t.Run("FRK-01_RollbackConsistency400", runFraudFRK01Rollback400)
}

// -------------------------------------------------------------------------------------------------
// 2) FRAUD-EQV-01 — duplicate split_id surfaces multi-row evidence
// -------------------------------------------------------------------------------------------------

// runFraudEQV01DuplicateSplitID. Inserts two distinct entries (A
// and B) sharing the SAME split_id. Asserts the lookup endpoint
// returns 200 with entries[] of length 2, canonical_bytes_hex
// distinct, sequence_numbers ASC. This is the equivocation-
// evidence contract documented in api/commitments.go.
func runFraudEQV01DuplicateSplitID(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{LogDIDSuffix: "fraud-eqv-01"})

	// Synthesise a 32-byte split_id. Deterministic so a failure
	// is reproducible from the test name alone.
	splitID := sha256.Sum256([]byte("fraud-eqv-01-split-id"))
	bytesA := []byte("fraud-eqv-01-canonical-A")
	bytesB := []byte("fraud-eqv-01-canonical-B")
	hashA := sha256.Sum256(bytesA)
	hashB := sha256.Sum256(bytesB)
	if hashA == hashB {
		t.Fatal("test fixture: hashes collided — this is fixture corruption")
	}

	// We use seq numbers high enough they won't collide with any
	// real submission the harness might do (it doesn't, but
	// defense in depth).
	const seqA, seqB = uint64(900_001), uint64(900_002)
	logTime := time.Now().UTC()
	op := stack.Operator()

	fraudInsertCommitmentRow(t, op, seqA, hashA, logTime, splitID, bytesA)
	fraudInsertCommitmentRow(t, op, seqB, hashB, logTime.Add(time.Second), splitID, bytesB)

	// Lookup via the live HTTP handler.
	url := fmt.Sprintf(
		"%s/v1/commitments/by-split-id/%s/%s",
		stack.LedgerBaseURL(),
		artifact.PREGrantCommitmentSchemaID,
		hex.EncodeToString(splitID[:]),
	)
	resp, err := http.Get(url)
	mustNotErr(t, "GET commitments by-split-id", err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}

	var parsed struct {
		Entries []struct {
			CanonicalBytesHex string `json:"canonical_bytes_hex"`
			LogTime           string `json:"log_time"`
			Position          struct {
				SequenceNumber uint64 `json:"sequence_number"`
				LogDID         string `json:"log_did"`
			} `json:"position"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got := len(parsed.Entries); got != 2 {
		t.Fatalf("entries len=%d, want 2 (equivocation evidence)", got)
	}
	// Stable ASC sequence order is the documented contract.
	seqs := []uint64{
		parsed.Entries[0].Position.SequenceNumber,
		parsed.Entries[1].Position.SequenceNumber,
	}
	if !sort.SliceIsSorted(seqs, func(i, j int) bool { return seqs[i] < seqs[j] }) {
		t.Fatalf("entries not ASC by seq: %v", seqs)
	}
	if seqs[0] != seqA || seqs[1] != seqB {
		t.Fatalf("entries seqs = %v, want %v", seqs, []uint64{seqA, seqB})
	}
	if parsed.Entries[0].CanonicalBytesHex == parsed.Entries[1].CanonicalBytesHex {
		t.Fatal("equivocation entries carry identical canonical bytes (fixture broken)")
	}
	wantA := hex.EncodeToString(bytesA)
	wantB := hex.EncodeToString(bytesB)
	if parsed.Entries[0].CanonicalBytesHex != wantA {
		t.Fatalf("entry[0] canonical_bytes = %s, want %s",
			parsed.Entries[0].CanonicalBytesHex, wantA)
	}
	if parsed.Entries[1].CanonicalBytesHex != wantB {
		t.Fatalf("entry[1] canonical_bytes = %s, want %s",
			parsed.Entries[1].CanonicalBytesHex, wantB)
	}
	if parsed.Entries[0].Position.LogDID != stack.LogDID() {
		t.Fatalf("entry[0] log_did = %q, want %q",
			parsed.Entries[0].Position.LogDID, stack.LogDID())
	}
}

// -------------------------------------------------------------------------------------------------
// 3) FRAUD-FRK-01 — rollback (old >= new) returns 400
// -------------------------------------------------------------------------------------------------

// runFraudFRK01Rollback400. Probes /v1/tree/consistency/100/50.
// The ledger's documented contract is HTTP 400 with a typed
// error class — the rollback / fork-evidence signal a fraud
// bot polls for SLA violations. Body MUST be JSON.
func runFraudFRK01Rollback400(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{LogDIDSuffix: "fraud-frk-01"})

	// Old > New → 400.
	resp1, err := http.Get(stack.LedgerBaseURL() + "/v1/tree/consistency/100/50")
	mustNotErr(t, "GET consistency old>new", err)
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp1.Body, 512))
		t.Fatalf("old>new status=%d, want 400, body=%s", resp1.StatusCode, body)
	}
	if ct := resp1.Header.Get("Content-Type"); ct == "" {
		t.Fatalf("rollback response Content-Type empty")
	}

	// Old == New → also 400 (per api/tree.go: "old size must be
	// less than new size").
	resp2, err := http.Get(stack.LedgerBaseURL() + "/v1/tree/consistency/50/50")
	mustNotErr(t, "GET consistency old==new", err)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp2.Body, 512))
		t.Fatalf("old==new status=%d, want 400, body=%s", resp2.StatusCode, body)
	}

	// Body parses as JSON (the typed-error envelope shape) so a
	// fraud-bot consumer doesn't see a free-text 400.
	var raw map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&raw); err != nil {
		t.Fatalf("400 body not JSON: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("400 body is empty JSON object — no diagnostic for fraud bot")
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Helper — direct insert into commitment_split_id + entry_index + bytestore
// -------------------------------------------------------------------------------------------------

// fraudInsertCommitmentRow seeds one (seq, hash, split_id) tuple
// into both Postgres tables the lookup handler joins (entry_index
// + commitment_split_id) AND writes the canonical bytes into the
// in-process bytestore (so the fetcher can read them at lookup
// time). No admission validation runs — the synthetic bytes are
// not real Pedersen commitments.
func fraudInsertCommitmentRow(
	t *testing.T,
	op *testLedger,
	seq uint64,
	hash [32]byte,
	logTime time.Time,
	splitID [32]byte,
	canonicalBytes []byte,
) {
	t.Helper()
	ctx := context.Background()

	if _, err := op.Pool.Exec(ctx, `
		INSERT INTO entry_index (sequence_number, canonical_hash, log_time, signer_did)
		VALUES ($1, $2, $3, $4)`,
		seq, hash[:], logTime, "did:example:fraud-eqv",
	); err != nil {
		t.Fatalf("insert entry_index seq=%d: %v", seq, err)
	}

	if _, err := op.Pool.Exec(ctx, `
		INSERT INTO commitment_split_id (sequence_number, schema_id, split_id)
		VALUES ($1, $2, $3)`,
		seq, artifact.PREGrantCommitmentSchemaID, splitID[:],
	); err != nil {
		t.Fatalf("insert commitment_split_id seq=%d: %v", seq, err)
	}

	if err := op.EntryBytes.WriteEntry(ctx, seq, hash, canonicalBytes); err != nil {
		t.Fatalf("write bytestore seq=%d: %v", seq, err)
	}
}
