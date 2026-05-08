/*
FILE PATH: integration/equivocation_test.go

End-to-end test for the cryptographic-commitment surface.

# WHAT THIS TEST PINS

A malicious dealer publishes two distinct commitment entries
under the same (schema_id, split_id) tuple. The ledger's
admission pipeline admits both — the (schema_id, split_id)
BTREE index is non-UNIQUE specifically so this case lands as
cryptographic evidence rather than being silently destroyed by
a constraint violation.

Surviving guarantees:

 1. Both entries are durable in commitment_split_id.
    A regression here destroys evidence at admission time.

 2. The lookup endpoint
    (GET /v1/commitments/by-split-id/{schema_id}/{hex})
    returns BOTH entries in ascending sequence order.

 3. The SDK's *artifact.CommitmentEquivocationError construction
    wraps the two-entry response correctly. Confirms the error
    shape callers see in production.

Equivocation transparency flows through KindEntryCommitmentEquivocation
via gossipnet.EquivocationScanner (subscribed to the splitid
index 0x0A), with cryptographically-verified findings projected
into the BadgerDB equivocation projection 0x0B.

Skip semantics: skipped when ATTESTA_TEST_DSN is unset.
*/
package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/artifact"

	opapi "github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/store"
)

// TestEquivocation_EndToEnd seeds two distinct commitment entries
// under the same SplitID, then exercises the three surviving
// downstream guarantees in order.
func TestEquivocation_EndToEnd(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetTables(t, ctx, pool)

	// ── Seed two entries under the same SplitID ──────────────────
	var splitID [32]byte
	splitID[0] = 0xEE
	splitID[1] = 0xEE
	const seqA, seqB uint64 = 100, 200

	// Distinct payloads so the canonical_hash UNIQUE constraint
	// on entry_index doesn't reject the second seed. The SplitID
	// embedded in each payload is identical — that's the
	// equivocation signature.
	payloadA := buildSyntheticCommitmentPayload(t, splitID)
	payloadB := mutateCommitmentPayload(t, payloadA)

	seedCommitmentEntry(t, ctx, pool, seqA, splitID, payloadA)
	seedCommitmentEntry(t, ctx, pool, seqB, splitID, payloadB)

	// ── Guarantee 1: both rows survive in commitment_split_id ────
	rowCount := countSplitIDRows(t, ctx, pool,
		artifact.PREGrantCommitmentSchemaID, splitID)
	if rowCount != 2 {
		t.Fatalf("expected 2 commitment_split_id rows, got %d", rowCount)
	}

	// ── Guarantee 2: lookup endpoint returns array of length 2 ───
	reader := &stubEntryReader{
		wireBySeq: map[uint64][]byte{
			seqA: payloadA,
			seqB: payloadB,
		},
	}
	fetcher := store.NewPostgresCommitmentFetcher(pool, reader, testLogDID)
	handler := opapi.NewCommitmentLookupHandler(&opapi.CryptographicCommitmentDeps{
		Fetcher: fetcher,
		Logger:  slog.Default(),
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/commitments/by-split-id/{schema_id}/{hex}", handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	url := fmt.Sprintf("%s/v1/commitments/by-split-id/%s/%s",
		srv.URL,
		artifact.PREGrantCommitmentSchemaID,
		hex.EncodeToString(splitID[:]))
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET lookup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("lookup status=%d body=%q", resp.StatusCode, body)
	}

	var got opapi.CommitmentLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode lookup response: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 entries (equivocation), got %d", len(got.Entries))
	}
	if got.Entries[0].Position.SequenceNumber != seqA {
		t.Errorf("entries[0].sequence: got %d, want %d",
			got.Entries[0].Position.SequenceNumber, seqA)
	}
	if got.Entries[1].Position.SequenceNumber != seqB {
		t.Errorf("entries[1].sequence: got %d, want %d",
			got.Entries[1].Position.SequenceNumber, seqB)
	}

	// ── Guarantee 3: SDK CommitmentEquivocationError shape ───────
	entries, fetchErr := fetcher.FindCommitmentEntries(
		ctx, artifact.PREGrantCommitmentSchemaID, splitID)
	if fetchErr != nil {
		t.Fatalf("fetcher.FindCommitmentEntries: %v", fetchErr)
	}
	if len(entries) != 2 {
		t.Fatalf("fetcher returned %d entries, want 2 — SDK would NOT detect equivocation",
			len(entries))
	}
	simulated := &artifact.CommitmentEquivocationError{
		SchemaID: artifact.PREGrantCommitmentSchemaID,
		SplitID:  splitID,
		Entries:  entries,
	}
	if !errors.Is(simulated, artifact.ErrCommitmentEquivocation) {
		t.Errorf("simulated SDK error does not satisfy errors.Is(ErrCommitmentEquivocation)")
	}
	if len(simulated.Entries) != 2 {
		t.Errorf("simulated SDK error carries %d entries, want 2",
			len(simulated.Entries))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// mutateCommitmentPayload returns a copy of payloadA with the
// commitment_bytes_hex field altered (one byte flipped) so the
// resulting canonical_hash is distinct. The SplitID embedded in
// the wire bytes is preserved — the equivocation signature is
// "different commitment, same SplitID".
func mutateCommitmentPayload(t *testing.T, payloadA []byte) []byte {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(payloadA, &env); err != nil {
		t.Fatalf("unmarshal payloadA: %v", err)
	}
	hexStr, ok := env["commitment_bytes_hex"].(string)
	if !ok || len(hexStr) < 4 {
		t.Fatal("payloadA missing commitment_bytes_hex")
	}
	mutated := []byte(hexStr)
	if mutated[len(mutated)-1] == '0' {
		mutated[len(mutated)-1] = '1'
	} else {
		mutated[len(mutated)-1] = '0'
	}
	env["commitment_bytes_hex"] = string(mutated)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal mutated payload: %v", err)
	}
	return out
}

// countSplitIDRows returns how many rows commitment_split_id has
// for the supplied (schema_id, split_id) tuple.
func countSplitIDRows(
	t *testing.T, ctx context.Context, pool any,
	schemaID string, splitID [32]byte,
) int {
	t.Helper()
	type pgxPoolish interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgxRow
	}
	if p, ok := pool.(pgxPoolish); ok {
		var n int
		if err := p.QueryRow(ctx, `
			SELECT COUNT(*) FROM commitment_split_id
			WHERE schema_id = $1 AND split_id = $2`,
			schemaID, splitID[:]).Scan(&n); err != nil {
			t.Fatalf("count split_id: %v", err)
		}
		return n
	}
	t.Fatal("pool type does not match expected pgxpool shape")
	return -1
}

// pgxRow abstracts pgx.Row's Scan method without importing pgx.
type pgxRow interface {
	Scan(dest ...any) error
}
