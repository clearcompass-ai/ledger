/*
FILE PATH: api/commitments_test.go

End-to-end coverage for the /v1/commitments/by-split-id handler
(NewCommitmentLookupHandler) under the Pure CQRS principle.

Two layers:

 1. Handler-with-mock-fetcher
    Exercises the request validation + response-shape contract
    against a stub types.CommitmentFetcher. No Badger, no
    gossipstore — pure handler logic.

 2. Handler→BadgerCommitmentFetcher→BadgerStore
    Wires the production fetcher against an in-memory BadgerStore
    populated via the gossipstore.WriteEntryLookupEntry path the
    sequencer uses. Asserts the full CQRS pipeline serves
    /by-split-id without touching Postgres.

The integration layer is the load-bearing assertion: it proves
that with the 0x0C projection populated, the handler returns
fully-formed CommitmentLookupResponse JSON without any Postgres
fetch — the architectural goal of P8 + Alignment 4.
*/
package api_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/crypto/escrow"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/gossipstore"
)

// ─────────────────────────────────────────────────────────────────────
// Layer 1: handler with mock fetcher
// ─────────────────────────────────────────────────────────────────────

// stubFetcher satisfies types.CommitmentFetcher for handler tests
// without bringing up Badger.
type stubFetcher struct {
	rows []*types.EntryWithMetadata
	err  error
}

func (s *stubFetcher) FindCommitmentEntries(
	schemaID string, splitID [32]byte,
) ([]*types.EntryWithMetadata, error) {
	return s.rows, s.err
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func validHex32() string {
	return strings.Repeat("ab", 32) // 64 chars = 32 bytes
}

func newCommitmentTestServer(h http.HandlerFunc) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/commitments/by-split-id/{schema_id}/{hex}", h)
	return httptest.NewServer(mux)
}

func TestNewCommitmentLookupHandler_PanicsOnNilDeps(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil deps")
		}
	}()
	_ = api.NewCommitmentLookupHandler(nil)
}

func TestNewCommitmentLookupHandler_PanicsOnNilFetcher(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil fetcher")
		}
	}()
	_ = api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Logger: discardLog(),
	})
}

func TestCommitmentLookupHandler_RejectsUnsupportedSchema(t *testing.T) {
	h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Fetcher: &stubFetcher{},
		Logger:  discardLog(),
	})
	srv := newCommitmentTestServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/not-a-real-schema/" + validHex32())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCommitmentLookupHandler_RejectsBadHexLength(t *testing.T) {
	h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Fetcher: &stubFetcher{},
		Logger:  discardLog(),
	})
	srv := newCommitmentTestServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/" +
		artifact.PREGrantCommitmentSchemaID + "/abcd")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (short hex)", resp.StatusCode)
	}
}

func TestCommitmentLookupHandler_RejectsBadHexEncoding(t *testing.T) {
	h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Fetcher: &stubFetcher{},
		Logger:  discardLog(),
	})
	srv := newCommitmentTestServer(h)
	defer srv.Close()

	bad := strings.Repeat("zz", 32) // 64 chars but not hex
	resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/" +
		artifact.PREGrantCommitmentSchemaID + "/" + bad)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (bad hex)", resp.StatusCode)
	}
}

func TestCommitmentLookupHandler_NoMatch_Returns404(t *testing.T) {
	h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Fetcher: &stubFetcher{rows: nil}, // empty
		Logger:  discardLog(),
	})
	srv := newCommitmentTestServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/" +
		artifact.PREGrantCommitmentSchemaID + "/" + validHex32())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (empty result)", resp.StatusCode)
	}
}

func TestCommitmentLookupHandler_FetcherError_Returns500(t *testing.T) {
	h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Fetcher: &stubFetcher{err: errors.New("boom")},
		Logger:  discardLog(),
	})
	srv := newCommitmentTestServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/" +
		artifact.PREGrantCommitmentSchemaID + "/" + validHex32())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestCommitmentLookupHandler_SingleRow_Returns200JSON(t *testing.T) {
	canonical := []byte("canonical-bytes-payload")
	logTime := time.Date(2026, 4, 25, 14, 32, 0, 0, time.UTC)

	h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Fetcher: &stubFetcher{rows: []*types.EntryWithMetadata{{
			CanonicalBytes: canonical,
			LogTime:        logTime,
			Position:       types.LogPosition{Sequence: 7234891, LogDID: "did:web:ledger"},
		}}},
		Logger: discardLog(),
	})
	srv := newCommitmentTestServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/" +
		artifact.PREGrantCommitmentSchemaID + "/" + validHex32())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var out api.CommitmentLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(out.Entries))
	}
	if out.Entries[0].CanonicalBytesHex != hex.EncodeToString(canonical) {
		t.Errorf("CanonicalBytesHex drift")
	}
	if out.Entries[0].Position.SequenceNumber != 7234891 {
		t.Errorf("Sequence = %d, want 7234891", out.Entries[0].Position.SequenceNumber)
	}
	if out.Entries[0].Position.LogDID != "did:web:ledger" {
		t.Errorf("LogDID = %q", out.Entries[0].Position.LogDID)
	}
}

func TestCommitmentLookupHandler_AllowsBothCommitmentSchemas(t *testing.T) {
	// Both v7.75 commitment schemas must be accepted on the path.
	for _, schema := range []string{
		artifact.PREGrantCommitmentSchemaID,
		escrow.EscrowSplitCommitmentSchemaID,
	} {
		h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
			Fetcher: &stubFetcher{}, // empty → 404
			Logger:  discardLog(),
		})
		srv := newCommitmentTestServer(h)
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/" +
			schema + "/" + validHex32())
		if err != nil {
			t.Fatalf("schema=%s: %v", schema, err)
		}
		_ = resp.Body.Close()
		// 404 (empty) — schema accepted; not 400 (which would
		// indicate the schema was rejected).
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("schema=%s: status = %d, want 404 (allowed but empty)",
				schema, resp.StatusCode)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Layer 2: end-to-end handler→BadgerCommitmentFetcher→BadgerStore
// ─────────────────────────────────────────────────────────────────────

// inMemoryBadgerStore opens a hermetic in-memory BadgerStore for
// the end-to-end test.
func inMemoryBadgerStore(t *testing.T) *gossipstore.BadgerStore {
	t.Helper()
	opts := badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("badger.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := gossipstore.New(gossipstore.Config{DB: db, GCInterval: -1})
	if err != nil {
		t.Fatalf("gossipstore.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close(context.Background()) })
	return st
}

// TestCommitmentLookup_EndToEnd_BadgerCQRS pins the architectural
// goal: a single GET against /v1/commitments/by-split-id is
// served entirely from the Badger 0x0C projection — no Postgres
// touch. The sequencer's write-time output (via WriteEntryLookupEntry)
// is the same path the production sequencer takes.
func TestCommitmentLookup_EndToEnd_BadgerCQRS(t *testing.T) {
	st := inMemoryBadgerStore(t)
	ctx := context.Background()

	// Sequencer would write this row at Phase 2 commit-time.
	splitID := [32]byte{0x12, 0x34}
	canonical := []byte("end-to-end-canonical-bytes")
	logTime := time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC)
	if err := st.WriteEntryLookupEntry(ctx,
		artifact.PREGrantCommitmentSchemaID, splitID, 42,
		gossipstore.EntryLookupIndexEntry{
			CanonicalBytes: canonical,
			LogTimeMicros:  logTime.UnixMicro(),
			LogDID:         "did:web:ledger.example",
		}); err != nil {
		t.Fatalf("WriteEntryLookupEntry: %v", err)
	}

	// Wire the production fetcher and handler.
	fetcher := gossipstore.NewBadgerCommitmentFetcher(st)
	h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Fetcher: fetcher,
		Logger:  discardLog(),
	})
	srv := newCommitmentTestServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/" +
		artifact.PREGrantCommitmentSchemaID + "/" + hex.EncodeToString(splitID[:]))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var out api.CommitmentLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(out.Entries))
	}
	if out.Entries[0].CanonicalBytesHex != hex.EncodeToString(canonical) {
		t.Errorf("CanonicalBytesHex drift")
	}
	if out.Entries[0].Position.SequenceNumber != 42 {
		t.Errorf("Sequence = %d, want 42", out.Entries[0].Position.SequenceNumber)
	}
	if out.Entries[0].Position.LogDID != "did:web:ledger.example" {
		t.Errorf("LogDID = %q, want did:web:ledger.example",
			out.Entries[0].Position.LogDID)
	}
	parsed, err := time.Parse(time.RFC3339Nano, out.Entries[0].LogTime)
	if err != nil {
		t.Fatalf("parse LogTime: %v", err)
	}
	if !parsed.Equal(logTime) {
		t.Errorf("LogTime = %v, want %v", parsed, logTime)
	}
}

// TestCommitmentLookup_EndToEnd_EquivocationCase pins the
// Decision-4 contract: when the 0x0C projection holds two entries
// at the same (schema, split_id), the handler returns 200 OK with
// both entries in seq-ascending order (the SDK consumer surfaces
// the equivocation via *CommitmentEquivocationError).
func TestCommitmentLookup_EndToEnd_EquivocationCase(t *testing.T) {
	st := inMemoryBadgerStore(t)
	ctx := context.Background()

	splitID := [32]byte{0xAA, 0xBB}
	for _, row := range []struct {
		seq    uint64
		bytes  []byte
		micros int64
	}{
		{99, []byte("entry-99"), 99000},
		{7, []byte("entry-7"), 7000},
	} {
		if err := st.WriteEntryLookupEntry(ctx,
			artifact.PREGrantCommitmentSchemaID, splitID, row.seq,
			gossipstore.EntryLookupIndexEntry{
				CanonicalBytes: row.bytes,
				LogTimeMicros:  row.micros,
				LogDID:         "did:web:ledger",
			}); err != nil {
			t.Fatalf("Write seq=%d: %v", row.seq, err)
		}
	}

	h := api.NewCommitmentLookupHandler(&api.CryptographicCommitmentDeps{
		Fetcher: gossipstore.NewBadgerCommitmentFetcher(st),
		Logger:  discardLog(),
	})
	srv := newCommitmentTestServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/commitments/by-split-id/" +
		artifact.PREGrantCommitmentSchemaID + "/" + hex.EncodeToString(splitID[:]))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var out api.CommitmentLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Entries) != 2 {
		t.Fatalf("entries = %d, want 2 (equivocation case)", len(out.Entries))
	}
	// Seq-ascending order verified.
	if out.Entries[0].Position.SequenceNumber != 7 {
		t.Errorf("got[0].Sequence = %d, want 7",
			out.Entries[0].Position.SequenceNumber)
	}
	if out.Entries[1].Position.SequenceNumber != 99 {
		t.Errorf("got[1].Sequence = %d, want 99",
			out.Entries[1].Position.SequenceNumber)
	}
}
