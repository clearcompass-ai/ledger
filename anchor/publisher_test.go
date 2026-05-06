/*
FILE PATH: anchor/publisher_test.go

DESCRIPTION:

	Tier-3 alignment tests for the SDK-backed outbound HTTP wiring
	inside anchor/publisher.go. The previous bare http.Client gave
	no connection pooling and no 503-Retry-After backpressure
	honoring; SubmitViaHTTP and Publisher now use sdklog.DefaultClient
	so WAL-pressure 503s from the ledger's own admission endpoint
	are absorbed locally rather than turning into hard submit
	failures.

	These tests pin the new behavior:
	  - SubmitViaHTTP succeeds when the target returns 503-then-202.
	  - SubmitViaHTTP propagates a non-202, non-503 status as an
	    error (no spurious retry on, e.g., 422).
	  - SubmitViaHTTP propagates an entry whose canonical bytes
	    round-trip correctly even after a retry.
*/
package anchor

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// fixtureSignedEntry builds a minimal signed entry suitable for
// envelope.Serialize. The signature itself is not verified by the
// SubmitViaHTTP path (the server is fake); we just need a serializable
// entry.
func fixtureSignedEntry(t *testing.T, payload []byte) *envelope.Entry {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:   "did:test:signer",
		Destination: "did:test:log",
		EventTime:   1,
	}
	entry, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     bytes.Repeat([]byte{0x01}, 64),
	}}
	return entry
}

// Tier-3 BUG #2/#6 alignment: SubmitViaHTTP uses sdklog.DefaultClient,
// which wraps the transport with RetryAfterRoundTripper. A 503 with
// Retry-After: 1 followed by a 202 must succeed transparently — the
// caller never sees the 503.
func TestSubmitViaHTTP_RetriesOn503(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// Drain body so the second attempt's payload is observed.
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			http.Error(w, "empty body on retry", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	submit := SubmitViaHTTP(srv.URL)
	entry := fixtureSignedEntry(t, []byte("retry-on-503"))
	if err := submit(entry); err != nil {
		t.Fatalf("SubmitViaHTTP: %v", err)
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("expected at least 2 attempts (503 → 202), got %d", got)
	}
}

// Non-503, non-202 statuses are returned as errors — no retry.
// 422 (validation failure) is the canonical "client error, do not
// retry" status.
func TestSubmitViaHTTP_DoesNotRetry422(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("bad entry"))
	}))
	defer srv.Close()

	submit := SubmitViaHTTP(srv.URL)
	entry := fixtureSignedEntry(t, []byte("no-retry-on-422"))
	err := submit(entry)
	if err == nil {
		t.Fatal("expected error on 422")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 attempt for 422, got %d", got)
	}
}

// 202 happy path: the request body delivered to the server matches
// envelope.Serialize(entry) byte-for-byte. Pre-fix-regression guard.
func TestSubmitViaHTTP_HappyPath_BytesMatch(t *testing.T) {
	entry := fixtureSignedEntry(t, []byte("happy-bytes"))
	wantBytes, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("envelope.Serialize: %v", err)
	}

	var seen []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	submit := SubmitViaHTTP(srv.URL)
	if err := submit(entry); err != nil {
		t.Fatalf("SubmitViaHTTP: %v", err)
	}
	if !bytes.Equal(seen, wantBytes) {
		t.Errorf("server received %d bytes, want %d (envelope.Serialize result)",
			len(seen), len(wantBytes))
	}
}
