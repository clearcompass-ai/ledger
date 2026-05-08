/*
FILE PATH: lifecycle/archive_reader_test.go

DESCRIPTION:

	Tier-3 alignment tests for the SDK-backed HTTP wiring inside
	lifecycle/archive_reader.go. Pre-fix the bare http.Client gave
	no 503-Retry-After honoring; post-fix sdklog.DefaultClient
	delivers it.

	Also pins the mirrored Tier-2 BUG #3 detect-and-error behavior
	for fetchBytes — oversize archive bodies surface as typed errors
	instead of being silently truncated to ingest failures
	downstream.
*/
package lifecycle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fixtureReader returns a fresh ArchiveReader. The SDK-wired client
// inside survives across calls.
func fixtureReader(t *testing.T) *ArchiveReader {
	t.Helper()
	return NewArchiveReader(nil)
}

// 503 → 200 round-trip succeeds transparently because the underlying
// client is sdklog.DefaultClient (RetryAfterRoundTripper).
func TestArchiveReader_FetchBytes_RetriesOn503(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("after-retry"))
	}))
	defer srv.Close()

	r := fixtureReader(t)
	got, err := r.fetchBytes(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchBytes: %v", err)
	}
	if string(got) != "after-retry" {
		t.Errorf("body: got %q, want %q", got, "after-retry")
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("expected at least 2 attempts (503 → 200), got %d", got)
	}
}

// Tier-2 BUG #3 mirror: a body larger than the 2 MiB archive cap is
// surfaced as a typed error rather than silently truncated.
func TestArchiveReader_FetchBytes_OversizeErrors(t *testing.T) {
	const cap = 2 << 20
	huge := make([]byte, cap+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(huge)
	}))
	defer srv.Close()

	r := fixtureReader(t)
	_, err := r.fetchBytes(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for oversize body")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should mention size cap: %v", err)
	}
}

// Boundary: a body exactly at the cap is accepted.
func TestArchiveReader_FetchBytes_AtCapAccepted(t *testing.T) {
	const cap = 2 << 20
	body := make([]byte, cap)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	r := fixtureReader(t)
	got, err := r.fetchBytes(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("body at exact cap should be accepted: %v", err)
	}
	if len(got) != cap {
		t.Errorf("len = %d, want %d", len(got), cap)
	}
}

// Non-200, non-503 statuses propagate as errors immediately.
func TestArchiveReader_FetchBytes_404Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := fixtureReader(t)
	_, err := r.fetchBytes(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status: %v", err)
	}
}
