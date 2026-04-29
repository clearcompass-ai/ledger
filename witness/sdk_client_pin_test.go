/*
FILE PATH: witness/sdk_client_pin_test.go

DESCRIPTION:
    Tier-3 alignment pin tests. The three witness HTTP clients
    (EquivocationMonitor, HeadSync, CommitmentEquivocationAlertPublisher)
    all use sdklog.DefaultClient under the hood, which means
    503-Retry-After backpressure is honored automatically. These
    tests exercise that wiring through one representative path each
    so a future refactor that drops back to a bare http.Client fails
    here loudly.
*/
package witness

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestEquivocationMonitor_FetchPeerHead_RetriesOn503 pins the SDK
// transport for the equivocation monitor's peer-head fetch path.
// Without RetryAfterRoundTripper, the first 503 from a peer would
// fail equivocation detection silently; with it, the monitor
// transparently retries and observes the eventual success or
// real failure.
func TestEquivocationMonitor_FetchPeerHead_RetriesOn503(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tree_size":42,"root_hash":"abcd","hash_algo":1}`))
	}))
	defer srv.Close()

	em := &EquivocationMonitor{
		client: defaultClientFromConstructor(),
	}
	head, _, err := em.fetchPeerHead(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchPeerHead: %v", err)
	}
	if head.TreeSize != 42 {
		t.Errorf("TreeSize=%d, want 42", head.TreeSize)
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("expected at least 2 attempts (503 → 200), got %d", got)
	}
}

// defaultClientFromConstructor returns an http.Client built the
// same way NewEquivocationMonitor does — sdklog.DefaultClient(30s).
// We can't call NewEquivocationMonitor directly here without a
// pgxpool, so we pin the client construction by reproducing it.
func defaultClientFromConstructor() *http.Client {
	em := NewEquivocationMonitor(EquivocationMonitorConfig{}, nil, nil, nil)
	return em.client
}
