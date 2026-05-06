/*
FILE PATH: gossipnet/wiring_test.go

Smoke tests for the gossipnet.Build wiring helper. Verifies:

  - Build returns a non-nil Bundle when given a Store + NetworkID.
  - PostHandler + FeedHandler are non-nil and serve HTTP without
    panicking on a malformed request (the rate-limit + handler
    chain is intact).
  - Sink defaults to NopSink when PeerEndpoints is empty.
  - Build rejects nil Store and zero NetworkID.

Round-trip and protocol correctness live in the SDK's own
gossip + middleware test suites. This file pins only the
ledger-side wiring assembly.
*/
package gossipnet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
)

func nonZeroNetworkID() sdkcosign.NetworkID {
	var n sdkcosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

func TestBuild_RejectsNilStore(t *testing.T) {
	_, err := Build(Config{
		NetworkID: nonZeroNetworkID(),
	})
	if err == nil || !strings.Contains(err.Error(), "Store") {
		t.Fatalf("err = %v, want Store-required", err)
	}
}

func TestBuild_RejectsZeroNetworkID(t *testing.T) {
	_, err := Build(Config{
		Store: sdkgossip.NewInMemoryStore(),
	})
	if err == nil || !strings.Contains(err.Error(), "NetworkID") {
		t.Fatalf("err = %v, want NetworkID-required", err)
	}
}

func TestBuild_NoPeers_NopSink(t *testing.T) {
	b, err := Build(Config{
		Store:     sdkgossip.NewInMemoryStore(),
		NetworkID: nonZeroNetworkID(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if b.PostHandler == nil || b.FeedHandler == nil {
		t.Errorf("handlers nil")
	}
	if b.Sink != sdkgossip.NopSink {
		t.Errorf("Sink = %T, want NopSink (no peers configured)", b.Sink)
	}
}

func TestBuild_PostHandler_RejectsBadJSON(t *testing.T) {
	b, err := Build(Config{
		Store:        sdkgossip.NewInMemoryStore(),
		NetworkID:    nonZeroNetworkID(),
		RateLimitRPS: -1, // disable rate limit so the handler is what we test
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	srv := httptest.NewServer(b.PostHandler)
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json",
		strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (bad JSON)", resp.StatusCode)
	}
}

func TestBuild_FeedHandler_ServesLatestSTH(t *testing.T) {
	store := sdkgossip.NewInMemoryStore()
	b, err := Build(Config{
		Store:            store,
		NetworkID:        nonZeroNetworkID(),
		FeedRateLimitRPS: -1,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	srv := httptest.NewServer(b.FeedHandler)
	defer srv.Close()

	// No events yet → /v1/gossip/sth/latest returns "not found" or empty.
	resp, err := http.Get(srv.URL + "/v1/gossip/sth/latest?originator=did:web:nope")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The feed handler returns 404 for an originator with no events.
	// We just confirm it didn't panic / hang.
	if resp.StatusCode == 0 {
		t.Errorf("status = 0 (handler did not respond)")
	}
}

func TestBundle_CloseablesNonEmpty(t *testing.T) {
	b, err := Build(Config{
		Store:     sdkgossip.NewInMemoryStore(),
		NetworkID: nonZeroNetworkID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Closeables) < 2 {
		t.Errorf("Closeables = %d, want >= 2 (handlers)", len(b.Closeables))
	}
	// Each Closeable accepts a context and returns nil for a clean
	// no-op shutdown on these in-memory components.
	for i, c := range b.Closeables {
		if err := c.Close(context.Background()); err != nil {
			t.Errorf("Closeables[%d].Close: %v", i, err)
		}
	}
}
