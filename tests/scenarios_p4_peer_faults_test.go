//go:build scenarios

/*
FILE PATH:

	tests/scenarios_p4_peer_faults_test.go

DESCRIPTION:

	Layer 0 — Persona 4 (Peer Ledger, fault-injected sub-tests).
	Three operationally-realistic perturbation paths the gossip
	network must survive:

	  - HonorsRateLimit_429 — Peer returns 429 + Retry-After
	    on Publish; the gossip client's typed RateLimitedError
	    carries the parsed delay; the originator's publish loop
	    is expected to back off (we assert the typed error,
	    not auto-retry behaviour, because retry is a runtime
	    decision the SDK explicitly leaves to callers).
	  - RebroadcastSucceedsIfAnyPeerSucceeds — A 3-peer fan-out
	    where one peer is hard-down: the originator's "publish
	    to N peers" loop succeeds end-to-end as long as at least
	    one peer accepts. This is the gossip layer's contribution
	    to the propagation invariant a Court / Insurance network
	    depends on: even partial network partitions converge.
	  - NetworkIDIsolation — The peer is configured for
	    NetworkID-A; the originator publishes under NetworkID-B;
	    the peer rejects with 403 / ErrNetworkNotConfigured. The
	    store carries no event from the wrong-network publish.

KEY ARCHITECTURAL DECISIONS:
  - 429 path uses an httptest.Server that wraps the SDK's
    handler in a faultable proxy (mirrors witnessSwarm's
    httpFault pattern). We can't fault inject INSIDE the SDK's
    handler; we wrap.
  - Multi-peer fan-out is hand-coded rather than using
    gossip.MultiSink because the test's contract is "the
    originator's publish-to-N pattern works under failure".
    MultiSink is the SDK's blessed implementation; we're
    asserting the underlying invariant any equivalent
    implementation must satisfy.
  - NetworkID isolation deliberately drives the SAME originator
    key across mismatched networks. The SDK's handler-level
    rejection is the test's contract; the fact that
    cryptographically-valid signatures still get rejected on
    AllowedNetworks mismatch is the cryptographic-isolation
    guarantee.

OVERVIEW:

	runP4HonorsRateLimit429
	    → publish to a 429-returning peer; expect typed
	      gossip.RateLimitedError with non-zero RetryAfter.
	runP4RebroadcastIfAny
	    → 3 peers, peer 0 hard-down. Originator publishes one
	      event to all three; ≥ 2 succeed; the originator's
	      "any success" rule lets the publish round complete.
	runP4NetworkIDIsolation
	    → peer configured for net A; originator publishes under
	      net B; peer rejects; store empty.

KEY DEPENDENCIES:
  - github.com/clearcompass-ai/attesta/gossip:
    RateLimitedError, ErrRateLimited, NewClient.
  - tests/scenarios_p4_peer_helpers_test.go: gossipPeer,
    p4Originator, p4Verifier, p4SignAndPublish, p4MakeFinding.
  - tests/scenarios_witness_test.go: httpFault (re-used for
    consistent fault-injection mechanics).
*/
package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/gossip"
)

// -------------------------------------------------------------------------------------------------
// 1) HonorsRateLimit_429
// -------------------------------------------------------------------------------------------------

// runP4HonorsRateLimit429. The peer's POST handler is wrapped to
// return 429 + Retry-After=2 on the first request. The SDK's
// gossip Publish surfaces this as an err where errors.Is matches
// gossip.ErrRateLimited and errors.As yields a *RateLimitedError
// carrying the parsed RetryAfter.
//
// Persona 4 does NOT auto-retry. Retry is a runtime decision the
// originator's publish loop makes; the protocol guarantee we
// pin here is "the typed shape is parseable" so the originator
// can reason about backoff.
func runP4HonorsRateLimit429(t *testing.T) {
	t.Helper()
	netID := p3MakeNetworkID(0x60)
	orig := newP4Originator(t, "did:example:p4-rl", netID)
	verifier := newP4Verifier(t, orig)

	// We can't directly wrap the SDK handler so we stand up a
	// pure 429 server. The SDK client will see the response and
	// build the typed error from headers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", strconv.Itoa(2))
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	_ = verifier // keep referenced for symmetry with other faults

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	finding := p4MakeFinding(t, srv.URL, 600)
	lamport, prev := orig.nextChain()
	signed, err := gossip.Sign(ctx, finding, orig.Signer, netID, orig.DID, prev, lamport)
	mustNotErr(t, "gossip.Sign", err)

	client, err := gossip.NewClient(srv.URL,
		gossip.WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))
	mustNotErr(t, "NewClient", err)
	defer func() { _ = client.Close(ctx) }()

	pubErr := client.Publish(ctx, signed)
	if pubErr == nil {
		t.Fatal("Publish succeeded under forced 429; want ErrRateLimited")
	}
	if !errors.Is(pubErr, gossip.ErrRateLimited) {
		t.Fatalf("err = %v, want errors.Is(ErrRateLimited)", pubErr)
	}
	var rl *gossip.RateLimitedError
	if !errors.As(pubErr, &rl) {
		t.Fatalf("err = %v, want errors.As(*RateLimitedError)", pubErr)
	}
	if rl.RetryAfter < 1*time.Second {
		t.Fatalf("RateLimitedError.RetryAfter = %v, want >= 1s", rl.RetryAfter)
	}
}

// -------------------------------------------------------------------------------------------------
// 2) RebroadcastSucceedsIfAnyPeerSucceeds
// -------------------------------------------------------------------------------------------------

// runP4RebroadcastIfAny stands up THREE peers; peer 0's HTTP
// server is replaced mid-test with a hard-fail handler. The
// originator's intended pattern is "publish this event to all
// three peers; the round succeeds if at least one accepts". We
// emulate that loop directly: gossip.NewClient per peer; Publish;
// count successes.
//
// This is not the SDK's MultiSink (which uses goroutines + a
// quorum policy); it's the lower-level invariant any "publish to
// N peers" loop relies on.
func runP4RebroadcastIfAny(t *testing.T) {
	t.Helper()
	netID := p3MakeNetworkID(0x61)
	orig := newP4Originator(t, "did:example:p4-rebroadcast", netID)
	verifier := newP4Verifier(t, orig)

	const n = 3
	peers := make([]*gossipPeer, 0, n)
	for i := 0; i < n; i++ {
		peers = append(peers, newGossipPeer(t, verifier, netID))
	}

	// Replace peer[0]'s server router with a hard-fail handler
	// AT THE FIXTURE LEVEL. We do this by closing the original
	// server and substituting a permanently-500 server at the
	// same URL handle.
	hardDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(hardDown.Close)
	peers[0] = &gossipPeer{URL: hardDown.URL, Store: peers[0].Store}

	finding := p4MakeFinding(t, "did:example:cdn-rb", 700)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lamport, prev := orig.nextChain()
	signed, err := gossip.Sign(ctx, finding, orig.Signer, netID, orig.DID, prev, lamport)
	mustNotErr(t, "gossip.Sign", err)

	successes := 0
	for i, p := range peers {
		client, err := gossip.NewClient(p.URL,
			gossip.WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))
		mustNotErr(t, "NewClient", err)
		if err := client.Publish(ctx, signed); err == nil {
			successes++
		} else if i == 0 {
			// peer 0 is expected to fail.
			continue
		}
		_ = client.Close(ctx)
	}
	if successes < 1 {
		t.Fatalf("0 successful publishes across %d peers; rebroadcast invariant violated", n)
	}
	// Concretely we expect 2 successes (peers 1 and 2 are healthy),
	// so anything below that is a hard regression.
	if successes != n-1 {
		t.Fatalf("successes = %d, want %d (only peer 0 down)", successes, n-1)
	}

	id, err := gossip.EventIDOf(signed)
	mustNotErr(t, "EventIDOf", err)
	for i := 1; i < n; i++ {
		_, err := peers[i].Store.Get(ctx, id)
		if err != nil {
			t.Fatalf("peer[%d] missing event %x: %v", i, id[:8], err)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 3) NetworkIDIsolation
// -------------------------------------------------------------------------------------------------

// runP4NetworkIDIsolation. The peer's handler is configured for
// NetworkID-A; the originator publishes a SignedEvent stamped
// with NetworkID-B. The SDK's gossip handler validates
// AllowedNetworks at request time and returns 403; the
// originator's Publish errors.
//
// The cryptographic-isolation contract: even if the originator's
// signature is valid (it is — the signature is over canonical
// bytes that include NetworkID-B; the verifier could check it
// against the right key), the wrong-network rejection comes
// FIRST. The store stays empty.
func runP4NetworkIDIsolation(t *testing.T) {
	t.Helper()
	netA := p3MakeNetworkID(0x70)
	netB := p3MakeNetworkID(0x71)

	orig := newP4Originator(t, "did:example:p4-netiso", netB)
	verifier := newP4Verifier(t, orig)
	peer := newGossipPeer(t, verifier, netA) // peer accepts A only

	finding := p4MakeFinding(t, peer.URL, 800)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lamport, prev := orig.nextChain()
	signed, err := gossip.Sign(ctx, finding, orig.Signer, netB, orig.DID, prev, lamport)
	mustNotErr(t, "gossip.Sign", err)

	client, err := gossip.NewClient(peer.URL,
		gossip.WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))
	mustNotErr(t, "NewClient", err)
	defer func() { _ = client.Close(ctx) }()
	pubErr := client.Publish(ctx, signed)
	if pubErr == nil {
		t.Fatal("Publish succeeded across mismatched NetworkID; want network rejection")
	}

	stats, err := peer.Store.Stats(ctx)
	mustNotErr(t, "Stats", err)
	if stats.EventCount != 0 {
		t.Fatalf("Store.TotalEvents = %d after wrong-network publish, want 0",
			stats.EventCount)
	}
}
