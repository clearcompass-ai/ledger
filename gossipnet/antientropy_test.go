/*
FILE PATH: gossipnet/antientropy_test.go

Catchup-loop tests for AntiEntropy. Uses the SDK's gossip.Client
directly against a stub HTTP server so we exercise the wire
format end to end (rather than mocking the Client interface and
losing coverage of the wire path).
*/
package gossipnet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkcosign "github.com/clearcompass-ai/ortholog-sdk/crypto/cosign"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	sdkgossip "github.com/clearcompass-ai/ortholog-sdk/gossip"
)

// stubFeedServer serves the SDK's /v1/gossip/since wire format
// against a fixed list of events. Each call increments calls
// so tests can assert how many times the loop polled.
func stubFeedServer(t *testing.T, events []sdkgossip.SignedEvent) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// Parse since param. The SDK FeedClient.Since uses
		// "lamport" as the query name (per feed_client.go).
		var since uint64
		if s := r.URL.Query().Get("lamport"); s != "" {
			if v, err := strconv.ParseUint(s, 10, 64); err == nil {
				since = v
			}
		}
		filtered := []sdkgossip.SignedEvent{}
		for _, ev := range events {
			if ev.LamportTime > since {
				filtered = append(filtered, ev)
			}
		}
		var next uint64
		if len(filtered) > 0 {
			next = filtered[len(filtered)-1].LamportTime
		}
		resp := sdkgossip.FeedListResponse{
			Events:      filtered,
			NextLamport: next,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return srv, &calls
}

// signSTH signs a stubEvent for a fixture DID under cosign + the
// supplied prev/lamport. Mirrors the gossipstore test helper.
func signSTH(t *testing.T, kp *did.DIDKeyPairSecp256k1, prev [32]byte, lamport uint64, data string) sdkgossip.SignedEvent {
	t.Helper()
	signer := sdkcosign.NewECDSAWitnessSigner(kp.PrivateKey)
	se, err := sdkgossip.Sign(context.Background(),
		stubAEEvent{kind: sdkgossip.KindCosignedTreeHead, data: data},
		signer, aeNetworkID(), kp.DID, prev, lamport)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return se
}

// stubAEEvent — minimal Event impl. Same shape as gossipstore's
// stubEvent but local to this test file to avoid cross-package
// test imports.
type stubAEEvent struct {
	kind sdkgossip.Kind
	data string
}

func (s stubAEEvent) Kind() sdkgossip.Kind { return s.kind }
func (s stubAEEvent) Bindings() [][32]byte { return nil }
func (s stubAEEvent) Validate() error      { return nil }
func (s stubAEEvent) CanonicalBytes() []byte {
	out := []byte(s.kind)
	out = append(out, '|')
	return append(out, s.data...)
}
func (s stubAEEvent) EncodeWireBody() (json.RawMessage, error) {
	return json.RawMessage(`{"data":"` + s.data + `"}`), nil
}

func aeNetworkID() sdkcosign.NetworkID {
	var n sdkcosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// TestAntiEntropy_PullsAndAppendsFromPeer exercises the happy path:
// stub peer serves 3 events; the loop runs one tick; all 3 land
// in the local store.
func TestAntiEntropy_PullsAndAppendsFromPeer(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}

	// Build 3 events.
	prev := [32]byte{}
	events := make([]sdkgossip.SignedEvent, 0, 3)
	for i := uint64(1); i <= 3; i++ {
		ev := signSTH(t, kp, prev, i, "x")
		events = append(events, ev)
		id, _ := sdkgossip.EventIDOf(ev)
		prev = id
	}

	srv, calls := stubFeedServer(t, events)
	defer srv.Close()

	store := sdkgossip.NewInMemoryStore()
	ae, err := NewAntiEntropy(AntiEntropyConfig{
		Store:    store,
		Peers:    []AntiEntropyPeer{{DID: kp.DID, BaseURL: srv.URL}},
		Interval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = ae.Run(ctx)

	if calls.Load() < 1 {
		t.Errorf("calls = %d, want >= 1", calls.Load())
	}
	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 3 {
		t.Errorf("EventCount = %d, want 3", stats.EventCount)
	}
}

// TestAntiEntropy_NoPeers_ReturnsImmediately confirms the disabled
// path: empty peers means Run returns nil immediately.
func TestAntiEntropy_NoPeers_ReturnsImmediately(t *testing.T) {
	store := sdkgossip.NewInMemoryStore()
	ae, err := NewAntiEntropy(AntiEntropyConfig{
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := ae.Run(ctx); err != nil {
		t.Errorf("err = %v, want nil (no peers)", err)
	}
}

// TestAntiEntropy_RejectsMissingPeerFields confirms construction
// validation: a peer with empty DID or BaseURL is a config bug
// surfacing at boot.
func TestAntiEntropy_RejectsMissingPeerFields(t *testing.T) {
	store := sdkgossip.NewInMemoryStore()
	_, err := NewAntiEntropy(AntiEntropyConfig{
		Store: store,
		Peers: []AntiEntropyPeer{{DID: "did:web:x"}}, // missing URL
	})
	if err == nil || !strings.Contains(err.Error(), "BaseURL") {
		t.Errorf("err = %v, want BaseURL-required", err)
	}
}

// TestAntiEntropy_HonorsContextCancel confirms Run unblocks on
// ctx cancellation between ticks.
func TestAntiEntropy_HonorsContextCancel(t *testing.T) {
	srv, _ := stubFeedServer(t, nil)
	defer srv.Close()

	store := sdkgossip.NewInMemoryStore()
	ae, err := NewAntiEntropy(AntiEntropyConfig{
		Store:    store,
		Peers:    []AntiEntropyPeer{{DID: "did:web:peer", BaseURL: srv.URL}},
		Interval: 1 * time.Hour, // long; we cancel before this fires
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ae.Run(ctx) }()
	cancel()
	select {
	case rerr := <-done:
		if !errors.Is(rerr, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", rerr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return on cancel")
	}
}

// hexDecodeForTest helps inspect signature bytes when debugging.
func hexDecodeForTest(s string) []byte {
	out, _ := hex.DecodeString(s)
	return out
}
