/*
FILE PATH: gossipnet/equivocation_publisher_test.go

Smoke tests for EquivocationPublisher. The verified-finding
construction path lives in the SDK's findings package; this file
only exercises the operator-side wiring (config validation +
the panic-on-nil contract).
*/
package gossipnet

import (
	"context"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/cosign"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	sdkgossip "github.com/clearcompass-ai/ortholog-sdk/gossip"
)

func newTestSigner(t *testing.T) cosign.WitnessSigner {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return cosign.NewECDSAWitnessSigner(priv)
}

func TestEquivocationPublisher_RejectsNilStore(t *testing.T) {
	_, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		Sink:       sdkgossip.NopSink,
		Signer:     newTestSigner(t),
		NetworkID:  nonZeroNetworkID(),
		Originator: "did:web:x",
	})
	if err == nil || !strings.Contains(err.Error(), "Store") {
		t.Errorf("err = %v, want Store-required", err)
	}
}

func TestEquivocationPublisher_RejectsNilSink(t *testing.T) {
	_, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		Store:      sdkgossip.NewInMemoryStore(),
		Signer:     newTestSigner(t),
		NetworkID:  nonZeroNetworkID(),
		Originator: "did:web:x",
	})
	if err == nil || !strings.Contains(err.Error(), "Sink") {
		t.Errorf("err = %v, want Sink-required", err)
	}
}

func TestEquivocationPublisher_RejectsZeroNetworkID(t *testing.T) {
	_, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		Store:      sdkgossip.NewInMemoryStore(),
		Sink:       sdkgossip.NopSink,
		Signer:     newTestSigner(t),
		Originator: "did:web:x",
	})
	if err == nil || !strings.Contains(err.Error(), "NetworkID") {
		t.Errorf("err = %v, want NetworkID-required", err)
	}
}

func TestEquivocationPublisher_RejectsEmptyOriginator(t *testing.T) {
	_, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		Store:     sdkgossip.NewInMemoryStore(),
		Sink:      sdkgossip.NopSink,
		Signer:    newTestSigner(t),
		NetworkID: nonZeroNetworkID(),
	})
	if err == nil || !strings.Contains(err.Error(), "Originator") {
		t.Errorf("err = %v, want Originator-required", err)
	}
}

func TestEquivocationPublisher_PanicsOnNilVerified(t *testing.T) {
	pub, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		Store:      sdkgossip.NewInMemoryStore(),
		Sink:       sdkgossip.NopSink,
		Signer:     newTestSigner(t),
		NetworkID:  nonZeroNetworkID(),
		Originator: "did:web:x",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil verified finding")
		}
	}()
	pub.Publish(context.Background(), nil)
}
