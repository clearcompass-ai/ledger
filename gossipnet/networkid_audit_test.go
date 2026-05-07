/*
FILE PATH:
    gossipnet/networkid_audit_test.go

DESCRIPTION:
    L3 — NetworkID enforcement audit. Pins that EVERY gossipnet
    constructor rejects a zero NetworkID at boot. The ledger
    must not bypass the SDK's domain-separation invariant: every
    cosign payload signed or verified by this process is bound
    to a specific NetworkID, and a fresh deployment without a
    network bootstrap document cannot construct a publisher.

KEY ARCHITECTURAL DECISIONS:
    - Constructor-level enforcement, not call-site enforcement.
      The check fires ONCE at boot, not on every Sign/Verify.
      Cheap + impossible to bypass once construction succeeds.
    - One subtest per constructor so a failure points at the
      specific constructor that regressed.
    - Tests build the smallest valid Config + flip NetworkID to
      zero. Other required fields are filled with stub values
      (no real signer / store / sink needed for this audit).
*/
package gossipnet

import (
	"strings"
	"testing"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
)

// TestNetworkIDAudit_STHPublisherRejectsZero pins L3 for the
// STHPublisher constructor.
func TestNetworkIDAudit_STHPublisherRejectsZero(t *testing.T) {
	t.Parallel()
	var zero sdkcosign.NetworkID
	_, err := NewSTHPublisher(PublisherConfig{
		NetworkID:  zero,
		Originator: "did:web:test",
	})
	if err == nil {
		t.Fatal("NewSTHPublisher accepted zero NetworkID; want rejection")
	}
	if !strings.Contains(err.Error(), "NetworkID") {
		t.Errorf("err = %v; want message mentioning NetworkID", err)
	}
}

// TestNetworkIDAudit_EquivocationPublisherRejectsZero pins L3
// for the EquivocationPublisher constructor.
func TestNetworkIDAudit_EquivocationPublisherRejectsZero(t *testing.T) {
	t.Parallel()
	var zero sdkcosign.NetworkID
	_, err := NewEquivocationPublisher(EquivocationPublisherConfig{
		NetworkID:  zero,
		Originator: "did:web:test",
	})
	if err == nil {
		t.Fatal("NewEquivocationPublisher accepted zero NetworkID; want rejection")
	}
	if !strings.Contains(err.Error(), "NetworkID") {
		t.Errorf("err = %v; want message mentioning NetworkID", err)
	}
}

// TestNetworkIDAudit_BundleRejectsZero pins L3 for the Build
// (Bundle) constructor — the umbrella wiring entry point used
// by cmd/ledger to assemble the gossip pipeline.
func TestNetworkIDAudit_BundleRejectsZero(t *testing.T) {
	t.Parallel()
	var zero sdkcosign.NetworkID
	cfg := Config{
		NetworkID: zero,
	}
	_, err := Build(cfg)
	if err == nil {
		t.Fatal("gossipnet.Build accepted zero NetworkID; want rejection")
	}
	if !strings.Contains(err.Error(), "NetworkID") {
		t.Errorf("err = %v; want message mentioning NetworkID", err)
	}
}
