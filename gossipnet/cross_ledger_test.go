/*
FILE PATH: gossipnet/cross_ledger_test.go

C15 — Cross-component CT integration test (ledger-side
scaffolding).

# WHAT THIS TEST PINS

Two ledgers A and B running in the same process, fully wired
through the gossip plumbing the ledger deploys in production
(POST /v1/gossip + GET /v1/gossip/{since,sth/latest,event,by-kind}
+ BufferedSink + DIDOriginatorVerifier + InMemoryKeyManager).

Round-trip:

 1. Ledger A signs a KindCosignedTreeHead event (the STH
    emission shape STHPublisher produces in the commit hot path).
 2. A's BufferedSink → MultiSink → HTTPSink → B's POST /v1/gossip.
    Inbound verification succeeds against A's did:key (resolved
    from the wire's `originator` field by B's DIDOriginatorVerifier).
 3. B's gossip Handler appends the event to B's local Store.
 4. An external auditor queries B's GET /v1/gossip/event/{eventID}
    via gossip.FeedClient.Event and receives the same SignedEvent
    bytes A originally published.

# WHY THIS LIVES IN THE LEDGER REPO

The full cross-component test (ledger + JN composer + auditor +
witness daemon) spans repos. The ledger's portion — proving
that a SignedEvent emitted by one ledger round-trips through
another ledger's gossip endpoints — is the ledger-side
scaffold. Cross-repo tests compose this fixture with
JN-composer and auditor harnesses landed elsewhere.

# COVERAGE GAPS DELIBERATELY OUT OF SCOPE

  - Witness cosignature collection: A publishes an STH whose
    Signatures slice is empty (no actual K-of-N collection here).
    The witness collector is exercised by witness/head_sync_test
    paths; this test exercises the gossip transport.
  - Anti-entropy catchup loop: covered by
    gossipnet/antientropy_test.go's TestAntiEntropy_PullsAndAppendsFromPeer.
  - Equivocation detection: covered by
    gossipnet/equivocation_monitor_test.go's
    TestEquivocationMonitor_DetectsAndPublishes.
*/
package gossipnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// ledgerFixture bundles one ledger's gossip stack: the
// in-memory store + the bundle (handlers + verifier) + the
// httptest.Server exposing the bundle's endpoints.
type ledgerFixture struct {
	store  *sdkgossip.InMemoryStore
	bundle *Bundle
	server *httptest.Server
	url    string
}

// newLedgerFixture builds one ledger's gossip stack with no
// peer fan-out (it's a pure receiver in this test). PostHandler
// + FeedHandler are mounted on a single httptest.Server.
func newLedgerFixture(t *testing.T, networkID cosign.NetworkID) *ledgerFixture {
	t.Helper()
	store := sdkgossip.NewInMemoryStore()
	bundle, err := Build(Config{
		Store:            store,
		NetworkID:        networkID,
		RateLimitRPS:     -1, // disable rate limiter inside tests
		FeedRateLimitRPS: -1,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /v1/gossip", bundle.PostHandler)
	mux.Handle("GET /v1/gossip/sth/latest", bundle.FeedHandler)
	mux.Handle("GET /v1/gossip/since", bundle.FeedHandler)
	mux.Handle("GET /v1/gossip/by-kind", bundle.FeedHandler)
	mux.Handle("GET /v1/gossip/event/{eventID}", bundle.FeedHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, c := range bundle.Closeables {
			_ = c.Close(ctx)
		}
	})
	return &ledgerFixture{
		store:  store,
		bundle: bundle,
		server: srv,
		url:    srv.URL,
	}
}

// TestCrossLedger_STHRoundTrip — C15 happy path.
//
//  1. Build ledger A (publisher) + ledger B (receiver) in
//     the same process, sharing one NetworkID.
//  2. A signs a KindCosignedTreeHead event under its did:key.
//  3. A publishes via gossip.HTTPSink pointing at B's POST
//     /v1/gossip.
//  4. Assert B's local Store has the appended event.
//  5. As an auditor, retrieve the event by EventID via
//     gossip.FeedClient.Event from B and confirm round-trip.
func TestCrossLedger_STHRoundTrip(t *testing.T) {
	netID := nonZeroNetworkID()

	// B is the receiver. A's publishes target B's URL.
	opB := newLedgerFixture(t, netID)

	// A is the publisher. We don't need A to host any HTTP
	// surface — A's stack is just the publisher + signer +
	// own (empty) local store for chain-discipline state.
	aKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	aSigner := cosign.NewECDSAWitnessSigner(aKP.PrivateKey)
	aStore := sdkgossip.NewInMemoryStore()

	// HTTP sink pointing at B's /v1/gossip.
	bClient, err := sdkgossip.NewClient(opB.url)
	if err != nil {
		t.Fatal(err)
	}
	bSink, err := sdkgossip.NewHTTPSink(bClient)
	if err != nil {
		t.Fatal(err)
	}

	publisher, err := NewSTHPublisher(PublisherConfig{
		Store:      aStore,
		Sink:       bSink,
		Signer:     aSigner,
		NetworkID:  netID,
		Originator: aKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Compose the head A is publishing. The SDK's
	// findings.NewCosignedTreeHeadFinding rejects heads with
	// zero signatures (a finding without any cosignature is not
	// transparency evidence). We attach one signature from a
	// throwaway witness signer; cryptographic verification
	// against a witness key set is OUT of scope for this
	// transport-only test.
	witKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	witSigner := cosign.NewECDSAWitnessSigner(witKP.PrivateKey)
	headBare := types.TreeHead{
		TreeSize: 4242,
		RootHash: [32]byte{0xCA, 0xFE, 0xBA, 0xBE},
	}
	witSig, err := witSigner.Sign(cosign.NewTreeHeadPayload(headBare),
		netID, cosign.HashAlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	head := types.CosignedTreeHead{
		TreeHead:   headBare,
		Signatures: []types.WitnessSignature{witSig},
	}

	publisher.PublishCosignedHead(context.Background(), head)

	// Give the BufferedSink worker a moment to drain to B.
	// PublishCosignedHead is best-effort + non-blocking; we
	// poll instead of sleeping a fixed duration.
	deadline := time.Now().Add(2 * time.Second)
	var bStats sdkgossip.StoreStats
	for time.Now().Before(deadline) {
		bStats, _ = opB.store.Stats(context.Background())
		if bStats.EventCount >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if bStats.EventCount != 1 {
		t.Fatalf("ledger B EventCount = %d, want 1 (publish did not propagate)",
			bStats.EventCount)
	}

	// ── Auditor path: GET /v1/gossip/event/{eventID} ────────
	// Resolve the EventID from A's local store (A appended on
	// publish per gossip.Store contract). Pass it to B's
	// FeedClient and confirm round-trip.
	aHeadStats, _ := aStore.Stats(context.Background())
	if aHeadStats.EventCount != 1 {
		t.Fatalf("ledger A EventCount = %d, want 1 (local Append did not happen)",
			aHeadStats.EventCount)
	}
	// Iterate A's store to recover the EventID.
	var aEvent sdkgossip.SignedEvent
	if err := aStore.Iterate(context.Background(), sdkgossip.Filter{},
		func(ev sdkgossip.SignedEvent) error {
			aEvent = ev
			return nil
		}); err != nil {
		t.Fatalf("iterate A store: %v", err)
	}
	eventID, err := sdkgossip.EventIDOf(aEvent)
	if err != nil {
		t.Fatal(err)
	}

	// External auditor: an http.Client + FeedClient pointed at
	// B's URL. No ledger privileges required.
	auditor, err := sdkgossip.NewFeedClient(opB.url, &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditorEvent, err := auditor.Event(context.Background(), eventID)
	if err != nil {
		t.Fatalf("auditor.Event: %v", err)
	}

	// Round-trip: the auditor's event must equal A's signed
	// event byte-for-byte (canonical fields).
	if auditorEvent.Originator != aKP.DID {
		t.Errorf("auditor event Originator = %q, want %q",
			auditorEvent.Originator, aKP.DID)
	}
	if auditorEvent.Kind != sdkgossip.KindCosignedTreeHead {
		t.Errorf("auditor event Kind = %s, want KindCosignedTreeHead",
			auditorEvent.Kind)
	}
	if auditorEvent.LamportTime != aEvent.LamportTime {
		t.Errorf("auditor event LamportTime = %d, want %d",
			auditorEvent.LamportTime, aEvent.LamportTime)
	}
	if auditorEvent.SigBytes != aEvent.SigBytes {
		t.Errorf("auditor event SigBytes mismatch — wire round-trip drift")
	}

	// Decode the body to confirm the cosigned head reached the
	// auditor with TreeSize + RootHash intact.
	finding, err := decodeAuditorBody(auditorEvent)
	if err != nil {
		t.Fatalf("decode auditor body: %v", err)
	}
	if finding.Head.TreeSize != head.TreeSize {
		t.Errorf("auditor head TreeSize = %d, want %d",
			finding.Head.TreeSize, head.TreeSize)
	}
	if finding.Head.RootHash != head.RootHash {
		t.Errorf("auditor head RootHash = %x, want %x",
			finding.Head.RootHash, head.RootHash)
	}
}

// TestCrossLedger_LatestSTH — confirms the auditor can ask
// "what's B's latest view of A's STH?" via the LatestSTH
// endpoint after a publish round-trip.
func TestCrossLedger_LatestSTH(t *testing.T) {
	netID := nonZeroNetworkID()
	opB := newLedgerFixture(t, netID)

	aKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	aSigner := cosign.NewECDSAWitnessSigner(aKP.PrivateKey)
	aStore := sdkgossip.NewInMemoryStore()
	bClient, _ := sdkgossip.NewClient(opB.url)
	bSink, _ := sdkgossip.NewHTTPSink(bClient)
	publisher, err := NewSTHPublisher(PublisherConfig{
		Store: aStore, Sink: bSink, Signer: aSigner,
		NetworkID: netID, Originator: aKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	witKP, _ := did.GenerateDIDKeySecp256k1()
	witSigner := cosign.NewECDSAWitnessSigner(witKP.PrivateKey)
	bareHead := types.TreeHead{
		TreeSize: 9999,
		RootHash: [32]byte{0xDE, 0xAD},
	}
	witSig, err := witSigner.Sign(cosign.NewTreeHeadPayload(bareHead),
		netID, cosign.HashAlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	head := types.CosignedTreeHead{
		TreeHead:   bareHead,
		Signatures: []types.WitnessSignature{witSig},
	}
	publisher.PublishCosignedHead(context.Background(), head)

	// Wait for B to receive.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stats, _ := opB.store.Stats(context.Background())
		if stats.EventCount >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// As an auditor, query B's LatestSTH for A's DID.
	auditor, _ := sdkgossip.NewFeedClient(opB.url, &http.Client{Timeout: 2 * time.Second})
	got, found, err := auditor.LatestSTH(context.Background(), aKP.DID)
	if err != nil {
		t.Fatalf("LatestSTH: %v", err)
	}
	if !found {
		t.Fatal("LatestSTH found = false; want true after publish round-trip")
	}
	if got.Event.Originator != aKP.DID {
		t.Errorf("Originator = %q, want %q", got.Event.Originator, aKP.DID)
	}
	if got.Event.Kind != sdkgossip.KindCosignedTreeHead {
		t.Errorf("Kind = %s, want KindCosignedTreeHead", got.Event.Kind)
	}
}

// decodeAuditorBody decodes a SignedEvent's body as a
// WireCosignedTreeHeadBody and converts to a typed
// CosignedTreeHeadFinding. Mirrors the ledger's
// gossipnet/equivocation_monitor.go decodeSTHFromEvent helper.
func decodeAuditorBody(ev sdkgossip.SignedEvent) (*findings.CosignedTreeHeadFinding, error) {
	if ev.Kind != sdkgossip.KindCosignedTreeHead {
		return nil, fmt.Errorf("mismatched kind: %s", ev.Kind)
	}
	var wire sdkgossip.WireCosignedTreeHeadBody
	if err := json.Unmarshal(ev.Body, &wire); err != nil {
		return nil, err
	}
	return findings.CosignedTreeHeadFromWire(wire)
}
