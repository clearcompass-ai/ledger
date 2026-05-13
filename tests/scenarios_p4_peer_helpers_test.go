//go:build scenarios

/*
FILE PATH:

	tests/scenarios_p4_peer_helpers_test.go

DESCRIPTION:

	Layer 0 — Persona 4 (Peer Ledger, fixtures + helpers). The
	minimal moving parts a peer-ledger gossip test needs:

	  - gossipPeer: an httptest.Server mounting the SDK's
	    gossip.Handler (POST /v1/gossip) + gossip.FeedHandler
	    (GET /v1/gossip/since etc.) over a *gossip.InMemoryStore.
	  - p4Verifier: a tiny OriginatorKeyManager implementation
	    backed by a single (originator, *ecdsa.PublicKey) entry,
	    suitable for the test's single-originator topology.
	  - p4Originator: bundles the originator's signing key
	    (cosign.WitnessSigner) + its DID + its current Lamport /
	    prev-hash chain state, threaded across signs.
	  - Sign-and-publish + pull-once helpers wrapping the SDK's
	    gossip.Sign + Publish + FeedClient.Since.

KEY ARCHITECTURAL DECISIONS:
  - One InMemoryStore per peer. Each peer owns its own append
    log; convergence is asserted by event-set equality across
    stores after a round of pull. The SDK's reference store is
    the system under test, so we drive it directly rather than
    replacing it with a mock.
  - p4Verifier holds a single originator. Multi-originator
    scenarios are out of scope for Persona 4 (they belong to
    Persona 7's cross-network tests). The verifier returns
    gossip.ErrUnknownOriginator for any other originator,
    mirroring the SDK's typed-error contract.
  - Pull is one shot. p4PullOnce fetches /v1/gossip/since on the
    source peer, then Append's every event into the dest peer's
    store. Real production pull uses a background goroutine with
    backoff; that's a peer-runtime concern, not a wire-protocol
    concern. Persona 4 tests the protocol; the runtime is left
    to production code.
  - p4Originator is value-tagged (Lamport, PrevHash) but the
    pointer-receiver helpers mutate the in-process state. This
    mirrors a real originator's signing-loop where every signed
    event advances the chain head.

OVERVIEW:

	p4Originator               → originator state.
	newP4Originator(t, did)    → fresh originator + key.
	p4Verifier                 → in-test OriginatorKeyManager.
	newP4Verifier(t, orig)     → constructor.
	gossipPeer                 → test peer fixture.
	newGossipPeer(t, ver, nid) → peer with handlers mounted.
	p4SignAndPublish(t, ev,
	                 orig, peer)   → sign, publish, advance chain.
	p4PullOnce(t, src, dst)        → drain src.Since → dst.Append.
	p4MakeFinding(t, originator,
	              treeSize)        → fresh CosignedTreeHeadFinding.

KEY DEPENDENCIES:
  - github.com/clearcompass-ai/attesta/gossip:
    Handler / FeedHandler / Sign / NewClient / NewFeedClient /
    InMemoryStore / NewInMemoryKeyManager / Event /
    OriginatorVerifier / SignedEvent.
  - github.com/clearcompass-ai/attesta/gossip/findings:
    NewCosignedTreeHeadFinding.
  - github.com/clearcompass-ai/attesta/crypto/cosign:
    NewECDSAWitnessSigner, WitnessSigner.
  - github.com/clearcompass-ai/attesta/crypto/signatures:
    VerifyEntry (raw R||S ECDSA verify).
*/
package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// -------------------------------------------------------------------------------------------------
// 1) p4Originator
// -------------------------------------------------------------------------------------------------

// p4Originator bundles the originator state every Persona 4 test
// signs against. Lamport / PrevHash are mutated in place by
// p4SignAndPublish so tests don't have to track them externally.
type p4Originator struct {
	DID       string
	PrivKey   *ecdsa.PrivateKey
	Signer    cosign.WitnessSigner
	NetworkID cosign.NetworkID

	mu       sync.Mutex
	lamport  uint64
	prevHash [32]byte
}

// newP4Originator returns a fresh originator: scenario-grade ECDSA
// key + cosign.WitnessSigner + DID. NetworkID is supplied by
// caller so isolation tests can mint mismatched IDs.
func newP4Originator(t *testing.T, did string, networkID cosign.NetworkID) *p4Originator {
	t.Helper()
	priv := scenarioKey(t)
	signer := cosign.NewECDSAWitnessSigner(priv)
	return &p4Originator{
		DID:       did,
		PrivKey:   priv,
		Signer:    signer,
		NetworkID: networkID,
	}
}

// nextChain returns (lamport, prevHash) for the originator's NEXT
// event, monotonically advancing each call. The SDK requires
// strict monotone Lamport so we add 1 each time.
func (o *p4Originator) nextChain() (uint64, [32]byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lamport++
	return o.lamport, o.prevHash
}

// recordChainHead is called after a successful publish to advance
// the originator's prevHash to the EventID of the just-signed
// event.
func (o *p4Originator) recordChainHead(eventID [32]byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.prevHash = eventID
}

// -------------------------------------------------------------------------------------------------
// 2) p4Verifier — in-test OriginatorKeyManager
// -------------------------------------------------------------------------------------------------

// p4Verifier holds the originator's *ecdsa.PublicKey and verifies
// gossip signatures against it. Implements OriginatorKeyManager
// so it can be wrapped by gossip.NewInMemoryKeyManager (which
// the handler casts to internally). RotateOriginator is a no-op;
// rotation is out of scope for Persona 4.
type p4Verifier struct {
	mu         sync.RWMutex
	originator string
	pubKey     *ecdsa.PublicKey
}

// newP4Verifier returns a verifier preloaded with the originator's
// pubkey. Single-originator topology — a second originator
// triggers ErrUnknownOriginator.
func newP4Verifier(t *testing.T, orig *p4Originator) *p4Verifier {
	t.Helper()
	if orig == nil || orig.PrivKey == nil {
		t.Fatal("newP4Verifier: orig nil")
	}
	return &p4Verifier{
		originator: orig.DID,
		pubKey:     &orig.PrivKey.PublicKey,
	}
}

// VerifyOriginator implements gossip.OriginatorVerifier. Only
// SchemeECDSA is supported (all Persona 4 tests use ECDSA);
// other schemes return a typed gossip error.
func (v *p4Verifier) VerifyOriginator(originator string, digest [32]byte, sigBytes []byte, schemeTag uint8) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if originator != v.originator {
		return fmt.Errorf("p4Verifier: unknown originator %q", originator)
	}
	if schemeTag != signatures.SchemeECDSA {
		return fmt.Errorf("p4Verifier: schemeTag %d not supported", schemeTag)
	}
	if err := signatures.VerifyEntry(digest, sigBytes, v.pubKey); err != nil {
		return fmt.Errorf("p4Verifier: ECDSA verify: %w", err)
	}
	return nil
}

// RotateOriginator is a no-op for Persona 4. Rotation tests would
// belong to a future Persona 7 file.
func (v *p4Verifier) RotateOriginator(_ string, _ []byte, _ [32]byte) error {
	return nil
}

// -------------------------------------------------------------------------------------------------
// 3) gossipPeer fixture
// -------------------------------------------------------------------------------------------------

// gossipPeer is a single node in the Persona 4 gossip topology.
// Holds its own InMemoryStore + handler + httptest.Server.
type gossipPeer struct {
	URL     string
	Store   *gossip.InMemoryStore
	handler *gossip.Handler
	feed    *gossip.FeedHandler
	srv     *httptest.Server
}

// newGossipPeer spins up an InMemoryStore, wraps the verifier in a
// key manager (the SDK's handler casts to OriginatorKeyManager at
// construction), constructs the POST handler + feed handler, and
// mounts them on a fresh httptest.Server. Returns the live peer.
func newGossipPeer(t *testing.T, verifier gossip.OriginatorVerifier, networkID cosign.NetworkID) *gossipPeer {
	t.Helper()
	store := gossip.NewInMemoryStore()
	km, err := gossip.NewInMemoryKeyManager(verifier)
	mustNotErr(t, "NewInMemoryKeyManager", err)

	h, err := gossip.NewHandler(gossip.HandlerConfig{
		Store:           store,
		Verifier:        km,
		AllowedNetworks: map[cosign.NetworkID]struct{}{networkID: {}},
	})
	mustNotErr(t, "NewHandler", err)

	feed, err := gossip.NewFeedHandler(gossip.FeedHandlerConfig{Store: store})
	mustNotErr(t, "NewFeedHandler", err)

	mux := http.NewServeMux()
	mux.Handle("POST /v1/gossip", h)
	mux.Handle("GET /v1/gossip/since", feed)
	mux.Handle("GET /v1/gossip/sth/latest", feed)
	mux.Handle("GET /v1/gossip/by-kind", feed)
	mux.Handle("GET /v1/gossip/event/{eventID}", feed)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = h.Close(ctx)
		_ = feed.Close(ctx)
		_ = store.Close(ctx)
	})

	return &gossipPeer{
		URL:     srv.URL,
		Store:   store,
		handler: h,
		feed:    feed,
		srv:     srv,
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Sign + Publish helper
// -------------------------------------------------------------------------------------------------

// p4SignAndPublish signs ev under orig's key + chain state and
// POSTs the resulting SignedEvent to peer's /v1/gossip endpoint
// via gossip.NewClient. On success advances orig's chain head.
// Returns the SignedEvent so the caller can re-publish (anti-
// entropy tests) or assert on its EventID.
func p4SignAndPublish(t *testing.T, ev gossip.Event, orig *p4Originator, peer *gossipPeer) gossip.SignedEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lamport, prev := orig.nextChain()
	signed, err := gossip.Sign(ctx, ev, orig.Signer, orig.NetworkID, orig.DID, prev, lamport)
	mustNotErr(t, "gossip.Sign", err)

	client, err := gossip.NewClient(peer.URL,
		gossip.WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))
	mustNotErr(t, "NewClient publish", err)
	defer func() { _ = client.Close(ctx) }()

	if err := client.Publish(ctx, signed); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	id, err := gossip.EventIDOf(signed)
	mustNotErr(t, "EventIDOf", err)
	orig.recordChainHead(id)
	return signed
}

// -------------------------------------------------------------------------------------------------
// 5) Pull helper
// -------------------------------------------------------------------------------------------------

// p4PullOnce drains every event from src (since lamport=0) and
// applies them to dst's store. Returns the count of NEW events
// added to dst (by EventCount delta), not the number of Append
// calls — the SDK treats re-Appending an existing event as
// idempotent success (returns nil), so a nil return does NOT
// imply "newly stored". Counting by store-stats delta gives the
// caller the convergence signal it actually needs.
func p4PullOnce(t *testing.T, src, dst *gossipPeer) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fc, err := gossip.NewFeedClient(src.URL, &http.Client{Timeout: 2 * time.Second})
	mustNotErr(t, "NewFeedClient", err)

	startStats, err := dst.Store.Stats(ctx)
	mustNotErr(t, "Stats start", err)

	resp, err := fc.Since(ctx, gossip.IterCursor{Lamport: 0}, 1000)
	mustNotErr(t, "Since", err)

	for _, ev := range resp.Events {
		err := dst.Store.Append(ctx, ev)
		if err == nil {
			continue
		}
		// Duplicate / out-of-order on the receive side is benign
		// during anti-entropy; surface only unexpected errors.
		if errors.Is(err, gossip.ErrChainBreak) ||
			errors.Is(err, gossip.ErrLamportRegression) {
			continue
		}
		t.Fatalf("dst.Append unexpected: %v", err)
	}

	endStats, err := dst.Store.Stats(ctx)
	mustNotErr(t, "Stats end", err)
	return endStats.EventCount - startStats.EventCount
}

// -------------------------------------------------------------------------------------------------
// 6) Test event factory
// -------------------------------------------------------------------------------------------------

// p4MakeFinding constructs a CosignedTreeHeadFinding with fresh
// random RootHash + the supplied tree size + a zero-valued
// witness signature (the structural-validity floor — the SDK
// rejects truly empty signatures slices).
func p4MakeFinding(t *testing.T, ledgerEndpoint string, treeSize uint64) *findings.CosignedTreeHeadFinding {
	t.Helper()
	var rh [32]byte
	if _, err := rand.Read(rh[:]); err != nil {
		t.Fatalf("p4MakeFinding rand: %v", err)
	}
	// SMTRoot derived from the same random source as RootHash so
	// equal-RootHash heads also share an SMTRoot (the property
	// peer-helper fixtures rely on for P4 round-trips). Required
	// non-zero by attesta v0.8.0+ Validate.
	var sr [32]byte
	for i := range sr {
		sr[i] = rh[i] ^ 0x5A
	}
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{RootHash: rh, SMTRoot: sr, TreeSize: treeSize},
		Signatures: []types.WitnessSignature{
			{
				PubKeyID:  [32]byte{0x01},
				SchemeTag: signatures.SchemeECDSA,
				SigBytes:  make([]byte, 64),
			},
		},
	}
	f, err := findings.NewCosignedTreeHeadFinding(head, ledgerEndpoint)
	mustNotErr(t, "NewCosignedTreeHeadFinding", err)
	return f
}
