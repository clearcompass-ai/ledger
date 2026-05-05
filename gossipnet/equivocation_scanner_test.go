/*
End-to-end test for the EquivocationScanner. Wires:

  1. In-memory BadgerDB-backed gossipstore
  2. EquivocationScanner subscribed to splitid index (0x0A)
  3. Two splitid entries at the same (schema, split_id) signed
     by the same DID — a real cryptographic equivocation
  4. NopSink as the gossip output (we read the local gossip
     Store + projection directly)
  5. Verifies: scanner detects, signs the gossip event, appends
     locally, projects into 0x0B, AND a fresh
     gossip/findings.FetchEquivocationByBinding round-trip
     pulls back the verified finding.
*/
package gossipnet_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/cosign"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	sdkgossip "github.com/clearcompass-ai/ortholog-sdk/gossip"
	"github.com/clearcompass-ai/ortholog-sdk/gossip/findings"

	"github.com/clearcompass-ai/ortholog-operator/gossipnet"
	"github.com/clearcompass-ai/ortholog-operator/gossipstore"
)

func nonZeroNetworkIDForScanner() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

func openInMemBadgerForScanner(t *testing.T) *badger.DB {
	t.Helper()
	opts := badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("badger.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestEquivocationScanner_DetectsAndPublishes(t *testing.T) {
	db := openInMemBadgerForScanner(t)
	store, err := gossipstore.New(gossipstore.Config{DB: db, GCInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })

	// The "equivocator" — also the operator that admitted both
	// entries. Single DID signs both sides.
	eqKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	eqSigner := cosign.NewECDSAWitnessSigner(eqKP.PrivateKey)
	netID := nonZeroNetworkIDForScanner()

	// Sign two distinct canonical hashes with the SAME key.
	hashA := sha256.Sum256([]byte("entry-a"))
	hashB := sha256.Sum256([]byte("entry-b"))
	sigA, err := signatures.SignEntry(hashA, eqKP.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := signatures.SignEntry(hashB, eqKP.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	const schemaID = "pre-grant-commitment-v1"
	splitID := sha256.Sum256([]byte("split-x"))

	// Build the scanner. The sink is a no-op for this test —
	// we read the local store + projection to confirm the
	// scanner did its job.
	scanner, err := gossipnet.NewEquivocationScanner(gossipnet.EquivocationScannerConfig{
		Store:       store,
		GossipStore: store,
		Sink:        sdkgossip.NopSink,
		Signer:      eqSigner,
		NetworkID:   netID,
		Originator:  eqKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Drive the scanner.
	scanCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		_ = scanner.Run(scanCtx)
	}()

	// Give Subscribe a beat to register.
	time.Sleep(50 * time.Millisecond)

	// Sequencer simulation: write the FIRST entry — no
	// equivocation yet, scanner should observe but not act.
	if err := store.WriteSplitIDIndexEntry(scanCtx, schemaID, splitID, 100,
		gossipstore.SplitIDIndexEntry{
			EquivocatorDID: eqKP.DID,
			CanonicalHash:  hashA,
			SigBytes:       sigA,
		}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)

	// Write the SECOND entry — collision. Scanner detects.
	if err := store.WriteSplitIDIndexEntry(scanCtx, schemaID, splitID, 200,
		gossipstore.SplitIDIndexEntry{
			EquivocatorDID: eqKP.DID,
			CanonicalHash:  hashB,
			SigBytes:       sigB,
		}); err != nil {
		t.Fatal(err)
	}

	// Wait for the scanner to publish.
	binding := findings.EntryCommitmentBinding(schemaID, splitID)
	deadline := time.Now().Add(2 * time.Second)
	var projBytes []byte
	for time.Now().Before(deadline) {
		projBytes, _ = store.GetEquivProjection(scanCtx, binding)
		if len(projBytes) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(projBytes) == 0 {
		t.Fatal("scanner did not project equivocation into 0x0B within 2s")
	}

	// Cancel + wait for graceful exit.
	cancel()
	select {
	case <-scanDone:
	case <-time.After(2 * time.Second):
		t.Fatal("scanner did not exit on cancel")
	}

	// Confirm the projected event has the right shape.
	stats, _ := store.Stats(context.Background())
	if stats.EventCount < 1 {
		t.Errorf("local gossip store EventCount = %d, want ≥ 1", stats.EventCount)
	}

	// End-to-end zero-trust validation: serve via FeedHandler +
	// FeedClient, then call findings.FetchEquivocationByBinding
	// to re-verify cryptographically.
	feed, err := sdkgossip.NewFeedHandler(sdkgossip.FeedHandlerConfig{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(feed)
	defer srv.Close()
	feedClient, _ := sdkgossip.NewFeedClient(srv.URL, &http.Client{Timeout: 2 * time.Second})

	registry := did.NewVerifierRegistry()
	if err := registry.Register("key", did.NewKeyVerifier()); err != nil {
		t.Fatal(err)
	}
	verified, err := findings.FetchEquivocationByBinding(
		context.Background(), feedClient, registry, schemaID, splitID,
	)
	if err != nil {
		t.Fatalf("FetchEquivocationByBinding: %v", err)
	}
	if len(verified) != 1 {
		t.Fatalf("verified count = %d, want 1", len(verified))
	}
	if verified[0].EquivocatorDID() != eqKP.DID {
		t.Errorf("EquivocatorDID = %q, want %q",
			verified[0].EquivocatorDID(), eqKP.DID)
	}
	if verified[0].SplitID() != splitID {
		t.Errorf("SplitID round-trip mismatch")
	}
	a, b := verified[0].Sides()
	gotA := hex.EncodeToString(a.CanonicalHash[:])
	gotB := hex.EncodeToString(b.CanonicalHash[:])
	if gotA == gotB {
		t.Error("verified sides have identical CanonicalHash — should differ")
	}
}

func TestEquivocationScanner_NoFalsePositiveOnSingleEntry(t *testing.T) {
	db := openInMemBadgerForScanner(t)
	store, _ := gossipstore.New(gossipstore.Config{DB: db, GCInterval: -1})
	t.Cleanup(func() { _ = store.Close(context.Background()) })

	eqKP, _ := did.GenerateDIDKeySecp256k1()
	eqSigner := cosign.NewECDSAWitnessSigner(eqKP.PrivateKey)
	hashA := sha256.Sum256([]byte("only-entry"))
	sigA, _ := signatures.SignEntry(hashA, eqKP.PrivateKey)
	splitID := sha256.Sum256([]byte("solo"))
	const schemaID = "pre-grant-commitment-v1"

	scanner, _ := gossipnet.NewEquivocationScanner(gossipnet.EquivocationScannerConfig{
		Store: store, GossipStore: store, Sink: sdkgossip.NopSink,
		Signer: eqSigner, NetworkID: nonZeroNetworkIDForScanner(),
		Originator: eqKP.DID,
	})
	scanCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go scanner.Run(scanCtx)
	time.Sleep(50 * time.Millisecond)

	// Single entry — no collision.
	store.WriteSplitIDIndexEntry(scanCtx, schemaID, splitID, 1,
		gossipstore.SplitIDIndexEntry{
			EquivocatorDID: eqKP.DID,
			CanonicalHash:  hashA,
			SigBytes:       sigA,
		})
	time.Sleep(150 * time.Millisecond)

	// Local gossip store should have ZERO events; projection
	// also empty.
	stats, _ := store.Stats(context.Background())
	if stats.EventCount != 0 {
		t.Errorf("EventCount = %d, want 0 (no equivocation, no publish)", stats.EventCount)
	}
	binding := findings.EntryCommitmentBinding(schemaID, splitID)
	bytesProj, _ := store.GetEquivProjection(scanCtx, binding)
	if len(bytesProj) != 0 {
		t.Errorf("projection has %d bytes, want 0 (no equivocation)", len(bytesProj))
	}
}
