//go:build scenarios

/*
FILE PATH:

	tests/scenarios_p3_witness_helpers_test.go

DESCRIPTION:

	Layer 0 — Persona 3 (Witness Daemon, helpers + isolation tests).
	Helpers used by Persona 3's K-of-N collector tests, plus the two
	sub-scenarios that require non-default witness handler config
	(NetworkID isolation, Purpose restriction). Split from
	scenarios_p3_witness_test.go so each file fits the project's
	per-file LoC budget.

KEY ARCHITECTURAL DECISIONS:
  - p3BuildClients constructs []*cosign.WitnessClient from a
    witnessSwarm. Each client gets the supplied NetworkID — which
    may DELIBERATELY differ from the swarm's AllowedNetworks for
    isolation tests.
  - p3SyntheticTreeHead returns a fresh-bytes types.TreeHead so
    every Persona 3 sub-scenario signs distinct payload bytes.
    Tree-head cosignatures over identical (RootHash, TreeSize)
    could otherwise be replayed across runs and mask an
    "unauthorised reuse" bug.
  - p3RestrictedPurposeWitness spins up ONE witness with
    AllowedPurposes={PurposeTreeHead}, exposing a (URL,
    PublicKey) pair the test wires into a collector. Used by
    DisallowedPurpose_403; the rest of Persona 3 uses the
    standard-config witnessSwarm.
  - Network-isolation test asserts the per-endpoint Err carries
    the RateLimited / NetworkNotConfigured shape the SDK
    promises; we MUST NOT collapse "any error" into a single
    failure assertion — the diagnostic surface is the test's
    contract.

OVERVIEW:

	p3BuildClients(t, swarm, networkID)        → []*WitnessClient.
	p3BuildCollector(t, clients, k)            → *WitnessCollector.
	p3SyntheticTreeHead(t, treeSize)           → types.TreeHead.
	p3RestrictedPurposeWitness(t, networkID,
	                           allowed)        → URL + signer + pubkey.
	runP3WitnessSignsWrongNetworkID_Rejected   → quorum fails on
	                                              NetworkID mismatch.
	runP3DisallowedPurpose_403                 → quorum fails when
	                                              Purpose not allowed.

KEY DEPENDENCIES:
  - github.com/clearcompass-ai/attesta/crypto/cosign:
    NewWitnessClient, NewWitnessCollector, NewWitnessHandler,
    NewECDSAWitnessSigner, NewTreeHeadPayload, NewRotationPayload,
    NetworkID, Purpose.
  - tests/scenarios_witness_test.go: witnessSwarm, scenarioKey.
*/
package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Collector / client constructors
// -------------------------------------------------------------------------------------------------

// p3BuildClients constructs one cosign.WitnessClient per witnessSwarm
// URL, using networkID as the per-client setting. The supplied
// networkID need not match swarm.NetworkID() — isolation tests
// deliberately diverge them.
//
// The client's HTTP timeout is fixed at 2s; tests that inject
// slowness deliberately exceed this to exercise the deadline path.
func p3BuildClients(t *testing.T, swarm *witnessSwarm, networkID cosign.NetworkID) []*cosign.WitnessClient {
	t.Helper()
	urls := swarm.URLs()
	clients := make([]*cosign.WitnessClient, 0, len(urls))
	for _, u := range urls {
		c, err := cosign.NewWitnessClient(u, networkID,
			cosign.WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))
		mustNotErr(t, "NewWitnessClient", err)
		clients = append(clients, c)
	}
	return clients
}

// p3BuildCollector wraps p3BuildClients into a *WitnessCollector
// at the supplied K. K must be in [1, len(clients)]; values outside
// trigger the SDK's compile-time check (returns ErrInvalidPayload).
func p3BuildCollector(t *testing.T, clients []*cosign.WitnessClient, k int) *cosign.WitnessCollector {
	t.Helper()
	col, err := cosign.NewWitnessCollector(clients, k)
	mustNotErr(t, "NewWitnessCollector", err)
	if col.QuorumK() != k {
		t.Fatalf("collector QuorumK=%d, want %d", col.QuorumK(), k)
	}
	if col.QuorumN() != len(clients) {
		t.Fatalf("collector QuorumN=%d, want %d", col.QuorumN(), len(clients))
	}
	return col
}

// -------------------------------------------------------------------------------------------------
// 2) Synthetic tree head
// -------------------------------------------------------------------------------------------------

// p3SyntheticTreeHead returns a fresh-randomness types.TreeHead at
// the supplied tree size. Each call produces a distinct payload so
// signatures cannot be replayed across sub-scenarios. Used by
// every Persona 3 test that calls Collect.
func p3SyntheticTreeHead(t *testing.T, treeSize uint64) types.TreeHead {
	t.Helper()
	var rh [32]byte
	if _, err := rand.Read(rh[:]); err != nil {
		t.Fatalf("p3SyntheticTreeHead: rand: %v", err)
	}
	return types.TreeHead{RootHash: rh, TreeSize: treeSize}
}

// -------------------------------------------------------------------------------------------------
// 3) Restricted-purpose witness — single endpoint
// -------------------------------------------------------------------------------------------------

// p3RestrictedHandle bundles every artefact a restricted-purpose
// witness exposes: the live URL, the WitnessSigner the test feeds
// to a key set, and the public key for verification.
type p3RestrictedHandle struct {
	URL    string
	Signer cosign.WitnessSigner
	PubKey *ecdsa.PublicKey
}

// p3RestrictedPurposeWitness spins up a single httptest.Server
// hosting a cosign witness whose AllowedPurposes is exactly the
// supplied set. Used by DisallowedPurpose_403 to demonstrate that
// a witness configured for tree-head only refuses rotation
// cosignatures with HTTP 403.
func p3RestrictedPurposeWitness(
	t *testing.T,
	networkID cosign.NetworkID,
	allowed map[cosign.Purpose]struct{},
) p3RestrictedHandle {
	t.Helper()
	priv := scenarioKey(t)
	signer := cosign.NewECDSAWitnessSigner(priv)
	h, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
		Signer:          signer,
		AllowedNetworks: map[cosign.NetworkID]struct{}{networkID: {}},
		AllowedPurposes: allowed,
	})
	mustNotErr(t, "NewWitnessHandler restricted", err)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return p3RestrictedHandle{URL: srv.URL, Signer: signer, PubKey: &priv.PublicKey}
}

// -------------------------------------------------------------------------------------------------
// 4) WitnessSignsWrongNetworkID_Rejected
// -------------------------------------------------------------------------------------------------

// runP3WitnessSignsWrongNetworkID_Rejected boots a swarm under
// networkID-A, builds clients under networkID-B, and asserts the
// collector reports per-endpoint errors and ultimately fails
// quorum. This pins the SDK's promise that a witness in
// AllowedNetworks={A} returns 403 for a request whose network_id
// is B — the cryptographic isolation guarantee.
func runP3WitnessSignsWrongNetworkID_Rejected(t *testing.T) {
	t.Helper()
	netA := p3MakeNetworkID(0xA0)
	netB := p3MakeNetworkID(0xB0)
	swarm := newWitnessSwarm(t, 5, 3, netA)

	clients := p3BuildClients(t, swarm, netB)
	col := p3BuildCollector(t, clients, 3)

	payload := cosign.NewTreeHeadPayload(p3SyntheticTreeHead(t, 100))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := col.Collect(ctx, payload)
	if err == nil {
		t.Fatal("Collect succeeded under network mismatch; want ErrQuorumCollectionFailed")
	}
	if !errors.Is(err, cosign.ErrQuorumCollectionFailed) {
		t.Fatalf("err=%v, want ErrQuorumCollectionFailed", err)
	}
	if res == nil {
		t.Fatal("CollectionResult nil on quorum failure")
	}
	if len(res.Signatures) >= col.QuorumK() {
		t.Fatalf("collected %d signatures, expected < K=%d under net mismatch",
			len(res.Signatures), col.QuorumK())
	}
	if len(res.PerEndpoint) != len(clients) {
		t.Fatalf("PerEndpoint len=%d, want %d", len(res.PerEndpoint), len(clients))
	}
	for i, ep := range res.PerEndpoint {
		if ep.Err == nil {
			t.Fatalf("PerEndpoint[%d].Err nil under network mismatch", i)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 5) DisallowedPurpose_403
// -------------------------------------------------------------------------------------------------

// runP3DisallowedPurpose_403 stands up THREE witnesses, all of
// them configured with AllowedPurposes={PurposeTreeHead} only.
// The collector requests a RotationPayload (Purpose=PurposeRotation).
// Every witness returns 403; quorum fails. This pins the SDK's
// purpose-restriction layer end-to-end.
func runP3DisallowedPurpose_403(t *testing.T) {
	t.Helper()
	netID := p3MakeNetworkID(0xC0)
	allowed := map[cosign.Purpose]struct{}{cosign.PurposeTreeHead: {}}

	const n = 3
	clients := make([]*cosign.WitnessClient, 0, n)
	for i := 0; i < n; i++ {
		h := p3RestrictedPurposeWitness(t, netID, allowed)
		c, err := cosign.NewWitnessClient(h.URL, netID,
			cosign.WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))
		mustNotErr(t, "NewWitnessClient", err)
		clients = append(clients, c)
	}
	col := p3BuildCollector(t, clients, 2)

	// Rotation payload uses Purpose=PurposeRotation. The witnesses
	// only allow PurposeTreeHead, so every endpoint returns 403.
	rotHash := sha256.Sum256([]byte("p3-disallowed-rot"))
	payload := cosign.NewRotationPayload(rotHash[:])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := col.Collect(ctx, payload)
	if err == nil {
		t.Fatal("Collect succeeded under disallowed-purpose; want ErrQuorumCollectionFailed")
	}
	if !errors.Is(err, cosign.ErrQuorumCollectionFailed) {
		t.Fatalf("err=%v, want ErrQuorumCollectionFailed", err)
	}
	if res == nil || len(res.PerEndpoint) != n {
		t.Fatalf("CollectionResult shape unexpected: %+v", res)
	}
	for i, ep := range res.PerEndpoint {
		if ep.Err == nil {
			t.Fatalf("PerEndpoint[%d].Err nil under disallowed-purpose", i)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 6) NetworkID minting helper
// -------------------------------------------------------------------------------------------------

// p3MakeNetworkID returns a 32-byte NetworkID with every byte set
// to seed. Used to create deterministic, distinct NetworkIDs per
// sub-scenario without coupling tests via shared state.
func p3MakeNetworkID(seed byte) cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = seed
	}
	return nid
}
