//go:build p4
// +build p4

// FILE PATH: tests/p4/integrity_master_test.go
//
// P4.5 — Cryptographic integrity master test. Pins the
// transparency-tree contracts the rest of the network leans on
// for zero-trust audit:
//
//  1. SMT round-trip — Set(leaf) → Get(leaf) returns the exact
//     tip-tuple that was stored. Without this, any audit
//     relying on /v1/smt/proof would see a fictitious leaf.
//  2. SMT root changes on every distinct Set — root is a pure
//     deterministic function of leaf state. A root that
//     didn't change after a write would mean the SMT is not
//     committing to the new leaf — undetectable equivocation.
//  3. SMT MembershipProof verifies — for every leaf the store
//     returns, the SDK's VerifyMembershipProof MUST accept the
//     proof against the live root. Pins the cross-API audit
//     contract (Alignment 6: Parse, Don't Validate).
//  4. DetectEquivocation flags forks — given two cosigned
//     heads at the SAME TreeSize with DIFFERENT RootHashes,
//     DetectEquivocation returns a non-nil EquivocationProof.
//     Without this, a rogue ledger could publish two roots
//     and the network would never notice.
//  5. DetectEquivocation passes consistent heads — given two
//     identical cosigned heads, DetectEquivocation returns
//     (nil, nil). Pins the no-false-positives boundary —
//     benign duplicates must NOT trip the slasher.
//
// Each test case is one row of the matrix; failures point at
// exactly which cryptographic guarantee just broke.
package p4

import (
	"context"
	"errors"
	"testing"

	smt "github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
	upwitness "github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/ledger/store"
)

const p4IntegrityLogDID = "did:p4:integrity-master"

// TestP4_Integrity_SMT_RoundTrip: Set(leaf) → Get(leaf) returns
// a leaf whose tip-tuple bytes match what was stored. Pins the
// most basic transparency-tree contract: the store MUST faithfully
// hold what audits will later read.
func TestP4_Integrity_SMT_RoundTrip(t *testing.T) {
	pool := requirePostgres(t)
	defer pool.Close()
	ctx := context.Background()

	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(ctx, pool, 1024)
	tree := smt.NewTree(leafStore, nodeCache)

	if _, err := pool.Exec(ctx, `DELETE FROM smt_leaves`); err != nil {
		t.Fatalf("clear smt_leaves: %v", err)
	}

	key := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	want := types.SMTLeaf{
		Key: key,
		OriginTip: types.LogPosition{
			LogDID: p4IntegrityLogDID, Sequence: 4242,
		},
		AuthorityTip: types.LogPosition{
			LogDID: p4IntegrityLogDID, Sequence: 4242,
		},
	}
	if err := tree.SetLeaf(ctx, key, want); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	got, err := tree.GetLeaf(ctx, key)
	if err != nil {
		t.Fatalf("GetLeaf: %v", err)
	}
	if got == nil {
		t.Fatal("GetLeaf returned nil after Set — leaf vanished")
	}
	if got.OriginTip.Sequence != want.OriginTip.Sequence ||
		got.AuthorityTip.Sequence != want.AuthorityTip.Sequence ||
		got.OriginTip.LogDID != want.OriginTip.LogDID {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", *got, want)
	}
}

// TestP4_Integrity_SMT_RootChangesOnDistinctSet: setting two
// leaves at distinct keys produces two distinct roots. A root
// that doesn't move after a write would mean the SMT is not
// committing to the new leaf — silent equivocation surface.
//
// Uses smt.InMemoryLeafStore — the SDK's tree.Root() only
// computes roots from InMemoryLeafStore or OverlayLeafStore
// snapshots. For Postgres-backed stores the production path
// goes through ProcessBatch + OverlayLeafStore (see soak); a
// raw tree.Root() on a PostgresLeafStore returns the empty-
// tree hash by design.
func TestP4_Integrity_SMT_RootChangesOnDistinctSet(t *testing.T) {
	pool := requirePostgres(t)
	defer pool.Close()
	ctx := context.Background()

	leafStore := smt.NewInMemoryLeafStore()
	nodeCache := smt.NewInMemoryNodeCache()
	tree := smt.NewTree(leafStore, nodeCache)

	key1 := [32]byte{0x11}
	key2 := [32]byte{0x22}

	rootEmpty, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root (empty): %v", err)
	}

	if err := tree.SetLeaf(ctx, key1, types.SMTLeaf{
		Key:          key1,
		OriginTip:    types.LogPosition{LogDID: p4IntegrityLogDID, Sequence: 1},
		AuthorityTip: types.LogPosition{LogDID: p4IntegrityLogDID, Sequence: 1},
	}); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	root1, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root after Set key1: %v", err)
	}
	if root1 == rootEmpty {
		t.Fatal("root unchanged after first Set — SMT is not committing to the leaf")
	}

	if err := tree.SetLeaf(ctx, key2, types.SMTLeaf{
		Key:          key2,
		OriginTip:    types.LogPosition{LogDID: p4IntegrityLogDID, Sequence: 2},
		AuthorityTip: types.LogPosition{LogDID: p4IntegrityLogDID, Sequence: 2},
	}); err != nil {
		t.Fatalf("Set key2: %v", err)
	}
	root2, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root after Set key2: %v", err)
	}
	if root2 == root1 {
		t.Fatal("root unchanged after second Set — second leaf not committed")
	}
}

// TestP4_Integrity_SMT_MembershipProofVerifies: for every leaf
// the SMT holds, the SDK's smt.VerifyMembershipProof MUST accept
// a freshly-generated proof against the live root. This is the
// cross-API audit contract — auditors fetch /v1/smt/root + the
// per-key proof and verify entirely on their own CPU.
//
// InMemoryLeafStore for the same reason as RootChangesOnDistinctSet
// — tree.Root() / GenerateMembershipProof only compute against
// in-memory or overlay snapshots.
func TestP4_Integrity_SMT_MembershipProofVerifies(t *testing.T) {
	pool := requirePostgres(t)
	defer pool.Close()
	ctx := context.Background()

	leafStore := smt.NewInMemoryLeafStore()
	nodeCache := smt.NewInMemoryNodeCache()
	tree := smt.NewTree(leafStore, nodeCache)

	keys := [][32]byte{
		{0xA1}, {0xA2}, {0xA3}, {0xA4}, {0xA5},
	}
	for i, k := range keys {
		if err := tree.SetLeaf(ctx, k, types.SMTLeaf{
			Key: k,
			OriginTip: types.LogPosition{
				LogDID: p4IntegrityLogDID, Sequence: uint64(i + 1),
			},
			AuthorityTip: types.LogPosition{
				LogDID: p4IntegrityLogDID, Sequence: uint64(i + 1),
			},
		}); err != nil {
			t.Fatalf("SetLeaf %d: %v", i, k[0])
		}
	}

	root, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}

	// Every key's proof must verify against this same root.
	for i, k := range keys {
		proof, err := tree.GenerateMembershipProof(ctx, k)
		if err != nil {
			t.Fatalf("GenerateMembershipProof key=%x: %v", k[0], err)
		}
		if err := smt.VerifyMembershipProof(proof, root); err != nil {
			t.Fatalf("VerifyMembershipProof key=%x (#%d): %v — "+
				"the SDK's verifier rejected a proof generated "+
				"by the SDK's tree against the SDK's tree's own "+
				"root. This is the most fundamental cross-API "+
				"break possible.", k[0], i, err)
		}
	}
}

// TestP4_Integrity_DetectEquivocation_FlagsFork: given two
// cosigned heads at the SAME TreeSize with DIFFERENT RootHashes,
// signed by a quorum of K-of-N witnesses, witness.DetectEquivocation
// returns a non-nil EquivocationProof. Without this the network
// can't slash a forking ledger.
//
// Note: this test does NOT require Postgres — it's pure SDK
// crypto. We still gate it on requirePostgres for fixture
// uniformity (every P4 cell goes through one bootstrap path).
func TestP4_Integrity_DetectEquivocation_FlagsFork(t *testing.T) {
	pool := requirePostgres(t)
	defer pool.Close()

	netID := p4IntegrityNetID()
	const totalN, quorumK = 3, 2

	// Build N witnesses. Their public keys feed the WitnessKeySet
	// the verifier consults; their private keys produce the per-
	// head signatures.
	signers := make([]cosign.WitnessSigner, totalN)
	pubKeys := make([]types.WitnessPublicKey, totalN)
	for i := 0; i < totalN; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("generate witness key %d: %v", i, err)
		}
		s := cosign.NewECDSAWitnessSigner(priv)
		signers[i] = s
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		pubKeys[i] = types.WitnessPublicKey{
			ID:        s.PubKeyID(),
			PublicKey: pubBytes,
		}
	}

	keySet, err := cosign.NewWitnessKeySet(pubKeys, netID, quorumK, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	// Build two conflicting heads at the same TreeSize.
	headA := types.TreeHead{
		TreeSize: 100,
		RootHash: [32]byte{0xAA},
	}
	headB := types.TreeHead{
		TreeSize: 100,
		RootHash: [32]byte{0xBB}, // different root → fork
	}

	signHead := func(h types.TreeHead) types.CosignedTreeHead {
		out := types.CosignedTreeHead{TreeHead: h}
		payload := cosign.NewTreeHeadPayload(h)
		// Ask K signers to cosign — exactly the network policy.
		for i := 0; i < quorumK; i++ {
			sig, err := signers[i].Sign(context.Background(), payload, netID, cosign.HashAlgoSHA256)
			if err != nil {
				t.Fatalf("Sign head: %v", err)
			}
			out.Signatures = append(out.Signatures, sig)
		}
		return out
	}

	cosignedA := signHead(headA)
	cosignedB := signHead(headB)

	proof, err := upwitness.DetectEquivocation(cosignedA, cosignedB, keySet)
	if err != nil {
		t.Fatalf("DetectEquivocation: %v", err)
	}
	if proof == nil {
		t.Fatal("DetectEquivocation returned nil for two cosigned, conflicting heads — " +
			"the network's slashing path is silently broken")
	}
	if !proof.IsProven() {
		t.Errorf("EquivocationProof.IsProven() = false; "+
			"ValidSigsA=%d ValidSigsB=%d (expected both > 0)",
			proof.ValidSigsA, proof.ValidSigsB)
	}
	if proof.TreeSize != headA.TreeSize {
		t.Errorf("proof.TreeSize = %d, want %d", proof.TreeSize, headA.TreeSize)
	}
}

// TestP4_Integrity_DetectEquivocation_AcceptsBenignDuplicate:
// the same cosigned head presented twice (e.g., two gossip
// peers both relay a finding) MUST NOT trip equivocation
// detection. No-false-positive boundary.
func TestP4_Integrity_DetectEquivocation_AcceptsBenignDuplicate(t *testing.T) {
	pool := requirePostgres(t)
	defer pool.Close()

	netID := p4IntegrityNetID()
	const totalN, quorumK = 3, 2

	signers := make([]cosign.WitnessSigner, totalN)
	pubKeys := make([]types.WitnessPublicKey, totalN)
	for i := 0; i < totalN; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("generate witness key %d: %v", i, err)
		}
		s := cosign.NewECDSAWitnessSigner(priv)
		signers[i] = s
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		pubKeys[i] = types.WitnessPublicKey{
			ID:        s.PubKeyID(),
			PublicKey: pubBytes,
		}
	}

	keySet, err := cosign.NewWitnessKeySet(pubKeys, netID, quorumK, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	head := types.TreeHead{TreeSize: 200, RootHash: [32]byte{0xCC}}
	out := types.CosignedTreeHead{TreeHead: head}
	payload := cosign.NewTreeHeadPayload(head)
	for i := 0; i < quorumK; i++ {
		sig, err := signers[i].Sign(context.Background(), payload, netID, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		out.Signatures = append(out.Signatures, sig)
	}

	// Same cosigned head twice → no equivocation.
	proof, err := upwitness.DetectEquivocation(out, out, keySet)
	if err != nil && !errors.Is(err, upwitness.ErrDifferentSizes) {
		t.Fatalf("DetectEquivocation (duplicate): %v", err)
	}
	if proof != nil {
		t.Fatalf("DetectEquivocation returned proof for IDENTICAL heads " +
			"(no fork) — false-positive slashing surface")
	}
}

// p4IntegrityNetID is a deterministic NetworkID scoped to this
// integrity test file so a parallel run can't cross-pollinate
// with witness_matrix_test.go's set.
func p4IntegrityNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(0xC0 | (i & 0x3F))
	}
	return n
}
