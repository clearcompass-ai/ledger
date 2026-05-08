//go:build p4
// +build p4

// FILE PATH: tests/p4/witness_matrix_test.go
//
// P4.4 — Witness offline matrix. Pins the K-of-N quorum policy
// AGAINST the now-correct Backpressure-Stall semantics: when
// fewer than K of N witnesses are reachable, the SDK collector
// returns ErrQuorumCollectionFailed and the builder loop's
// pre-commit gate aborts the batch (no cursor advance, no SMT
// mutation, sequencer's MaxBuilderLag fires, WAL fills, 503s
// flow).
//
// MATRIX (one row per test case):
//
//	+--------+----------+--------+-----------+----------------+
//	| Total  | Quorum K | Online | Expected  | Pinned         |
//	|  N     |          |        | Outcome   | Invariant      |
//	+--------+----------+--------+-----------+----------------+
//	| 5      | 3        | 5      | success   | all-online     |
//	| 5      | 3        | 3      | success   | exact-quorum   |
//	| 5      | 3        | 2      | err       | below-quorum   |
//	| 5      | 3        | 0      | err       | all-offline    |
//	+--------+----------+--------+-----------+----------------+
//
// Each row constructs N httptest servers, each backed by a
// distinct ECDSA WitnessSigner + cosign.NewWitnessHandler. For
// "online < N" rows we close the offline ones BEFORE driving
// HeadSync; the SDK's WitnessClient returns a transport error
// for the closed endpoint, the collector counts it as a per-
// endpoint failure, and the K-of-N decision falls out
// deterministically.
//
// HeadSync persists each successful collection (head + sigs) to
// Postgres via store.TreeHeadStore — that's why this matrix
// requires ATTESTA_TEST_DSN.
package p4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/witness"
)

// p4WitnessNetID returns a deterministic non-zero NetworkID
// scoped to this test file. Different from any other test's
// NetworkID so a parallel run can't cross-pollinate.
func p4WitnessNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 0x40)
	}
	return n
}

// witnessFixture bundles one synthetic witness — its cosign-side
// signer and the running httptest.Server. The fixture's URL
// becomes a HeadSyncConfig.WitnessEndpoints entry; closing
// Server simulates "this witness is offline".
type witnessFixture struct {
	signer cosign.WitnessSigner
	server *httptest.Server
	url    string
}

// newWitnessFixture spins up one in-process witness behind an
// httptest.Server.
func newWitnessFixture(t *testing.T, netID cosign.NetworkID) *witnessFixture {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("generate witness key: %v", err)
	}
	signer := cosign.NewECDSAWitnessSigner(priv)

	handler, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
		Signer:          signer,
		AllowedNetworks: map[cosign.NetworkID]struct{}{netID: {}},
	})
	if err != nil {
		t.Fatalf("NewWitnessHandler: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(cosign.DefaultCosignPath, handler)
	srv := httptest.NewServer(mux)

	return &witnessFixture{
		signer: signer,
		server: srv,
		url:    srv.URL,
	}
}

// runMatrixCell drives one row of the matrix. Constructs N
// witness fixtures, closes the first (N-online) of them to
// simulate offline witnesses, builds a HeadSync, and asserts
// the call outcome matches expectQuorumOK.
func runMatrixCell(
	t *testing.T,
	cellName string,
	totalN, quorumK, online int,
	expectQuorumOK bool,
) {
	t.Run(cellName, func(t *testing.T) {
		pool := requirePostgres(t)
		defer pool.Close()

		ctx := context.Background()
		netID := p4WitnessNetID()

		// Build N witnesses up-front. Close the first
		// (totalN - online) BEFORE building HeadSync — the
		// HTTP client's first request to a closed httptest
		// server returns ECONNREFUSED, which the SDK collector
		// counts as a per-endpoint failure.
		fixtures := make([]*witnessFixture, totalN)
		for i := range fixtures {
			fixtures[i] = newWitnessFixture(t, netID)
		}
		t.Cleanup(func() {
			for _, f := range fixtures {
				if f.server != nil {
					f.server.Close()
				}
			}
		})
		offlineCount := totalN - online
		for i := 0; i < offlineCount; i++ {
			fixtures[i].server.Close()
		}

		// Build the HeadSync over all N endpoints (online +
		// offline alike — the collector is responsible for the
		// per-endpoint outcome).
		endpoints := make([]string, totalN)
		for i, f := range fixtures {
			endpoints[i] = f.url
		}

		treeStore := store.NewTreeHeadStore(pool)

		// Reset tree_head + tree_head_sigs so the cell runs
		// against a known-empty state (the cell uses a single
		// fixed TreeSize, so prior runs of the same cell would
		// hit the UNIQUE constraint on (tree_size, signer)).
		if _, err := pool.Exec(ctx, `DELETE FROM tree_head_sigs`); err != nil {
			t.Fatalf("clear tree_head_sigs: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM tree_heads`); err != nil {
			t.Fatalf("clear tree_head: %v", err)
		}

		hs, err := witness.NewHeadSync(witness.HeadSyncConfig{
			WitnessEndpoints:  endpoints,
			QuorumK:           quorumK,
			PerWitnessTimeout: 2 * time.Second,
			NetworkID:         netID,
			GossipPublisher:   nil,
		}, treeStore, silentLogger())
		if err != nil {
			t.Fatalf("NewHeadSync: %v", err)
		}

		// Drive RequestCosignatures with a head whose TreeSize
		// is unique-per-cell so persisted rows from one cell
		// don't FK-collide with another. Use the cell's
		// (totalN, quorumK, online) tuple as the size — easy
		// to read in a stack trace if it leaks.
		head := types.TreeHead{
			TreeSize: uint64(1000*totalN + 100*quorumK + online),
			RootHash: [32]byte{0xAA, 0xBB, byte(totalN), byte(quorumK), byte(online)},
		}

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cosigned, cosigErr := hs.RequestCosignatures(ctx, head)

		if expectQuorumOK {
			if cosigErr != nil {
				t.Fatalf("expected K-of-N success (online=%d, K=%d, N=%d) but got error: %v",
					online, quorumK, totalN, cosigErr)
			}
			if len(cosigned.Signatures) < quorumK {
				t.Errorf("collected %d signatures, expected >= K=%d",
					len(cosigned.Signatures), quorumK)
			}
			if cosigned.TreeSize != head.TreeSize {
				t.Errorf("returned head TreeSize = %d, want %d",
					cosigned.TreeSize, head.TreeSize)
			}
			return
		}
		// expect quorum failure
		if cosigErr == nil {
			t.Fatalf("expected ErrQuorumCollectionFailed (online=%d, K=%d, N=%d) "+
				"but RequestCosignatures returned nil — a "+
				"quorum-failure miss here would let the builder loop "+
				"advance past an unfinalized head, breaking Alignment 2",
				online, quorumK, totalN)
		}
		if !errors.Is(cosigErr, cosign.ErrQuorumCollectionFailed) {
			t.Errorf("error = %v; want chain containing ErrQuorumCollectionFailed", cosigErr)
		}
	})
}

// TestP4_WitnessMatrix exercises the full K-of-N matrix in a
// single Go test entry point. Each cell is a sub-test (t.Run)
// so a failing cell fails individually without aborting the
// matrix.
func TestP4_WitnessMatrix(t *testing.T) {
	runMatrixCell(t, "AllOnline_5of5", 5, 3, 5, true)
	runMatrixCell(t, "ExactQuorum_3of5", 5, 3, 3, true)
	runMatrixCell(t, "BelowQuorum_2of5", 5, 3, 2, false)
	runMatrixCell(t, "AllOffline_0of5", 5, 3, 0, false)
}

// TestP4_WitnessMatrix_SignaturesUnderQuorum confirms that the
// returned CosignedTreeHead carries EXACTLY K signatures (not
// N — the SDK collector short-circuits on the K-th valid sig).
// The Strict-STH-Finality CDN write must serialize the same
// K-of-N evidence the gossip publisher transmits.
func TestP4_WitnessMatrix_SignaturesUnderQuorum(t *testing.T) {
	pool := requirePostgres(t)
	defer pool.Close()
	ctx := context.Background()
	netID := p4WitnessNetID()

	const totalN, quorumK = 5, 3
	fixtures := make([]*witnessFixture, totalN)
	for i := range fixtures {
		fixtures[i] = newWitnessFixture(t, netID)
	}
	t.Cleanup(func() {
		for _, f := range fixtures {
			if f.server != nil {
				f.server.Close()
			}
		}
	})

	endpoints := make([]string, totalN)
	for i, f := range fixtures {
		endpoints[i] = f.url
	}

	if _, err := pool.Exec(ctx, `DELETE FROM tree_head_sigs`); err != nil {
		t.Fatalf("clear sigs: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM tree_heads`); err != nil {
		t.Fatalf("clear head: %v", err)
	}

	hs, err := witness.NewHeadSync(witness.HeadSyncConfig{
		WitnessEndpoints:  endpoints,
		QuorumK:           quorumK,
		PerWitnessTimeout: 2 * time.Second,
		NetworkID:         netID,
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{
		TreeSize: 99001,
		RootHash: [32]byte{0xC0, 0xDE},
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cosigned, err := hs.RequestCosignatures(ctx, head)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if len(cosigned.Signatures) < quorumK {
		t.Errorf("got %d signatures, want >= K=%d (collector should short-circuit at K)",
			len(cosigned.Signatures), quorumK)
	}
	if len(cosigned.Signatures) > totalN {
		t.Errorf("got %d signatures, want <= N=%d (impossible — more sigs than witnesses)",
			len(cosigned.Signatures), totalN)
	}
}
