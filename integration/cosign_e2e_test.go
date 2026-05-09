//go:build integration
// +build integration

// FILE PATH: integration/cosign_e2e_test.go
//
// True end-to-end black-box test against a docker-provisioned
// standalone-witness daemon. Skips when WITNESS_URL is unset;
// scripts/run-e2e.sh sets it after `docker compose up` reports
// the witness container healthy.
//
// WHY THIS IS DISTINCT FROM cosign_collection_test.go:
//
//	cosign_collection_test.go  → in-process httptest cosign
//	                              servers. Proves the SDK +
//	                              ledger code paths work.
//	cosign_e2e_test.go         → containerised witness daemon.
//	                              Proves the SHIPPABLE ARTIFACT
//	                              (Dockerfile.witness build →
//	                              binary in container → cosign
//	                              traffic over docker bridge)
//	                              works. The ONLY thing that can
//	                              fail this test that the in-
//	                              process tests can't catch is a
//	                              packaging / boot / OS-process
//	                              regression.
//
// PHYSICS UNDER TEST:
//
//  1. The witness container is up and serving /v1/cosign on
//     WITNESS_URL.
//
//  2. Its NetworkID matches the bootstrap doc on disk
//     (E2E_BOOTSTRAP env var).
//
//  3. The Ledger's witnessclient.HeadSync resolves the URL,
//     POSTs a real cosign request over the docker bridge, and
//     gets back a real types.WitnessSignature.
//
//  4. The signature persists to Postgres tree_head_sigs via
//     the production-shape persistence path.
//
//     The cosigned-checkpoint disk write is OUT of scope for this
//     test — that runs on the LEDGER's filesystem, not the
//     witness container. cosign_collection_test.go covers that.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/network"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/witnessclient"
)

// requireE2EEnv returns (WITNESS_URL, NetworkID) loaded from the
// E2E_BOOTSTRAP file. Skips the test if either env var is unset
// — keeps the test invisible to ad-hoc `go test -tags=integration`
// runs that don't have the docker stack up.
func requireE2EEnv(t *testing.T) (string, cosign.NetworkID) {
	t.Helper()
	witnessURL := os.Getenv("WITNESS_URL")
	if witnessURL == "" {
		t.Skip("WITNESS_URL unset — use scripts/run-e2e.sh")
	}
	bsPath := os.Getenv("E2E_BOOTSTRAP")
	if bsPath == "" {
		t.Skip("E2E_BOOTSTRAP unset — use scripts/run-e2e.sh")
	}
	body, err := os.ReadFile(bsPath)
	if err != nil {
		t.Fatalf("read bootstrap %s: %v", bsPath, err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal bootstrap: %v", err)
	}
	identity, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs(): %v", err)
	}
	return witnessURL, identity.NetworkID
}

// TestE2E_WitnessContainerHealthz pins the daemon's liveness
// endpoint. If this fails, the witness container isn't running
// or its /healthz binding is broken.
func TestE2E_WitnessContainerHealthz(t *testing.T) {
	witnessURL, _ := requireE2EEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, witnessURL+"/healthz", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s/healthz: %v "+
			"(is the witness container up? `docker ps | grep attesta_e2e_witness`)",
			witnessURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz: status=%d, want 200", resp.StatusCode)
	}
}

// TestE2E_HeadSyncCollectsFromContainer drives the Ledger's
// HeadSync against the docker-provisioned witness. K=1 quorum
// (one container in the e2e topology). Pins the full Ledger →
// docker-bridge → witness container → response → Postgres path.
func TestE2E_HeadSyncCollectsFromContainer(t *testing.T) {
	witnessURL, netID := requireE2EEnv(t)

	pool := requireIntegrationDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetCosignTables(t, ctx, pool)

	hs, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  []string{witnessURL},
		QuorumK:           1,
		PerWitnessTimeout: 5 * time.Second,
		NetworkID:         netID,
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	// time.Now().UnixNano() so every test run picks a tree_size
	// strictly greater than any value the witness daemon has
	// previously signed. The monotonicity guard inside the
	// daemon is per-process state and persists across test runs
	// while the container is alive — using a fixed value would
	// fail the second run (current run's value < lastSignedSize).
	head := types.TreeHead{
		TreeSize: uint64(time.Now().UnixNano()),
		RootHash: [32]byte{0xE2, 0xE2, 0x01},
	}

	timed, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cosigned, err := hs.RequestCosignatures(timed, head)
	if err != nil {
		t.Fatalf("RequestCosignatures against %s: %v", witnessURL, err)
	}

	if cosigned.TreeSize != head.TreeSize {
		t.Errorf("returned TreeSize = %d, want %d", cosigned.TreeSize, head.TreeSize)
	}
	if cosigned.RootHash != head.RootHash {
		t.Errorf("returned RootHash = %x, want %x", cosigned.RootHash, head.RootHash)
	}
	if len(cosigned.Signatures) != 1 {
		t.Errorf("len(Signatures) = %d, want 1 (K=1 e2e topology)", len(cosigned.Signatures))
	}

	// Persistence assertion against real Postgres.
	var sigCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tree_head_sigs WHERE tree_size = $1`,
		head.TreeSize,
	).Scan(&sigCount); err != nil {
		t.Fatalf("query tree_head_sigs: %v", err)
	}
	if sigCount != 1 {
		t.Errorf("persisted sigs for tree_size=%d: %d, want 1", head.TreeSize, sigCount)
	}
}

// TestE2E_RollbackRejectedAt409 pins the witness daemon's
// monotonicity guard via real HTTP. After signing tree_size=5000
// the daemon MUST refuse a subsequent tree_size=100 request with
// 409 Conflict. Bypasses HeadSync — sends the WireRequest
// directly so we observe the raw HTTP response.
func TestE2E_RollbackRejectedAt409(t *testing.T) {
	witnessURL, netID := requireE2EEnv(t)

	cosignURL := witnessURL + cosign.DefaultCosignPath

	post := func(treeSize uint64) *http.Response {
		t.Helper()
		root := [32]byte{0xE2, 0xE2, byte(treeSize)}
		inner, err := json.Marshal(struct {
			RootHash string `json:"root_hash"`
			TreeSize uint64 `json:"tree_size"`
		}{
			RootHash: fmt.Sprintf("%x", root[:]),
			TreeSize: treeSize,
		})
		if err != nil {
			t.Fatalf("marshal inner: %v", err)
		}
		body, err := json.Marshal(cosign.WireRequest{
			Purpose:   cosign.PurposeTreeHead,
			Payload:   inner,
			NetworkID: cosign.NetworkIDToWire(netID),
			HashAlgo:  cosign.HashAlgoToWire(cosign.HashAlgoSHA256),
		})
		if err != nil {
			t.Fatalf("marshal wire: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cosignURL,
			bytes.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", cosignURL, err)
		}
		return resp
	}

	// Pick tree_size HIGHER than any prior test in this run AND
	// any prior `go test` run while the witness container has
	// been alive. The monotonicity guard inside the daemon is in-
	// memory + persists across test runs; only nuking the
	// container resets it. time.Now().UnixNano() guarantees
	// strict monotonicity across runs without coordination.
	priming := uint64(time.Now().UnixNano())
	rollback := priming - 100_000 // < priming, but still big

	r1 := post(priming)
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("priming POST size=%d: status=%d, want 200", priming, r1.StatusCode)
	}

	r2 := post(rollback)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		t.Errorf("rollback POST size=%d after %d: status=%d, want 409 Conflict",
			rollback, priming, r2.StatusCode)
	}

	// Belt-and-braces: the response body should be a WireError.
	var werr cosign.WireError
	if err := json.NewDecoder(r2.Body).Decode(&werr); err != nil {
		t.Fatalf("decode WireError: %v", err)
	}
	if werr.Error == "" {
		t.Errorf("WireError.Error is empty; expected diagnostic")
	}
	// Don't assert on err string — guard returns
	// "tree_size rollback rejected: ..." but not a stable contract.
}
