// FILE PATH: tests/witness_fixture_test.go
//
// Real httptest cosign-server fixture for ledger tests.
//
// Replaces the deleted stubWitnessCosigner. Builds N httptest
// servers each running cosign.NewWitnessHandler from the SDK with
// a freshly-generated ECDSA key. Tests wire a
// witnessclient.NewHeadSync against the fixture's URLs and
// exercise the full HTTP cosign collection path against real
// witness handlers.
//
// PHYSICS: there is no mock layer between the Ledger's HeadSync
// and the SDK's witness handler. The Ledger POSTs JSON, the
// witness signs with a real key, the response carries a real
// types.WitnessSignature. PublishCosignedCheckpoint then writes
// the cosigned head to disk via the real EmbeddedAppender.
//
// USAGE:
//
//	netID := nonZeroTestNetworkID()
//	wfx := newWitnessFixture(t, netID, 3)  // 3 witnesses
//	hs, _ := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
//	    WitnessEndpoints:  wfx.URLs(),
//	    QuorumK:           2,
//	    PerWitnessTimeout: 2 * time.Second,
//	    NetworkID:         netID,
//	}, treeHeadStore, logger)
package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
)

// witnessFixture bundles N synthetic witnesses behind httptest
// servers. Each witness has its own ECDSA key + URL. Test code
// pulls URLs() to feed HeadSyncConfig.WitnessEndpoints, and DIDs()
// when constructing a network bootstrap document or
// cosign.WitnessKeySet.
type witnessFixture struct {
	t       *testing.T
	netID   cosign.NetworkID
	servers []*httptest.Server
	signers []cosign.WitnessSigner
	pubKeys []types.WitnessPublicKey
}

// newWitnessFixture spins up n httptest cosign servers under the
// supplied NetworkID. Cleanup is registered via t.Cleanup; the
// caller doesn't need to defer Close.
func newWitnessFixture(t *testing.T, netID cosign.NetworkID, n int) *witnessFixture {
	t.Helper()
	if n < 1 {
		t.Fatalf("newWitnessFixture: n must be >= 1, got %d", n)
	}
	wf := &witnessFixture{
		t:       t,
		netID:   netID,
		servers: make([]*httptest.Server, 0, n),
		signers: make([]cosign.WitnessSigner, 0, n),
		pubKeys: make([]types.WitnessPublicKey, 0, n),
	}
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("witnessFixture: generate key %d: %v", i, err)
		}
		signer := cosign.NewECDSAWitnessSigner(priv)

		handler, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
			Signer:          signer,
			AllowedNetworks: map[cosign.NetworkID]struct{}{netID: {}},
		})
		if err != nil {
			t.Fatalf("witnessFixture: NewWitnessHandler %d: %v", i, err)
		}
		mux := http.NewServeMux()
		mux.Handle(cosign.DefaultCosignPath, handler)
		srv := httptest.NewServer(mux)

		wf.servers = append(wf.servers, srv)
		wf.signers = append(wf.signers, signer)
		// Public-key bytes: x||y uncompressed. The
		// witness.KeysFromDIDs path (attesta v1.2) used by
		// production resolves did:key into the same form; here we
		// construct it directly from the test signer's underlying
		// key.
		pub := append(priv.X.Bytes(), priv.Y.Bytes()...)
		wf.pubKeys = append(wf.pubKeys, types.WitnessPublicKey{
			ID:        signer.PubKeyID(),
			PublicKey: pub,
		})
	}
	t.Cleanup(wf.close)
	return wf
}

// URLs returns the n test-server base URLs in construction order.
// Suitable for HeadSyncConfig.WitnessEndpoints.
func (wf *witnessFixture) URLs() []string {
	out := make([]string, len(wf.servers))
	for i, s := range wf.servers {
		out[i] = s.URL
	}
	return out
}

// PublicKeys returns the n witness public-key records. Suitable
// for cosign.NewWitnessKeySet when a test wants to verify
// CosignedTreeHead values directly.
func (wf *witnessFixture) PublicKeys() []types.WitnessPublicKey {
	out := make([]types.WitnessPublicKey, len(wf.pubKeys))
	copy(out, wf.pubKeys)
	return out
}

// CloseAt closes the i-th witness's httptest server, simulating
// "this witness is offline". Used by quorum-failure tests
// (P4.4 matrix). After CloseAt, RequestSignature against the
// closed URL surfaces ECONNREFUSED, which the SDK collector
// counts as a per-endpoint failure.
func (wf *witnessFixture) CloseAt(i int) {
	if i < 0 || i >= len(wf.servers) {
		return
	}
	wf.servers[i].Close()
}

// close shuts down every httptest server. Idempotent.
func (wf *witnessFixture) close() {
	for _, s := range wf.servers {
		if s != nil {
			s.Close()
		}
	}
}

// nonZeroTestNetworkID returns a deterministic non-zero
// NetworkID for tests. Distinct from production NetworkIDs;
// rejects cross-test pollination since cosign.NewWitnessHandler
// rejects requests whose network_id is not in AllowedNetworks.
func nonZeroTestNetworkID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(0x80 | (i & 0x7F))
	}
	return n
}
