/*
FILE PATH: gossipnet/escrow_override_test.go

Smoke tests for EscrowOverrideService. The end-to-end flow
(K-of-N collection → gossip publish) is exercised against a
stub witness peer + an in-memory gossip Store.
*/
package gossipnet

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
)

// stubCosignServer returns one signed cosign response per request,
// produced by the supplied witness signer over the wire payload.
// Matches the SDK's /v1/cosign WireResponse shape.
func stubCosignServer(t *testing.T, signer cosign.WitnessSigner, networkID cosign.NetworkID) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req cosign.WireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		// Decode payload using the SDK's shared decoder so the
		// stub speaks every registered Purpose.
		payload, err := cosign.DecodeWirePayload(req.Purpose, req.Payload)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		nid, err := cosign.NetworkIDFromWire(req.NetworkID)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = nid // we ignore — single-network test fixture
		algo := cosign.HashAlgoSHA256
		sig, err := signer.Sign(payload, networkID, algo)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cosign.WitnessSignatureToWire(sig))
	}))
}

func TestEscrowOverrideService_HappyPath(t *testing.T) {
	netID := nonZeroNetworkID()

	// One witness produces all K signatures (K=1 for the
	// fixture's simplicity; same code path serves K>1 with more
	// witnesses).
	witKP, _ := did.GenerateDIDKeySecp256k1()
	witSigner := cosign.NewECDSAWitnessSigner(witKP.PrivateKey)
	srv := stubCosignServer(t, witSigner, netID)
	defer srv.Close()

	client, err := cosign.NewWitnessClient(srv.URL, netID)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := cosign.NewWitnessCollector([]*cosign.WitnessClient{client}, 1)
	if err != nil {
		t.Fatal(err)
	}

	opKP, _ := did.GenerateDIDKeySecp256k1()
	opSigner := cosign.NewECDSAWitnessSigner(opKP.PrivateKey)

	store := sdkgossip.NewInMemoryStore()
	svc, err := NewEscrowOverrideService(EscrowOverrideServiceConfig{
		Collector:  collector,
		Store:      store,
		Sink:       sdkgossip.NopSink,
		Signer:     opSigner,
		NetworkID:  netID,
		Originator: opKP.DID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var escrowID, decisionHash [32]byte
	for i := range escrowID {
		escrowID[i] = byte(i)
		decisionHash[i] = byte(0xFF - i)
	}
	res, err := svc.ProcessOverride(context.Background(), escrowID, decisionHash, 1700000000)
	if err != nil {
		t.Fatalf("ProcessOverride: %v", err)
	}
	if res.Signatures != 1 {
		t.Errorf("Signatures = %d, want 1", res.Signatures)
	}
	if res.Lamport != 1 {
		t.Errorf("Lamport = %d, want 1 (first event in ledger chain)", res.Lamport)
	}
	if res.EventID == [32]byte{} {
		t.Error("EventID is zero")
	}

	// Local store should have one event of KindEscrowOverrideAuth.
	got, err := store.Get(context.Background(), res.EventID)
	if err != nil {
		t.Fatalf("Get appended event: %v", err)
	}
	if got.Kind != sdkgossip.KindEscrowOverrideAuth {
		t.Errorf("Kind = %s, want KindEscrowOverrideAuth", got.Kind)
	}
}

func TestEscrowOverrideService_RejectsConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg EscrowOverrideServiceConfig
		want string
	}{
		{
			name: "nil collector",
			cfg: EscrowOverrideServiceConfig{
				Store: sdkgossip.NewInMemoryStore(),
				Sink:  sdkgossip.NopSink,
				Signer: cosign.NewECDSAWitnessSigner(
					mustGenKey(t)),
				NetworkID:  nonZeroNetworkID(),
				Originator: "did:web:x",
			},
			want: "Collector",
		},
		{
			name: "empty originator",
			cfg: EscrowOverrideServiceConfig{
				Collector:  &cosign.WitnessCollector{},
				Store:      sdkgossip.NewInMemoryStore(),
				Sink:       sdkgossip.NopSink,
				Signer:     cosign.NewECDSAWitnessSigner(mustGenKey(t)),
				NetworkID:  nonZeroNetworkID(),
				Originator: "",
			},
			want: "Originator",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEscrowOverrideService(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want contains %q", err, tc.want)
			}
		})
	}
}

// mustGenKey is a tiny helper to mint an ECDSA private key for
// the fixture's WitnessSigner construction.
func mustGenKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	return kp.PrivateKey
}
