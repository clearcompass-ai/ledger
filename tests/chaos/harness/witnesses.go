/*
FILE PATH: tests/chaos/harness/witnesses.go

In-process witness fixture for chaos tests. Spawns N httptest.Server
instances each running a real cosign.WitnessHandler with a fresh
secp256k1 ECDSA key. The subprocess ledger reaches them over
localhost via the URLs returned from URLs().

Pattern adapted from tests/scenarios_witness_test.go's
witnessSwarm — same atomic.Value-based per-witness handler so
Fail / Slow / Heal mutations are lock-free on the hot path. Lives
here (non-_test.go, exported) so chaos test packages outside
package tests can construct + drive it.

WHY IN-PROCESS

The chaos suite is testing the LEDGER's recovery under SIGKILL,
not the witnesses'. Running witnesses as subprocesses too would
add 2N more process management surface for zero additional
signal. In-process httptest.Server binds to a random localhost
port; the subprocess ledger connects to that port over TCP same
as it would a real witness — the wire is identical.

LIFETIME

  - Construct via NewWitnesses(t, n, k, networkID). Server URLs +
    DIDs available immediately.
  - URLs() returns the witness endpoint list to pass into
    LEDGER_WITNESS_ENDPOINTS env var.
  - DIDs() returns the witness DIDs to include in bootstrap.json's
    genesis_witness_set field.
  - Close() shuts down every httptest server. Registered via
    t.Cleanup so callers don't have to manage it explicitly.

FAULT INJECTION

  - Fail(i, statusCode) — witness i returns the supplied status
    for every request until Heal(i) is called.
  - Slow(i, delay) — witness i sleeps `delay` before serving each
    request. Used to test "K-of-N with one slow witness" timing.
  - Heal(i) — restore witness i to the healthy signing handler.

All mutations are race-free against in-flight requests via the
atomic.Value handler swap.
*/
package harness

import (
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkcryptosigs "github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkdid "github.com/clearcompass-ai/attesta/did"
)

// Witnesses is a set of N in-process witness HTTP servers with
// per-witness fault injection. All methods are safe to call
// concurrently after construction.
type Witnesses struct {
	mu        sync.RWMutex
	n         int
	k         int
	networkID cosign.NetworkID
	servers   []*httptest.Server
	faults    []*httpFault
	healthy   []http.HandlerFunc
	signers   []cosign.WitnessSigner
	privKeys  []*ecdsa.PrivateKey
	dids      []string
}

// NewWitnesses spawns n witness servers and registers cleanup via
// t.Cleanup. n must be >= k >= 1. Each witness gets a fresh
// secp256k1 key + corresponding did:key DID.
func NewWitnesses(t *testing.T, n, k int, networkID cosign.NetworkID) *Witnesses {
	t.Helper()
	if n < 1 || k < 1 || k > n {
		t.Fatalf("NewWitnesses: invalid n=%d k=%d", n, k)
	}
	w := &Witnesses{
		n:         n,
		k:         k,
		networkID: networkID,
		servers:   make([]*httptest.Server, n),
		faults:    make([]*httpFault, n),
		healthy:   make([]http.HandlerFunc, n),
		signers:   make([]cosign.WitnessSigner, n),
		privKeys:  make([]*ecdsa.PrivateKey, n),
		dids:      make([]string, n),
	}
	for i := 0; i < n; i++ {
		priv, err := sdkcryptosigs.GenerateKey()
		if err != nil {
			t.Fatalf("witness %d: GenerateKey: %v", i, err)
		}
		signer := cosign.NewECDSAWitnessSigner(priv)
		base, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
			Signer:          signer,
			AllowedNetworks: map[cosign.NetworkID]struct{}{networkID: {}},
		})
		if err != nil {
			t.Fatalf("witness %d: NewWitnessHandler: %v", i, err)
		}
		did, err := didKeyFromPriv(priv)
		if err != nil {
			t.Fatalf("witness %d: derive did:key: %v", i, err)
		}

		fault := newHTTPFault(base)
		mux := http.NewServeMux()
		mux.Handle(cosign.DefaultCosignPath, fault)
		srv := httptest.NewServer(mux)

		w.servers[i] = srv
		w.faults[i] = fault
		w.healthy[i] = http.HandlerFunc(base.ServeHTTP)
		w.signers[i] = signer
		w.privKeys[i] = priv
		w.dids[i] = did
	}
	t.Cleanup(w.Close)
	return w
}

// Close shuts down every witness server. Idempotent; safe to
// call multiple times.
func (w *Witnesses) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, srv := range w.servers {
		if srv != nil {
			srv.Close()
			w.servers[i] = nil
		}
	}
}

// URLs returns a fresh slice of witness HTTP base URLs in
// registration order. Pass this comma-joined into
// LEDGER_WITNESS_ENDPOINTS.
func (w *Witnesses) URLs() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]string, 0, len(w.servers))
	for _, srv := range w.servers {
		if srv != nil {
			out = append(out, srv.URL)
		}
	}
	return out
}

// DIDs returns the witness did:key DIDs in registration order.
// Pass this into bootstrap.json's genesis_witness_set field.
func (w *Witnesses) DIDs() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]string, len(w.dids))
	copy(out, w.dids)
	return out
}

// N returns the witness count.
func (w *Witnesses) N() int { return w.n }

// K returns the quorum value the caller specified at construction.
// The ledger enforces this via LEDGER_WITNESS_QUORUM_K.
func (w *Witnesses) K() int { return w.k }

// NetworkID returns the cosign.NetworkID this swarm validates.
func (w *Witnesses) NetworkID() cosign.NetworkID { return w.networkID }

// Fail swaps witness i's handler with one that returns the
// supplied HTTP status for every request. Use Heal(i) to revert.
func (w *Witnesses) Fail(i int, status int) {
	w.faults[i].Set(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, http.StatusText(status), status)
	})
}

// Slow wraps witness i's handler with a pre-serve sleep.
// Used to test "K-of-N with one slow witness" scheduling.
func (w *Witnesses) Slow(i int, delay time.Duration) {
	healthy := w.healthy[i]
	w.faults[i].Set(func(rw http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		healthy(rw, r)
	})
}

// Heal restores witness i to its healthy signing handler. Safe to
// call on an already-healthy witness.
func (w *Witnesses) Heal(i int) {
	w.faults[i].Set(w.healthy[i])
}

// FailAll convenience — fail every witness with status.
func (w *Witnesses) FailAll(status int) {
	for i := 0; i < w.n; i++ {
		w.Fail(i, status)
	}
}

// HealAll restores every witness.
func (w *Witnesses) HealAll() {
	for i := 0; i < w.n; i++ {
		w.Heal(i)
	}
}

// rebindNetworkID rebuilds each witness's cosign handler with a
// fresh AllowedNetworks containing netID. The signing keys are
// preserved — only the network-allowlist changes. Used by the
// harness's two-phase construction (witnesses created before
// the bootstrap doc's NetworkID is known, then re-bound once
// the bootstrap is finalised).
func (w *Witnesses) rebindNetworkID(t *testing.T, netID cosign.NetworkID) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.networkID = netID
	for i, signer := range w.signers {
		base, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
			Signer:          signer,
			AllowedNetworks: map[cosign.NetworkID]struct{}{netID: {}},
		})
		if err != nil {
			t.Fatalf("rebind witness %d: %v", i, err)
		}
		w.healthy[i] = http.HandlerFunc(base.ServeHTTP)
		w.faults[i].Set(w.healthy[i])
	}
}

// ─────────────────────────────────────────────────────────────────────
// httpFault — atomic handler swap, pattern from witnessSwarm
// ─────────────────────────────────────────────────────────────────────

// httpFault is an http.Handler whose ServeHTTP delegates to an
// atomically-swappable inner handler. Mutating the inner handler
// (Set) is race-free against in-flight ServeHTTP calls.
type httpFault struct {
	current atomic.Value // holds http.HandlerFunc
}

func newHTTPFault(base http.Handler) *httpFault {
	f := &httpFault{}
	f.current.Store(http.HandlerFunc(base.ServeHTTP))
	return f
}

func (f *httpFault) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	f.current.Load().(http.HandlerFunc)(rw, r)
}

func (f *httpFault) Set(next http.HandlerFunc) {
	f.current.Store(next)
}

// ─────────────────────────────────────────────────────────────────────
// did:key derivation — same multibase+multicodec the ledger uses
// ─────────────────────────────────────────────────────────────────────

// didKeyFromPriv derives the did:key:z... identifier from a
// secp256k1 private key. Mirrors cmd/ledger/signers.go's
// didKeyFromSecp256k1Priv so witness DIDs match what the ledger
// would compute from the same key.
func didKeyFromPriv(priv *ecdsa.PrivateKey) (string, error) {
	uncompressed := sdkcryptosigs.PubKeyBytes(&priv.PublicKey)
	compressed, err := sdkcryptosigs.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		return "", err
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), nil
}
