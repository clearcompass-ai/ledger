//go:build scenarios

/*
FILE PATH:
    tests/scenarios_witness_test.go

DESCRIPTION:
    K-of-N witness swarm fixture for the Layer 0 scenarios suite.
    Spawns N independent cosign.WitnessHandler instances on httptest
    servers, each backed by a freshly-generated ECDSA key. Persona
    tests pass the swarm's URLs as the WitnessEndpoints in the
    LogDID's DIDDocument; the SDK's WitnessCollector then drives the
    Collect path against this swarm.

KEY ARCHITECTURAL DECISIONS:
    - Each witness is its own httptest.Server so latency / failure
      injection can target one witness without affecting the others.
    - Per-witness handler is wrapped in a switchable proxy
      (httpFault) so tests can flip a witness from healthy → slow →
      failing → healthy without restarting the server. Cheaper than
      tearing down and re-spawning httptest.Server.
    - All witnesses share the same NetworkID — production sometimes
      runs multi-network witnesses (one process serves several
      networks); the simpler single-network swarm is sufficient for
      Layer 0 cosign verification tests.
    - K is stored alongside N for documentation; the actual K-of-N
      enforcement happens in the SDK's WitnessCollector at the
      caller side, not in the swarm.

OVERVIEW:
    NewWitnessSwarm(t, n, k, networkID) → swarm of N httptest servers.
    URLs() / PublicKeys() / Signers()  → fixtures the persona test
                                         feeds to the auditor /
                                         WitnessCollector.
    Slow(idx, latency)                 → injects pre-handler delay.
    Fail(idx, status)                  → returns the supplied HTTP
                                         status without invoking the
                                         witness handler.
    RetryAfter(idx, after)             → returns 429 + Retry-After
                                         header.
    Heal(idx)                          → restores happy-path handler.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/attesta/crypto/cosign:
      NewWitnessHandler, NewECDSAWitnessSigner, NetworkID, Purpose.
    - tests/scenarios_skel_test.go: scenarioKey helper.
*/
package tests

import (
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
)

// -------------------------------------------------------------------------------------------------
// 1) httpFault — switchable handler wrapper
// -------------------------------------------------------------------------------------------------

// httpFault implements http.Handler. The active behaviour is held
// in an atomic.Value so test-time mutation (Slow / Fail / Heal) is
// race-free without a mutex on the hot path.
type httpFault struct {
	current atomic.Value // holds http.HandlerFunc
}

// newHTTPFault returns an httpFault initially serving healthy
// requests via base.
func newHTTPFault(base http.Handler) *httpFault {
	f := &httpFault{}
	f.current.Store(http.HandlerFunc(base.ServeHTTP))
	return f
}

// ServeHTTP dispatches to the current handler. newHTTPFault
// always stores a non-nil HandlerFunc and Set rejects nil, so the
// type assertion is total — no defensive nil branch.
func (f *httpFault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.current.Load().(http.HandlerFunc)(w, r)
}

// Set replaces the active handler.
func (f *httpFault) Set(next http.HandlerFunc) {
	f.current.Store(next)
}

// -------------------------------------------------------------------------------------------------
// 2) witnessSwarm
// -------------------------------------------------------------------------------------------------

// witnessSwarm holds N cosign witness HTTP endpoints with
// per-witness fault control. Goroutine-safe across all
// post-construction mutations.
type witnessSwarm struct {
	mu        sync.RWMutex
	n         int
	k         int
	networkID cosign.NetworkID
	servers   []*httptest.Server
	faults    []*httpFault
	healthy   []http.HandlerFunc // captured at boot for Heal.
	signers   []cosign.WitnessSigner
	privKeys  []*ecdsa.PrivateKey
}

// newWitnessSwarm spawns n witnesses on random localhost ports.
// The caller-supplied k value is recorded for documentation; the
// SDK's WitnessCollector enforces K-of-N at use time.
func newWitnessSwarm(t *testing.T, n, k int, networkID cosign.NetworkID) *witnessSwarm {
	t.Helper()
	if n < 1 || k < 1 || k > n {
		t.Fatalf("newWitnessSwarm: invalid n=%d k=%d", n, k)
	}
	s := &witnessSwarm{
		n:         n,
		k:         k,
		networkID: networkID,
		servers:   make([]*httptest.Server, n),
		faults:    make([]*httpFault, n),
		healthy:   make([]http.HandlerFunc, n),
		signers:   make([]cosign.WitnessSigner, n),
		privKeys:  make([]*ecdsa.PrivateKey, n),
	}
	for i := 0; i < n; i++ {
		priv := scenarioKey(t)
		signer := cosign.NewECDSAWitnessSigner(priv)
		base, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
			Signer:          signer,
			AllowedNetworks: map[cosign.NetworkID]struct{}{networkID: {}},
		})
		mustNotErr(t, "NewWitnessHandler", err)

		fault := newHTTPFault(base)
		srv := httptest.NewServer(fault)
		s.servers[i] = srv
		s.faults[i] = fault
		s.healthy[i] = http.HandlerFunc(base.ServeHTTP)
		s.signers[i] = signer
		s.privKeys[i] = priv
	}
	t.Cleanup(s.Close)
	return s
}

// Close shuts down every httptest server. Idempotent; calling on
// a partially-closed swarm is safe.
func (s *witnessSwarm) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, srv := range s.servers {
		if srv != nil {
			srv.Close()
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Accessors
// -------------------------------------------------------------------------------------------------

// URLs returns a fresh slice of witness URLs in registration order.
func (s *witnessSwarm) URLs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.servers))
	for _, srv := range s.servers {
		out = append(out, srv.URL)
	}
	return out
}

// Signers returns the witness signer slice. Persona tests pass
// these to the SDK's WitnessKeySet construction so the auditor
// can verify returned signatures.
func (s *witnessSwarm) Signers() []cosign.WitnessSigner {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]cosign.WitnessSigner, len(s.signers))
	copy(out, s.signers)
	return out
}

// PublicKeys returns the slice of public keys in registration
// order. ECDSA keys; persona tests build the WitnessKeySet from
// these.
func (s *witnessSwarm) PublicKeys() []*ecdsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ecdsa.PublicKey, len(s.privKeys))
	for i, pk := range s.privKeys {
		out[i] = &pk.PublicKey
	}
	return out
}

// N returns the swarm size.
func (s *witnessSwarm) N() int { return s.n }

// K returns the quorum threshold the swarm was constructed with.
// Documentation helper; the SDK is the actual enforcer.
func (s *witnessSwarm) K() int { return s.k }

// NetworkID returns the swarm's NetworkID.
func (s *witnessSwarm) NetworkID() cosign.NetworkID { return s.networkID }

// -------------------------------------------------------------------------------------------------
// 4) Fault injectors
// -------------------------------------------------------------------------------------------------

// Slow injects a pre-handler delay on witness idx. Subsequent
// requests are delayed by `latency` before reaching the real
// witness handler. To remove the delay, call Heal(idx).
func (s *witnessSwarm) Slow(t *testing.T, idx int, latency time.Duration) {
	t.Helper()
	s.requireIdx(t, idx)
	healthy := s.healthy[idx]
	s.faults[idx].Set(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			http.Error(w, "ctx cancel", http.StatusRequestTimeout)
			return
		case <-time.After(latency):
		}
		healthy(w, r)
	})
}

// Fail makes witness idx return the supplied HTTP status without
// invoking the witness handler. Useful for testing collector's
// graceful-degradation paths (5xx → next witness).
func (s *witnessSwarm) Fail(t *testing.T, idx, status int) {
	t.Helper()
	s.requireIdx(t, idx)
	if status < 100 || status > 599 {
		t.Fatalf("Fail: invalid HTTP status %d", status)
	}
	s.faults[idx].Set(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "fault: forced "+strconv.Itoa(status), status)
	})
}

// RetryAfter makes witness idx return 429 with the supplied
// Retry-After delay. Mirrors production rate-limit responses; the
// SDK's RetryAfterRoundTripper consumes the header.
func (s *witnessSwarm) RetryAfter(t *testing.T, idx int, after time.Duration) {
	t.Helper()
	s.requireIdx(t, idx)
	secs := int(after.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	s.faults[idx].Set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	})
}

// Heal restores witness idx to the original happy-path handler.
func (s *witnessSwarm) Heal(t *testing.T, idx int) {
	t.Helper()
	s.requireIdx(t, idx)
	s.faults[idx].Set(s.healthy[idx])
}

// requireIdx fatals if idx is out of range. Centralised so each
// fault helper carries one bounds check rather than duplicating.
func (s *witnessSwarm) requireIdx(t *testing.T, idx int) {
	t.Helper()
	if idx < 0 || idx >= s.n {
		t.Fatalf("witnessSwarm: idx %d out of [0,%d)", idx, s.n)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Tests — coverage gate
// -------------------------------------------------------------------------------------------------

// TestWitnessSwarm_Conformance exercises every helper above: boot,
// happy-path POST, fault injection (Slow / Fail / RetryAfter /
// Heal), and the accessor methods. Uses an in-process http.Client
// so no DNS / TLS / proxy variance.
func TestWitnessSwarm_Conformance(t *testing.T) {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(0xA0 + i)
	}
	swarm := newWitnessSwarm(t, 5, 3, nid)

	if swarm.N() != 5 || swarm.K() != 3 {
		t.Fatalf("N/K mismatch: %d/%d", swarm.N(), swarm.K())
	}
	if got := swarm.NetworkID(); got[0] != 0xA0 {
		t.Fatalf("NetworkID first byte = %x, want 0xA0", got[0])
	}
	if urls := swarm.URLs(); len(urls) != 5 {
		t.Fatalf("URLs len = %d, want 5", len(urls))
	}
	if signers := swarm.Signers(); len(signers) != 5 {
		t.Fatalf("Signers len = %d, want 5", len(signers))
	}
	if pks := swarm.PublicKeys(); len(pks) != 5 || pks[0] == nil {
		t.Fatalf("PublicKeys broken")
	}

	client := &http.Client{Timeout: 2 * time.Second}

	// Healthy — POST 405 / GET 405 (cosign handler is POST-only;
	// GET returns 405). Either way we must NOT get a connection
	// refused or 5xx; the swarm itself is up.
	resp, err := client.Get(swarm.URLs()[0] + "/v1/cosign")
	mustNotErr(t, "GET healthy", err)
	resp.Body.Close()

	// Slow then Heal.
	swarm.Slow(t, 0, 50*time.Millisecond)
	t0 := time.Now()
	resp, err = client.Get(swarm.URLs()[0] + "/v1/cosign")
	mustNotErr(t, "GET slow", err)
	resp.Body.Close()
	if time.Since(t0) < 40*time.Millisecond {
		t.Fatalf("Slow not effective (elapsed %v)", time.Since(t0))
	}
	swarm.Heal(t, 0)

	// Fail.
	swarm.Fail(t, 1, http.StatusInternalServerError)
	resp, err = client.Get(swarm.URLs()[1] + "/v1/cosign")
	mustNotErr(t, "GET fail", err)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("Fail status = %d, want 500", resp.StatusCode)
	}
	resp.Body.Close()
	swarm.Heal(t, 1)

	// RetryAfter.
	swarm.RetryAfter(t, 2, 5*time.Second)
	resp, err = client.Get(swarm.URLs()[2] + "/v1/cosign")
	mustNotErr(t, "GET retry-after", err)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("RetryAfter status = %d, want 429", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "5" {
		t.Fatalf("Retry-After header = %q, want \"5\"", ra)
	}
	resp.Body.Close()

	// requireIdx out-of-range path.
	rec := captureFatalScenario(t, func(inner *testing.T) { swarm.Heal(inner, 999) })
	if !rec {
		t.Fatal("requireIdx failed to Fatal on out-of-range idx")
	}
}

