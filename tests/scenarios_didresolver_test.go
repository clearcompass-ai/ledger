//go:build scenarios

/*
FILE PATH:
    tests/scenarios_didresolver_test.go

DESCRIPTION:
    Mock DID resolver for the Layer 0 scenarios suite. Topology in this
    architecture is W3C-DID-anchored: an auditor extracts a LogDID,
    passes it to a did.DIDResolver, and reads the returned DIDDocument's
    Service array to find the ledger / witness / CDN URLs. There is no
    centralized "topology registry" — routing is identity physics.

KEY ARCHITECTURAL DECISIONS:
    - Implements the SDK's did.DIDResolver interface (single method
      `Resolve(did string) (*did.DIDDocument, error)`). Auditor / peer
      / fraud-bot composites consume the resolver verbatim; production
      wires the SDK's WebDIDResolver or KeyResolver behind the same
      interface, so tests prove the wire shape works without coupling
      to a particular DID method.
    - Documents follow the SDK's DIDDocument layout exactly, including
      the Attesta extensions (witness_endpoints / ledger_endpoint /
      WitnessQuorumK) so DIDDocument.LedgerEndpointURL() and
      WitnessEndpointURLs() return values the auditor can consume.
    - Goroutine-safe via sync.RWMutex. Persona tests run multiple
      auditors in parallel against one resolver instance.
    - No fast path. The auditor calls Resolve on every endpoint
      lookup; production wraps the resolver in did.CachingResolver
      with explicit TTL — the test resolver does NOT cache, so
      tests can mutate bindings and observe immediate effects.

OVERVIEW:
    NewMockDIDResolver(t)              → fresh resolver, empty map.
    Bind(logDID, urls)                 → install one DIDDocument
                                         carrying ledger / cdn /
                                         witness service entries.
    Rotate(logDID, urls)               → replace document; the
                                         older binding is gone (a
                                         resolver mock, not a chain).
    Resolve(did)                       → SDK DIDResolver method;
                                         returns the installed doc
                                         or did.ErrDIDDocumentNotFound.
    AuditorAdapter()                   → wraps in did.DIDEndpointAdapter.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/attesta/did: DIDResolver, DIDDocument,
      Service, DIDEndpointAdapter.
*/
package tests

import (
	"errors"
	"sync"
	"testing"

	"github.com/clearcompass-ai/attesta/did"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

var (
	errMockDIDNotFound = errors.New("mockDIDResolver: DID not bound")
	errMockDIDEmpty    = errors.New("mockDIDResolver: empty DID")
)

// -------------------------------------------------------------------------------------------------
// 3) Endpoint bundle — one bind covers every URL an auditor needs
// -------------------------------------------------------------------------------------------------

// endpointBundle is the set of URLs a LogDID resolves to. Every
// field is optional but at least one must be set; tests that only
// need a ledger URL leave the others empty.
type endpointBundle struct {
	LedgerURL    string   // "AttestaLedgerEndpoint" service entry.
	CDNURL       string   // "AttestaArtifactStore" service entry.
	WitnessURLs  []string // "AttestaWitnessEndpoint" service entries.
	WitnessQuorumK int    // populates DIDDocument.WitnessQuorumK.
}

// -------------------------------------------------------------------------------------------------
// 4) mockDIDResolver — the resolver
// -------------------------------------------------------------------------------------------------

// mockDIDResolver is a goroutine-safe in-memory did.DIDResolver.
// One instance per persona test (or shared across composite
// scenarios that need cross-DID resolution).
type mockDIDResolver struct {
	mu   sync.RWMutex
	docs map[string]*did.DIDDocument
}

// newMockDIDResolver returns an empty resolver. Compile-time
// proof of interface conformance: every persona test passes the
// returned value into a `var _ did.DIDResolver = ...` slot before
// using it (see TestMockDIDResolver_Conformance below).
func newMockDIDResolver(t *testing.T) *mockDIDResolver {
	t.Helper()
	return &mockDIDResolver{docs: make(map[string]*did.DIDDocument)}
}

// -------------------------------------------------------------------------------------------------
// 5) Bind / Rotate
// -------------------------------------------------------------------------------------------------

// Bind installs a DIDDocument for logDID. The document carries one
// Service per URL provided. Subsequent calls to Resolve(logDID)
// return this document.
func (m *mockDIDResolver) Bind(t *testing.T, logDID string, b endpointBundle) {
	t.Helper()
	if logDID == "" {
		t.Fatal("Bind: empty logDID")
	}
	doc := &did.DIDDocument{
		Context:        []string{"https://www.w3.org/ns/did/v1"},
		ID:             logDID,
		WitnessQuorumK: b.WitnessQuorumK,
	}
	if b.LedgerURL != "" {
		doc.Service = append(doc.Service, did.Service{
			ID:              logDID + "#ledger",
			Type:            did.ServiceTypeLedger,
			ServiceEndpoint: b.LedgerURL,
		})
	}
	if b.CDNURL != "" {
		doc.Service = append(doc.Service, did.Service{
			ID:              logDID + "#cdn",
			Type:            did.ServiceTypeArtifactStore,
			ServiceEndpoint: b.CDNURL,
		})
	}
	for i, w := range b.WitnessURLs {
		doc.Service = append(doc.Service, did.Service{
			ID:              logDID + "#witness-" + itoaScenario(i),
			Type:            did.ServiceTypeWitness,
			ServiceEndpoint: w,
		})
	}
	if len(doc.Service) == 0 {
		t.Fatal("Bind: bundle has no endpoints")
	}
	m.mu.Lock()
	m.docs[logDID] = doc
	m.mu.Unlock()
}

// Rotate replaces an existing binding with a new bundle. The old
// document is discarded — the SDK's CachingResolver in production
// is responsible for cache eviction; the mock does not cache.
func (m *mockDIDResolver) Rotate(t *testing.T, logDID string, b endpointBundle) {
	t.Helper()
	m.mu.RLock()
	_, exists := m.docs[logDID]
	m.mu.RUnlock()
	if !exists {
		t.Fatalf("Rotate: %s not bound", logDID)
	}
	// Drop and re-bind. Bind validates and re-locks under the
	// write mutex.
	m.mu.Lock()
	delete(m.docs, logDID)
	m.mu.Unlock()
	m.Bind(t, logDID, b)
}

// -------------------------------------------------------------------------------------------------
// 6) Resolve — the DIDResolver interface implementation
// -------------------------------------------------------------------------------------------------

// Resolve satisfies did.DIDResolver. Production wires
// did.WebDIDResolver / did.KeyResolver behind the same shape; the
// auditor / peer / fraud-bot consumers see identical behavior.
func (m *mockDIDResolver) Resolve(didStr string) (*did.DIDDocument, error) {
	if didStr == "" {
		return nil, errMockDIDEmpty
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.docs[didStr]
	if !ok {
		return nil, errMockDIDNotFound
	}
	// Defensive copy to defeat caller mutation.
	dup := *doc
	dup.Service = append([]did.Service(nil), doc.Service...)
	return &dup, nil
}

// -------------------------------------------------------------------------------------------------
// 7) Adapter for auditor / peer consumers
// -------------------------------------------------------------------------------------------------

// AuditorAdapter wraps the resolver in the SDK's
// DIDEndpointAdapter so consumers get the higher-level
// LedgerEndpoint(logDID) and WitnessEndpoints(logDID) helpers
// without re-implementing the Service-array walk.
func (m *mockDIDResolver) AuditorAdapter() *did.DIDEndpointAdapter {
	return &did.DIDEndpointAdapter{Resolver: m}
}

// -------------------------------------------------------------------------------------------------
// 8) Tamper helper for adversarial tests
// -------------------------------------------------------------------------------------------------

// TamperLedgerEndpoint corrupts the LedgerEndpoint URL on the
// stored document, simulating a malicious DID-doc server.
// Adversarial fixture; happy paths use Rotate instead.
func (m *mockDIDResolver) TamperLedgerEndpoint(t *testing.T, logDID, fakeURL string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, ok := m.docs[logDID]
	if !ok {
		t.Fatalf("Tamper: %s not bound", logDID)
	}
	for i, s := range doc.Service {
		if s.Type == did.ServiceTypeLedger {
			doc.Service[i].ServiceEndpoint = fakeURL
			return
		}
	}
	t.Fatalf("Tamper: %s has no LedgerEndpoint to tamper", logDID)
}

// -------------------------------------------------------------------------------------------------
// 9) Tests — coverage gate
// -------------------------------------------------------------------------------------------------

// TestMockDIDResolver_Conformance proves the mock satisfies the
// did.DIDResolver interface at compile time and exercises the
// Bind / Resolve / Rotate / Tamper happy and adversarial paths.
func TestMockDIDResolver_Conformance(t *testing.T) {
	var _ did.DIDResolver = (*mockDIDResolver)(nil)

	r := newMockDIDResolver(t)
	logDID := scenarioLogDIDPrefix + ":resolver"

	// Empty DID rejected.
	if _, err := r.Resolve(""); !errors.Is(err, errMockDIDEmpty) {
		t.Fatalf("empty DID: err=%v, want errMockDIDEmpty", err)
	}
	// Unbound DID rejected.
	if _, err := r.Resolve(logDID); !errors.Is(err, errMockDIDNotFound) {
		t.Fatalf("unbound: err=%v, want errMockDIDNotFound", err)
	}

	// Bind a full bundle and round-trip.
	r.Bind(t, logDID, endpointBundle{
		LedgerURL:      "https://l.test/v1",
		CDNURL:         "https://cdn.test/log",
		WitnessURLs:    []string{"https://w1.test", "https://w2.test", "https://w3.test"},
		WitnessQuorumK: 2,
	})
	doc, err := r.Resolve(logDID)
	mustNotErr(t, "resolve", err)
	if doc.ID != logDID {
		t.Fatalf("doc.ID = %q, want %q", doc.ID, logDID)
	}
	if doc.WitnessQuorumK != 2 {
		t.Fatalf("WitnessQuorumK = %d, want 2", doc.WitnessQuorumK)
	}
	if len(doc.Service) != 5 { // 1 ledger + 1 cdn + 3 witnesses.
		t.Fatalf("Service count = %d, want 5", len(doc.Service))
	}

	// SDK helper round-trip.
	url, err := doc.LedgerEndpointURL()
	mustNotErr(t, "LedgerEndpointURL", err)
	if url != "https://l.test/v1" {
		t.Fatalf("LedgerEndpointURL = %q, want l.test/v1", url)
	}
	wEs := doc.WitnessEndpointURLs()
	if len(wEs) != 3 {
		t.Fatalf("WitnessEndpointURLs len = %d, want 3", len(wEs))
	}

	// Adapter round-trip.
	adapter := r.AuditorAdapter()
	if got, _ := adapter.LedgerEndpoint(logDID); got != "https://l.test/v1" {
		t.Fatalf("adapter LedgerEndpoint = %q", got)
	}

	// Defensive copy: mutating returned slice does NOT affect store.
	doc.Service = nil
	doc2, err := r.Resolve(logDID)
	mustNotErr(t, "resolve again", err)
	if len(doc2.Service) != 5 {
		t.Fatalf("post-mutation Service count = %d, want 5 (defensive copy broken)", len(doc2.Service))
	}

	// Rotate replaces.
	r.Rotate(t, logDID, endpointBundle{LedgerURL: "https://l2.test/v1"})
	doc3, err := r.Resolve(logDID)
	mustNotErr(t, "resolve after rotate", err)
	if got, _ := doc3.LedgerEndpointURL(); got != "https://l2.test/v1" {
		t.Fatalf("post-rotate LedgerEndpointURL = %q", got)
	}

	// Tamper.
	r.TamperLedgerEndpoint(t, logDID, "https://attacker.test")
	doc4, _ := r.Resolve(logDID)
	if got, _ := doc4.LedgerEndpointURL(); got != "https://attacker.test" {
		t.Fatalf("Tamper failed to take: %q", got)
	}
}

// itoaScenario is a stdlib-free integer formatter for the
// resolver's service IDs. The base-`tests` package already
// declares an `itoa`; the scenarios suite uses a distinct
// name to avoid the //go:build scenarios redeclaration.
func itoaScenario(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := make([]byte, 0, 8)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
