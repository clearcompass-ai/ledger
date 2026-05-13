/*
FILE PATH:

	admission/evidence_chain_verifier_test.go

DESCRIPTION:

	Binding tests for PR-F gate 4 — admission.VerifyEvidenceChainSurgical
	+ admission.ShouldWalkEvidenceChain.

	Two load-bearing properties:

	  1. Surgical predicate: walks fire ONLY for Path C
	     (scope-authority) entries. Path A / Path B / commentary
	     entries are no-op'd at admission. This is the cost-shape
	     property — without it, the gate would saturate the entry
	     fetcher at 100-150 admit/s.

	  2. Walks abort on the FIRST structural failure (cycle,
	     broken hop, depth overflow). Per-hop diagnostics are
	     available in the returned report.

	Real fixtures: real envelope entries with real EvidencePointers,
	real types.EntryFetcher stubs.
*/
package admission

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// stubEntryFetcher implements types.EntryFetcher from an in-memory
// map of position → entry. Concurrency-safe so the SDK walker (DFS)
// can call it freely.
type stubEntryFetcher struct {
	mu      sync.Mutex
	entries map[types.LogPosition]*envelope.Entry
	calls   int
	err     error
}

func newStubEntryFetcher() *stubEntryFetcher {
	return &stubEntryFetcher{entries: make(map[types.LogPosition]*envelope.Entry)}
}

func (s *stubEntryFetcher) put(pos types.LogPosition, e *envelope.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[pos] = e
}

func (s *stubEntryFetcher) Fetch(_ context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	entry, ok := s.entries[pos]
	if !ok {
		return nil, fmt.Errorf("stubEntryFetcher: not found %v", pos)
	}
	bytes, err := envelope.Serialize(entry)
	if err != nil {
		return nil, fmt.Errorf("stubEntryFetcher: serialize %v: %w", pos, err)
	}
	return &types.EntryWithMetadata{
		CanonicalBytes: bytes,
		LogTime:        time.Now().UTC(),
		Position:       pos,
	}, nil
}

func pathCEntry(scopePos *types.LogPosition) *envelope.Entry {
	apath := envelope.AuthorityScopeAuthority
	return &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:     "did:web:scope-member",
		Destination:   testLogDID,
		AuthorityPath: &apath,
		ScopePointer:  scopePos,
	}}
}

// scopeFixture returns a minimal Path A entry suitable for storage
// in a stubEntryFetcher as the chain root or hop. Uses
// envelope.NewEntry so ProtocolVersion is populated correctly
// (round-trips Serialize+Deserialize cleanly).
func scopeFixture(t *testing.T, did string, evidence []types.LogPosition) *envelope.Entry {
	t.Helper()
	keys, _ := multiSigFixture(t, 1)
	keys[0].DID = did
	keys[0].DID = did
	header := envelope.ControlHeader{
		SignerDID:        did,
		Destination:      testLogDID,
		EvidencePointers: evidence,
	}
	// Sign over a placeholder hash; the walker doesn't verify
	// signatures (it just needs Serialize+Deserialize to round-trip
	// the EvidencePointers DAG cleanly).
	stub, err := envelope.NewEntry(header, nil, []envelope.Signature{{
		SignerDID: did,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64), // 64-byte ECDSA stub; not verified
	}})
	if err != nil {
		t.Fatalf("envelope.NewEntry: %v", err)
	}
	return stub
}

func TestShouldWalkEvidenceChain_PathCFires(t *testing.T) {
	t.Parallel()

	scope := types.LogPosition{LogDID: testLogDID, Sequence: 1}
	if !ShouldWalkEvidenceChain(pathCEntry(&scope)) {
		t.Error("Path C entry did not fire predicate")
	}
}

func TestShouldWalkEvidenceChain_PathANoop(t *testing.T) {
	t.Parallel()

	apath := envelope.AuthoritySameSigner
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		AuthorityPath: &apath,
	}}
	if ShouldWalkEvidenceChain(entry) {
		t.Error("Path A entry fired predicate; surgical guarantee violated")
	}
}

func TestShouldWalkEvidenceChain_PathBNoop(t *testing.T) {
	t.Parallel()

	apath := envelope.AuthorityDelegation
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		AuthorityPath: &apath,
	}}
	if ShouldWalkEvidenceChain(entry) {
		t.Error("Path B entry fired predicate; surgical guarantee violated")
	}
}

func TestShouldWalkEvidenceChain_CommentaryNoop(t *testing.T) {
	t.Parallel()

	// AuthorityPath nil → commentary entry → predicate must not fire.
	entry := &envelope.Entry{Header: envelope.ControlHeader{}}
	if ShouldWalkEvidenceChain(entry) {
		t.Error("commentary entry fired predicate; surgical guarantee violated")
	}
}

func TestShouldWalkEvidenceChain_NilEntry(t *testing.T) {
	t.Parallel()

	if ShouldWalkEvidenceChain(nil) {
		t.Error("nil entry fired predicate")
	}
}

func TestVerifyEvidenceChainSurgical_NilEntryRejects(t *testing.T) {
	t.Parallel()

	_, err := VerifyEvidenceChainSurgical(context.Background(), nil, testLogDID, newStubEntryFetcher())
	if err == nil {
		t.Error("nil entry accepted")
	}
}

func TestVerifyEvidenceChainSurgical_NonSurgicalNoop(t *testing.T) {
	t.Parallel()

	// Path A entry: predicate false → no fetcher calls.
	apath := envelope.AuthoritySameSigner
	entry := &envelope.Entry{Header: envelope.ControlHeader{AuthorityPath: &apath}}
	fetcher := newStubEntryFetcher()
	report, err := VerifyEvidenceChainSurgical(context.Background(), entry, testLogDID, fetcher)
	if err != nil {
		t.Errorf("non-surgical entry errored: %v", err)
	}
	if report != nil {
		t.Errorf("non-surgical entry returned report: %+v", report)
	}
	if fetcher.calls != 0 {
		t.Errorf("fetcher called %d times for non-surgical entry; want 0", fetcher.calls)
	}
}

func TestVerifyEvidenceChainSurgical_NilFetcherForSurgicalEntryRejects(t *testing.T) {
	t.Parallel()

	scope := types.LogPosition{LogDID: testLogDID, Sequence: 1}
	entry := pathCEntry(&scope)
	_, err := VerifyEvidenceChainSurgical(context.Background(), entry, testLogDID, nil)
	if err == nil {
		t.Error("surgical entry + nil fetcher accepted; want fail-closed")
	}
}

func TestVerifyEvidenceChainSurgical_PathCWithoutScopePointerRejects(t *testing.T) {
	t.Parallel()

	// Surgical predicate fires on Path C, but the entry HAS no
	// ScopePointer — structural rejection. (Defensive — the
	// envelope shouldn't ship a Path C entry without
	// ScopePointer, but admission belt-and-braces.)
	apath := envelope.AuthorityScopeAuthority
	entry := &envelope.Entry{Header: envelope.ControlHeader{AuthorityPath: &apath}}
	_, err := VerifyEvidenceChainSurgical(context.Background(), entry, testLogDID, newStubEntryFetcher())
	if err == nil {
		t.Error("Path C without ScopePointer accepted")
	}
}

func TestVerifyEvidenceChainSurgical_ForeignScopePointerNoop(t *testing.T) {
	t.Parallel()

	// Decision #6 (cross-log no-op) applied to evidence chain too.
	scope := types.LogPosition{LogDID: "did:web:peer-log", Sequence: 1}
	entry := pathCEntry(&scope)
	fetcher := newStubEntryFetcher()
	report, err := VerifyEvidenceChainSurgical(context.Background(), entry, testLogDID, fetcher)
	if err != nil {
		t.Errorf("foreign-log scope walked: %v", err)
	}
	if report != nil {
		t.Errorf("foreign-log scope returned report: %+v", report)
	}
	if fetcher.calls != 0 {
		t.Errorf("foreign-log scope hit fetcher %d times; want 0", fetcher.calls)
	}
}

func TestVerifyEvidenceChainSurgical_LocalScopeWalksRoot(t *testing.T) {
	t.Parallel()

	scope := types.LogPosition{LogDID: testLogDID, Sequence: 1}
	entry := pathCEntry(&scope)
	fetcher := newStubEntryFetcher()
	// Seed the scope entry as a leaf (no further evidence).
	scopeEntry := scopeFixture(t, "did:web:scope-genesis", nil)
	fetcher.put(scope, scopeEntry)

	report, err := VerifyEvidenceChainSurgical(context.Background(), entry, testLogDID, fetcher)
	if err != nil {
		t.Errorf("valid one-hop walk rejected: %v", err)
	}
	if report == nil || len(report.Hops) == 0 {
		t.Errorf("expected non-empty report, got %+v", report)
	}
	if fetcher.calls != 1 {
		t.Errorf("fetcher called %d times; want 1 (root only)", fetcher.calls)
	}
}

func TestVerifyEvidenceChainSurgical_MissingRootRejects(t *testing.T) {
	t.Parallel()

	scope := types.LogPosition{LogDID: testLogDID, Sequence: 999}
	entry := pathCEntry(&scope)
	fetcher := newStubEntryFetcher() // empty; root not seeded
	_, err := VerifyEvidenceChainSurgical(context.Background(), entry, testLogDID, fetcher)
	if !errors.Is(err, verifier.ErrRootFetchFailed) {
		t.Errorf("err=%v, want ErrRootFetchFailed", err)
	}
}

func TestVerifyEvidenceChainSurgical_RejectsRouteThroughErrorMapping(t *testing.T) {
	t.Parallel()

	scope := types.LogPosition{LogDID: testLogDID, Sequence: 7}
	entry := pathCEntry(&scope)
	_, err := VerifyEvidenceChainSurgical(context.Background(), entry, testLogDID, newStubEntryFetcher())
	if err == nil {
		t.Fatal("expected ErrRootFetchFailed, got nil")
	}
	matched, status, _ := MapSDKError(err)
	if !matched {
		t.Error("MapSDKError did not match ErrRootFetchFailed; PR-A wiring violated")
	}
	if status != 500 {
		t.Errorf("status=%d, want 500", status)
	}
}
