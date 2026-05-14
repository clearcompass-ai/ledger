/*
FILE PATH:

	delegationresolver/ledger_source_test.go

DESCRIPTION:

	Binding tests for the LedgerEntrySource adapter and the
	NewSDKResolver construction shim.

	Pins:
	  - LedgerEntrySource satisfies delegation.EntrySource
	    structurally.
	  - delegation.Resolver (returned by NewSDKResolver) satisfies
	    attestation.DelegationResolver — the load-bearing
	    interface assertion for the policy verifier surface.
	  - DelegationOf returns ErrUnknownDelegate when:
	      * delegateDID is empty
	      * the fetcher returns no row
	  - DelegationOf returns a populated DelegationEntry when the
	    fetcher hits and the extractor extracts cleanly.
	  - DelegationOf surfaces fetcher errors as-is (wrapped).
	  - DelegationOf surfaces projection drift (entry's
	    DelegateDID != queried DID) as an explicit error.

	Real fixtures: real envelope.NewEntry constructed via
	envelope.Serialize, real types.EntryWithMetadata.
*/
package delegationresolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/delegation"
	"github.com/clearcompass-ai/attesta/types"
)

// fakeFetcher implements DelegationFetcher with a configured
// outcome. Used to pin the LedgerEntrySource without a Postgres
// dependency.
type fakeFetcher struct {
	out *types.EntryWithMetadata
	err error
}

func (f *fakeFetcher) FetchLatestDelegationByDID(_ context.Context, _ string) (*types.EntryWithMetadata, error) {
	return f.out, f.err
}

// fakeExtractor returns the configured (scopes, live, err).
type fakeExtractor struct {
	scopes []string
	live   bool
	err    error
}

func (f *fakeExtractor) Extract(*envelope.Entry) ([]string, bool, error) {
	return f.scopes, f.live, f.err
}

// delegationEntryWithMeta constructs a real EntryWithMetadata
// whose envelope.Deserialize round-trips cleanly. The constructed
// entry's Header.DelegateDID is `delegateDID`, SignerDID is
// `delegator`, and the rest is minimal.
func delegationEntryWithMeta(t *testing.T, delegateDID, delegator string, position types.LogPosition) *types.EntryWithMetadata {
	t.Helper()
	d := delegateDID
	header := envelope.ControlHeader{
		SignerDID:   delegator,
		Destination: position.LogDID,
		DelegateDID: &d,
	}
	stub := []envelope.Signature{{
		SignerDID: delegator,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	entry, err := envelope.NewEntry(header, nil, stub)
	if err != nil {
		t.Fatalf("envelope.NewEntry: %v", err)
	}
	bytes, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("envelope.Serialize: %v", err)
	}
	return &types.EntryWithMetadata{
		CanonicalBytes: bytes,
		LogTime:        time.Now().UTC(),
		Position:       position,
	}
}

func TestLedgerEntrySource_SatisfiesEntrySourceInterface(t *testing.T) {
	t.Parallel()

	// Compile-time satisfaction check. If LedgerEntrySource drifts
	// out of the delegation.EntrySource interface, this assignment
	// fails to build.
	var _ delegation.EntrySource = (*LedgerEntrySource)(nil)
}

func TestNewLedgerEntrySource_NilFetcherPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewLedgerEntrySource(nil) did not panic; production wiring requires non-nil fetcher")
		}
	}()
	_ = NewLedgerEntrySource(nil, nil)
}

func TestNewLedgerEntrySource_NilExtractorDefaultsToNoOp(t *testing.T) {
	t.Parallel()

	src := NewLedgerEntrySource(&fakeFetcher{}, nil)
	if _, ok := src.Extractor.(NoOpScopeExtractor); !ok {
		t.Errorf("nil extractor not defaulted to NoOpScopeExtractor; got %T", src.Extractor)
	}
}

func TestLedgerEntrySource_DelegationOf_EmptyDIDReturnsUnknown(t *testing.T) {
	t.Parallel()

	src := NewLedgerEntrySource(&fakeFetcher{}, nil)
	_, err := src.DelegationOf(context.Background(), "")
	if !errors.Is(err, attestation.ErrUnknownDelegate) {
		t.Errorf("empty DID err=%v, want ErrUnknownDelegate", err)
	}
}

func TestLedgerEntrySource_DelegationOf_NoRowReturnsUnknown(t *testing.T) {
	t.Parallel()

	src := NewLedgerEntrySource(&fakeFetcher{out: nil}, nil)
	_, err := src.DelegationOf(context.Background(), "did:web:absent")
	if !errors.Is(err, attestation.ErrUnknownDelegate) {
		t.Errorf("no-row err=%v, want ErrUnknownDelegate", err)
	}
}

func TestLedgerEntrySource_DelegationOf_FetcherErrorPropagates(t *testing.T) {
	t.Parallel()

	transient := errors.New("transport: db unreachable")
	src := NewLedgerEntrySource(&fakeFetcher{err: transient}, nil)
	_, err := src.DelegationOf(context.Background(), "did:web:any")
	if !errors.Is(err, transient) {
		t.Errorf("fetcher err not wrapped: got %v, want errors.Is(transient)", err)
	}
}

func TestLedgerEntrySource_DelegationOf_HappyPath(t *testing.T) {
	t.Parallel()

	delegate := "did:web:delegate-1"
	delegator := "did:web:root"
	meta := delegationEntryWithMeta(t,
		delegate, delegator,
		types.LogPosition{LogDID: "did:web:bench.log", Sequence: 7},
	)
	src := NewLedgerEntrySource(&fakeFetcher{out: meta}, &fakeExtractor{
		scopes: []string{"sealing_supervisor"},
		live:   true,
	})

	got, err := src.DelegationOf(context.Background(), delegate)
	if err != nil {
		t.Fatalf("DelegationOf: %v", err)
	}
	if got.DelegateDID != delegate {
		t.Errorf("DelegateDID=%q, want %q", got.DelegateDID, delegate)
	}
	if got.DelegatorDID != delegator {
		t.Errorf("DelegatorDID=%q, want %q", got.DelegatorDID, delegator)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "sealing_supervisor" {
		t.Errorf("Scopes=%v, want [sealing_supervisor]", got.Scopes)
	}
	if !got.Live {
		t.Error("Live=false, want true")
	}
}

func TestLedgerEntrySource_DelegationOf_RevokedDelegationCarriesLiveFalse(t *testing.T) {
	t.Parallel()

	delegate := "did:web:revoked"
	meta := delegationEntryWithMeta(t,
		delegate, "did:web:root",
		types.LogPosition{LogDID: "did:web:bench.log", Sequence: 9},
	)
	src := NewLedgerEntrySource(&fakeFetcher{out: meta}, &fakeExtractor{live: false})

	got, err := src.DelegationOf(context.Background(), delegate)
	if err != nil {
		t.Fatalf("DelegationOf: %v", err)
	}
	if got.Live {
		t.Error("revoked extractor returned Live=true; want false")
	}
}

func TestLedgerEntrySource_DelegationOf_ExtractorErrorPropagates(t *testing.T) {
	t.Parallel()

	meta := delegationEntryWithMeta(t,
		"did:web:d", "did:web:root",
		types.LogPosition{LogDID: "did:web:bench.log", Sequence: 1},
	)
	extractErr := errors.New("scope parse: malformed JSON")
	src := NewLedgerEntrySource(&fakeFetcher{out: meta}, &fakeExtractor{err: extractErr})
	_, err := src.DelegationOf(context.Background(), "did:web:d")
	if !errors.Is(err, extractErr) {
		t.Errorf("extractor err not wrapped: got %v", err)
	}
}

func TestLedgerEntrySource_DelegationOf_ProjectionDriftSurfaces(t *testing.T) {
	t.Parallel()

	// Synthesise a delegation entry whose DelegateDID in the
	// payload differs from the DID we queried for. This shape
	// is a CORRUPTION signal (idx_delegate_did_latest disagrees
	// with the canonical bytes). The adapter MUST surface it,
	// not silently return the entry.
	meta := delegationEntryWithMeta(t,
		"did:web:actual", "did:web:root",
		types.LogPosition{LogDID: "did:web:bench.log", Sequence: 3},
	)
	src := NewLedgerEntrySource(&fakeFetcher{out: meta}, nil)
	_, err := src.DelegationOf(context.Background(), "did:web:asked-for")
	if err == nil {
		t.Error("projection drift not surfaced")
	}
}

func TestNewSDKResolver_NilSourcePanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewSDKResolver(nil) did not panic")
		}
	}()
	_ = NewSDKResolver(nil)
}

func TestNewSDKResolver_SatisfiesAttestationDelegationResolver(t *testing.T) {
	t.Parallel()

	// In-memory source + SDK resolver — real SDK code path.
	inMem := delegation.NewInMemorySource()
	resolver := NewSDKResolver(inMem)
	// The compile-time assertion in sdk_resolver.go pins
	// *delegation.Resolver against attestation.DelegationResolver.
	// This run-time check ensures the constructor returns a
	// value of that type.
	var _ attestation.DelegationResolver = resolver
}

// perDIDFetcher dispatches FetchLatestDelegationByDID by the
// queried DID. Lets a test build a multi-hop chain (each level's
// fetcher returns the entry whose DelegateDID == queried DID).
type perDIDFetcher map[string]*types.EntryWithMetadata

func (m perDIDFetcher) FetchLatestDelegationByDID(_ context.Context, did string) (*types.EntryWithMetadata, error) {
	return m[did], nil
}

func TestSDKResolver_ResolvesOneHopChainAgainstLedgerEntrySource(t *testing.T) {
	t.Parallel()

	// Wire the full stack: perDIDFetcher → LedgerEntrySource →
	// Cached → *delegation.Resolver (NewSDKResolver). Confirms
	// the SDK's walker can walk against our adapter and that
	// Hops[0] is populated from our extractor.

	delegate := "did:web:bench-delegate"
	delegator := "did:web:bench-root"
	delegateMeta := delegationEntryWithMeta(t,
		delegate, delegator,
		types.LogPosition{LogDID: "did:web:bench.log", Sequence: 1},
	)
	// delegator has no on-log delegation — the chain ends here
	// (ErrUnknownDelegate, walker stops gracefully).
	fetcher := perDIDFetcher{delegate: delegateMeta}
	src := NewLedgerEntrySource(fetcher, &fakeExtractor{live: true, scopes: []string{"x"}})

	cached, err := NewCached(src, 10, nil)
	if err != nil {
		t.Fatalf("NewCached: %v", err)
	}
	resolver := NewSDKResolver(cached)

	chain, err := resolver.ResolveChain(context.Background(), delegate)
	if err != nil {
		t.Fatalf("ResolveChain: %v", err)
	}
	if len(chain.Hops) != 1 {
		t.Fatalf("len(Hops)=%d, want 1", len(chain.Hops))
	}
	if chain.Hops[0].DelegateDID != delegate {
		t.Errorf("Hops[0].DelegateDID=%q, want %q", chain.Hops[0].DelegateDID, delegate)
	}
	if chain.Hops[0].DelegatorDID != delegator {
		t.Errorf("Hops[0].DelegatorDID=%q, want %q", chain.Hops[0].DelegatorDID, delegator)
	}
	if !chain.Hops[0].Live {
		t.Error("Hops[0].Live=false, want true")
	}
}
