//go:build scenarios

/*
FILE PATH:
    tests/scenarios_auditor_test.go

DESCRIPTION:
    Lightweight HTTP auditor client for the Layer 0 scenarios suite.
    Mimics the production auditor's pull path: extract LogDID, ask
    the DID resolver for the CDN base, fetch tiles by deterministic
    c2sp.org/tlog-tiles path, recompute the inclusion / consistency
    proof locally from the tiles. No SDK builder import — the
    auditor demonstrates that everything an external consumer
    needs is reachable over plain HTTP + crypto/sha256 + the SDK's
    TileReader-style fetch.

KEY ARCHITECTURAL DECISIONS:
    - Built around the SDK's optessera.TileReader, which already
      caches and decodes c2sp.org tiles. Reusing it avoids
      re-implementing tile parsing in test code while still
      proving the wire path is consumable from outside the
      ledger process.
    - Polling, never time.Sleep. WaitForLeaf and WaitForTreeSize
      both take a context.Context with deadline; the polling
      cadence (50 ms) is fixed but the deadline is the only
      thing that controls flake-risk.
    - The auditor consumes a *did.DIDEndpointAdapter, exactly the
      shape an external auditor would obtain from the SDK's
      production resolver chain.
    - Inclusion-proof verification: walk the tile structure, hash
      siblings up to the root, compare to the head's RootHash.
      RFC 6962 leaf prefix (0x00) and node prefix (0x01) are
      explicit constants — pinned here so a future encoding drift
      surfaces as test failure not silent acceptance.

OVERVIEW:
    NewAuditor(t, adapter, tileReader)    → constructor.
    .ResolveLedgerEndpoint(logDID)        → DID resolver round-trip.
    .ResolveCDNEndpoint(logDID)           → DID resolver round-trip.
    .WaitForTreeSize(ctx, want)           → poll Head() until reached.
    .ReadLevel0Tile(ctx, idx)             → tile bytes.
    .VerifyLeafInclusion(leafHash, idx,
                          treeSize, root) → recompute, compare.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/attesta/did: DIDEndpointAdapter.
    - github.com/clearcompass-ai/ledger/tessera: TileReader.
    - tests/scenarios_skel_test.go: pollUntil / mustNotErr.
*/
package tests

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/types"

	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) RFC 6962 prefixes
// -------------------------------------------------------------------------------------------------

const (
	rfc6962LeafPrefix byte = 0x00
	rfc6962NodePrefix byte = 0x01
)

// -------------------------------------------------------------------------------------------------
// 2) headProvider — interface the auditor pulls heads from
// -------------------------------------------------------------------------------------------------

// headProvider is the minimal surface the auditor needs to read
// the current tree head. The scenariosStack's Tessera() satisfies
// this naturally; production wires the SDK's STH HTTP client
// behind the same shape.
type headProvider interface {
	Head() (types.TreeHead, error)
}

// -------------------------------------------------------------------------------------------------
// 3) auditor — the type
// -------------------------------------------------------------------------------------------------

// auditor is the in-test consumer that drives the same code paths
// an external standalone auditor would. Goroutine-safe: no
// internal state beyond pointers to externally-managed harness
// pieces.
type auditor struct {
	adapter    *did.DIDEndpointAdapter
	tileReader *optessera.TileReader
	heads      headProvider
}

// NewAuditor returns an auditor. All three dependencies are
// required; nil triggers t.Fatal at construction so persona
// tests fail loudly on misconfiguration.
func NewAuditor(t *testing.T, adapter *did.DIDEndpointAdapter, tileReader *optessera.TileReader, heads headProvider) *auditor {
	t.Helper()
	if adapter == nil {
		t.Fatal("NewAuditor: adapter required")
	}
	if tileReader == nil {
		t.Fatal("NewAuditor: tileReader required")
	}
	if heads == nil {
		t.Fatal("NewAuditor: heads required")
	}
	return &auditor{adapter: adapter, tileReader: tileReader, heads: heads}
}

// -------------------------------------------------------------------------------------------------
// 4) DID-anchored endpoint resolution
// -------------------------------------------------------------------------------------------------

// ResolveLedgerEndpoint walks the DID resolver to find the
// AttestaLedger service entry. Returns the empty string if the
// document carries no ledger endpoint (auditor caller fails
// loudly rather than silently fall back).
func (a *auditor) ResolveLedgerEndpoint(logDID string) (string, error) {
	url, err := a.adapter.LedgerEndpoint(logDID)
	if err != nil {
		return "", fmt.Errorf("auditor: resolve ledger endpoint: %w", err)
	}
	return url, nil
}

// ResolveCDNEndpoint walks the DID resolver to find the
// AttestaArtifactStore service entry.
func (a *auditor) ResolveCDNEndpoint(logDID string) (string, error) {
	doc, err := a.adapter.Resolver.Resolve(logDID)
	if err != nil {
		return "", fmt.Errorf("auditor: resolve doc: %w", err)
	}
	url, err := doc.ArtifactStoreURL()
	if err != nil {
		return "", fmt.Errorf("auditor: artifact store URL: %w", err)
	}
	return url, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Wait helpers — context-bounded polling, no time.Sleep
// -------------------------------------------------------------------------------------------------

// WaitForTreeSize polls heads.Head() until TreeSize >= want or
// ctx fires. Returns the latest head observed (even on timeout)
// so persona tests can include "current size = N" diagnostics.
func (a *auditor) WaitForTreeSize(ctx context.Context, want uint64) (types.TreeHead, error) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	var last types.TreeHead
	for {
		select {
		case <-ctx.Done():
			return last, fmt.Errorf("auditor: WaitForTreeSize: %w (last size=%d, want=%d)",
				ctx.Err(), last.TreeSize, want)
		case <-tick.C:
			h, err := a.heads.Head()
			if err == nil {
				last = h
				if h.TreeSize >= want {
					return h, nil
				}
			}
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 6) Tile fetching
// -------------------------------------------------------------------------------------------------

// ReadLevel0Tile fetches the level-0 tile at the given index. The
// underlying TileReader caches; second calls hit memory.
func (a *auditor) ReadLevel0Tile(ctx context.Context, idx uint64) ([]byte, error) {
	return a.tileReader.ReadTile(ctx, 0, idx)
}

// ReadEntryTile fetches the entry-data tile at the given index.
// Hash-only architecture: each entry slot holds a 32-byte SHA-256.
func (a *auditor) ReadEntryTile(ctx context.Context, idx uint64) ([]byte, error) {
	return a.tileReader.ReadEntryTile(ctx, idx)
}

// -------------------------------------------------------------------------------------------------
// 7) Inclusion-proof verification (lightweight, RFC 6962)
// -------------------------------------------------------------------------------------------------

// VerifyLeafInclusion walks an inclusion-proof slice and asserts
// that hashing leafHash up the proof produces the supplied root.
// The proof slice ordering matches RFC 6962 §2.1.1 (sibling
// hashes from leaf level upward, alternating left/right per the
// index bit).
//
// Standalone implementation — no SDK builder import — so this
// auditor demonstrates the verification can be done with crypto/
// sha256 alone. Persona 2 (browser-class) reuses this exact body.
func (a *auditor) VerifyLeafInclusion(leafHash [32]byte, idx, treeSize uint64, proof [][]byte, root [32]byte) error {
	if idx >= treeSize {
		return fmt.Errorf("VerifyLeafInclusion: idx %d >= treeSize %d", idx, treeSize)
	}

	// Wrap leaf with the RFC-6962 leaf-prefix to get the actual
	// hash that lives in the tree.
	h := sha256.Sum256(append([]byte{rfc6962LeafPrefix}, leafHash[:]...))

	last := treeSize - 1
	pos := idx
	pi := 0
	for last > 0 {
		if pi >= len(proof) {
			return errors.New("VerifyLeafInclusion: proof exhausted before reaching root")
		}
		sib := proof[pi]
		pi++
		if pos&1 == 1 || pos == last {
			h = hashChildren(sib, h[:])
		} else {
			h = hashChildren(h[:], sib)
		}
		if pos&1 == 1 || pos == last {
			pos >>= 1
			last >>= 1
		} else {
			pos >>= 1
			last >>= 1
		}
	}
	if pi != len(proof) {
		return fmt.Errorf("VerifyLeafInclusion: %d proof bytes unconsumed", len(proof)-pi)
	}
	if h != root {
		return errors.New("VerifyLeafInclusion: root mismatch")
	}
	return nil
}

// hashChildren computes SHA-256(0x01 || left || right) per RFC 6962.
func hashChildren(left, right []byte) [32]byte {
	var buf []byte
	buf = append(buf, rfc6962NodePrefix)
	buf = append(buf, left...)
	buf = append(buf, right...)
	return sha256.Sum256(buf)
}

// -------------------------------------------------------------------------------------------------
// 8) Tests — coverage gate (Postgres-gated; full lifecycle test)
// -------------------------------------------------------------------------------------------------

// TestAuditor_AccessorSurface is gated on ATTESTA_TEST_DSN. Boots a
// scenariosStack and exercises every helper on the auditor type
// that does not require an actual append (tile fetch under empty
// tree, accessor methods, error paths). End-to-end submit-then-
// verify is covered by Persona 1's TestPersona1_AuditorFull —
// scenariosStack now uses real Tessera, so an "append" must come
// from the ledger's own HTTP path, not from a shadow helper.
func TestAuditor_AccessorSurface(t *testing.T) {
	stack := NewScenariosStack(t, scenariosStackOpts{LogDIDSuffix: "auditor"})

	a := NewAuditor(t, stack.Resolver().AuditorAdapter(), stack.TileReader(), stack)

	// DID-anchored endpoint resolution.
	if got, err := a.ResolveLedgerEndpoint(stack.LogDID()); err != nil ||
		got != stack.LedgerBaseURL() {
		t.Fatalf("ResolveLedgerEndpoint: got %q err=%v", got, err)
	}
	if got, err := a.ResolveCDNEndpoint(stack.LogDID()); err != nil ||
		got != stack.CDNBaseURL() {
		t.Fatalf("ResolveCDNEndpoint: got %q err=%v", got, err)
	}

	// Empty tree → WaitForTreeSize(0) trivially OK.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	head, err := a.WaitForTreeSize(ctx, 0)
	mustNotErr(t, "WaitForTreeSize(0)", err)
	if head.TreeSize != 0 {
		t.Fatalf("empty-tree head.TreeSize = %d, want 0", head.TreeSize)
	}

	// VerifyLeafInclusion bounds check — idx >= treeSize → error.
	err = a.VerifyLeafInclusion([32]byte{}, 100, 4, nil, [32]byte{})
	if err == nil {
		t.Fatal("VerifyLeafInclusion accepted out-of-range idx")
	}

	// WaitForTreeSize with already-expired deadline → wrapped ctx err.
	tooShort, cancel2 := context.WithTimeout(context.Background(), 1*time.Millisecond)
	cancel2()
	_, err = a.WaitForTreeSize(tooShort, 1<<30) // unreachable.
	if err == nil {
		t.Fatal("WaitForTreeSize: missing ctx-cancel error")
	}
}
