/*
FILE PATH: api/proofs.go

SMT proof endpoints. Single membership/non-membership proofs, batch
multiproofs with SDK-D13 canonical ordering, and current root query.

KEY ARCHITECTURAL DECISIONS:
  - Proof generation uses sdk smt.Tree (shared with builder — callers
    should be aware of concurrent mutations; snapshot isolation is
    recommended for production via read-replica or tree snapshot).
  - Batch proof uses SDK-D13 canonical key ordering.
  - Root endpoint includes leaf count for monitoring.

POSTGRES-BACKED-STORE COMPATIBILITY:

	The SDK's Tree.Root and Tree.GenerateMembershipProof rely on
	collectLeafHashes (attesta/core/smt/tree.go), which only supports
	*smt.InMemoryLeafStore and *smt.OverlayLeafStore via a typed
	switch. PostgresLeafStore lands in the default arm and Tree.Root
	short-circuits to defaultHashes[TreeDepth] — the empty-tree root —
	regardless of how many leaves are committed.

	When deps.LeafStore implements the Materializable interface
	(PostgresLeafStore satisfies it via MaterializeToInMemory), the
	handlers below build an ephemeral in-memory tree on each call so
	Root/Proof compute against the actual leaf set. O(N) per call;
	acceptable for moderate-scale soaks and dev, NOT for 10B-leaf
	production deployments — see Item 11 in
	docs/production_readiness.md for the incremental-root work that
	makes the production path scalable.
*/
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/clearcompass-ai/attesta/core/smt"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// Materializable is implemented by LeafStores that can produce an
// SDK-compatible in-memory snapshot. PostgresLeafStore satisfies it
// (see store/smt_state.go). Pure in-memory stores do NOT need to
// implement it — the SDK already handles those natively.
type Materializable interface {
	MaterializeToInMemory(ctx context.Context) (*smt.InMemoryLeafStore, error)
}

// SMTRootReader reads the authoritative current SMT root. The
// production wiring (store.SMTRootStateStore) satisfies this; tests
// can inject fakes. nil = handler falls back to materialization.
type SMTRootReader interface {
	ReadRoot(ctx context.Context) ([32]byte, error)
}

// SMTDeps holds dependencies for SMT proof handlers.
type SMTDeps struct {
	Tree      *smt.Tree
	LeafStore smt.LeafStore
	// RootState is OPTIONAL. When set, /v1/smt/root reads from it
	// (O(1)) instead of falling back to leaf materialization (O(N)
	// per request). The production wiring passes
	// store.NewSMTRootStateStore(pool) here; the builder
	// (builder/loop.go) keeps the row up to date.
	RootState SMTRootReader
	Logger    *slog.Logger
}

// liveTree returns the tree to use for Root / Proof in this request.
// For Materializable backings (PostgresLeafStore) it builds a fresh
// in-memory tree from the current PG snapshot; otherwise it returns
// the configured tree directly. The returned tree's lifetime is the
// caller's HTTP request — no caching.
func (d *SMTDeps) liveTree(ctx context.Context) (*smt.Tree, error) {
	m, ok := d.LeafStore.(Materializable)
	if !ok {
		return d.Tree, nil
	}
	mem, err := m.MaterializeToInMemory(ctx)
	if err != nil {
		return nil, err
	}
	// Fresh in-memory node cache so we don't pollute the shared one
	// with materialized-from-PG node hashes that may not survive PG
	// state changes (concurrent builder commits).
	return smt.NewTree(mem, smt.NewInMemoryNodeCache()), nil
}

// NewSMTProofHandler creates GET /v1/smt/proof/{key}.
func NewSMTProofHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		keyHex := r.PathValue("key")
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil || len(keyBytes) != 32 {
			writeTypedError(ctx, w, apitypes.ErrorClassBadHexLength,
				http.StatusBadRequest, "key must be 64 hex characters (32 bytes)")
			return
		}

		var key [32]byte
		copy(key[:], keyBytes)

		tree, err := deps.liveTree(ctx)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "tree materialization failed")
			deps.Logger.Error("smt proof: liveTree", "error", err)
			return
		}

		leaf, _ := tree.GetLeaf(ctx, key)
		if leaf != nil {
			proof, pErr := tree.GenerateMembershipProof(ctx, key)
			if pErr != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
					http.StatusInternalServerError, "proof generation failed")
				deps.Logger.Error("membership proof", "error", pErr)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":  "membership",
				"proof": proof,
			})
			return
		}

		proof, err := tree.GenerateNonMembershipProof(ctx, key)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "non-membership proof failed")
			deps.Logger.Error("non-membership proof", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":  "non_membership",
			"proof": proof,
		})
	}
}

// NewSMTBatchProofHandler creates POST /v1/smt/batch_proof.
func NewSMTBatchProofHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedBody,
				http.StatusBadRequest, "failed to read body")
			return
		}

		var req struct {
			Keys []string `json:"keys"`
		}
		if uErr := json.Unmarshal(body, &req); uErr != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedJSON,
				http.StatusBadRequest, "invalid JSON")
			return
		}
		if len(req.Keys) == 0 || len(req.Keys) > 1000 {
			writeTypedError(ctx, w, apitypes.ErrorClassBatchTooLarge,
				http.StatusBadRequest, "keys count must be 1-1000")
			return
		}

		keys := make([][32]byte, len(req.Keys))
		for i, kHex := range req.Keys {
			kb, dErr := hex.DecodeString(kHex)
			if dErr != nil || len(kb) != 32 {
				writeTypedError(ctx, w, apitypes.ErrorClassBadHexLength,
					http.StatusBadRequest, "each key must be 64 hex characters")
				return
			}
			copy(keys[i][:], kb)
		}

		tree, err := deps.liveTree(ctx)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "tree materialization failed")
			deps.Logger.Error("smt batch proof: liveTree", "error", err)
			return
		}

		proof, err := tree.GenerateBatchProof(ctx, keys)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "batch proof generation failed")
			deps.Logger.Error("batch proof", "error", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}

// NewSMTRootHandler creates GET /v1/smt/root. Reads the
// authoritative root from deps.RootState when wired (O(1));
// falls back to per-request materialization when not (O(N)). The
// production wiring at cmd/ledger/boot/wire/wire.go sets RootState
// so this never hits the materialization path in production.
func NewSMTRootHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var root [32]byte
		if deps.RootState != nil {
			r, err := deps.RootState.ReadRoot(ctx)
			if err != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
					http.StatusInternalServerError, "root state read failed")
				deps.Logger.Error("smt root: ReadRoot", "error", err)
				return
			}
			root = r
		} else {
			tree, err := deps.liveTree(ctx)
			if err != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
					http.StatusInternalServerError, "tree materialization failed")
				deps.Logger.Error("smt root: liveTree", "error", err)
				return
			}
			r, err := tree.Root(ctx)
			if err != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
					http.StatusInternalServerError, "root computation failed")
				deps.Logger.Error("smt root", "error", err)
				return
			}
			root = r
		}
		leafCount, _ := deps.LeafStore.Count(ctx)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"root":       hex.EncodeToString(root[:]),
			"leaf_count": leafCount,
		})
	}
}
