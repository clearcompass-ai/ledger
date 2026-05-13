/*
FILE PATH: api/proofs.go

SMT proof endpoints under attesta v0.3.0 (Jellyfish/Patricia trie).
Single membership/non-membership proofs, batch multiproofs, and
current-root query.

# V0.3.0 ARCHITECTURE

The handlers operate against a shared smt.Tree whose internal rootHash
is advanced by the builder loop after each atomic commit. The tree's
LeafStore is a PostgresLeafStore; its NodeStore is a PostgresNodeStore
with a hot LRU. Both are content-addressed and concurrent-read-safe.
Proof generation walks the trie through the NodeStore directly — no
materialisation, no per-request O(N) snapshot.

The "Materializable" interface and "liveTree" indirection used in
v0.2.0 are GONE. Their entire purpose was to work around the v0.2.0
SDK's collectLeafHashes type-switch that short-circuited Tree.Root for
PostgresLeafStore. v0.3.0 fixes that at the SDK level; the workaround
is technical debt.

# CONCURRENCY

The shared tree.Root reads under the SDK's internal mutex; per-request
reads (Get/GetLeaf/GenerateMembershipProof/etc.) are safe concurrent
with the builder's writes (the single writer holds the same mutex for
the rootHash advance + SetRoot call).
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

// SMTRootReader reads the authoritative current SMT root. The
// production wiring (store.SMTRootStateStore) satisfies this; tests
// can inject fakes. When nil, /v1/smt/root falls back to tree.Root.
type SMTRootReader interface {
	ReadRoot(ctx context.Context) ([32]byte, error)
}

// SMTDeps holds dependencies for SMT proof handlers.
//
// Tree is the SDK's v0.3.0 smt.Tree, shared with the builder loop.
// LeafStore is the same store the tree wraps — exposed here for the
// Count() call on /v1/smt/root. RootState, when set, satisfies the
// O(1) root read; production wiring always sets it.
type SMTDeps struct {
	Tree      *smt.Tree
	LeafStore smt.LeafStore
	RootState SMTRootReader
	Logger    *slog.Logger
}

// NewSMTProofHandler creates GET /v1/smt/proof/{key}.
//
// Behaviour:
//   - leaf present at key  → membership proof (TerminalKind = leaf,
//     TerminalLeaf.Key == key)
//   - leaf absent          → non-membership proof (TerminalKind one of
//     leaf-blocking / branch-mismatch / empty)
//
// The response shape is {"type": "membership"|"non_membership",
// "proof": types.SMTProof}. The Jellyfish-shape SMTProof's exported
// fields marshal directly via encoding/json.
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

		leaf, _ := deps.Tree.GetLeaf(ctx, key)
		if leaf != nil {
			proof, pErr := deps.Tree.GenerateMembershipProof(ctx, key)
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

		proof, err := deps.Tree.GenerateNonMembershipProof(ctx, key)
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
//
// Body: {"keys": ["<hex>", ...]}, up to 1000 keys per request.
// Response: types.BatchProof with deduplicated SMTNodes covering
// every key's path from the SMT root. Verifier-side use:
// smt.VerifyBatchProof(proof, root).
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

		proof, err := deps.Tree.GenerateBatchProof(ctx, keys)
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

// NewSMTRootHandler creates GET /v1/smt/root.
//
// Reads the authoritative root from deps.RootState (O(1)) when wired.
// Production wiring always sets RootState. When not wired (test
// fixtures), falls back to deps.Tree.Root which returns the tree's
// cached rootHash — still O(1) and consistent with the builder's
// in-memory state.
//
// # LIGHT-CLIENT WARNING (SDK v0.8.0+)
//
// The bytes served here carry NO cryptographic binding to the
// witness-cosigned tree head. An adversary on the read path
// could swap a forged root and produce membership proofs against
// it that pass every check OTHER than the witness signature.
//
// For trust-rooted SMT-root consumption, prefer /v1/tree/head's
// smt_root field — that value is bound into the witness K-of-N
// cosignature (attesta SDK v0.8.0+; types.TreeHead.SMTRoot is in
// the cosign canonical payload). This handler remains for
// callers that already know the root they want (e.g. mid-batch
// proofs where the builder has advanced the SMT but witnesses
// haven't cosigned the new TreeSize yet).
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
			r, err := deps.Tree.Root(ctx)
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
