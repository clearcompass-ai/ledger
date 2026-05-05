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
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/clearcompass-ai/attesta/core/smt"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// SMTDeps holds dependencies for SMT proof handlers.
type SMTDeps struct {
	Tree *smt.Tree
	LeafStore smt.LeafStore
	Logger *slog.Logger
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

		leaf, _ := deps.Tree.GetLeaf(key)
		if leaf != nil {
			proof, err := deps.Tree.GenerateMembershipProof(key)
			if err != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
					http.StatusInternalServerError, "proof generation failed")
				deps.Logger.Error("membership proof", "error", err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":  "membership",
				"proof": proof,
			})
			return
		}

		proof, err := deps.Tree.GenerateNonMembershipProof(key)
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
		if err := json.Unmarshal(body, &req); err != nil {
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
			kb, err := hex.DecodeString(kHex)
			if err != nil || len(kb) != 32 {
				writeTypedError(ctx, w, apitypes.ErrorClassBadHexLength,
					http.StatusBadRequest, "each key must be 64 hex characters")
				return
			}
			copy(keys[i][:], kb)
		}

		proof, err := deps.Tree.GenerateBatchProof(keys)
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
func NewSMTRootHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		root, err := deps.Tree.Root()
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "root computation failed")
			deps.Logger.Error("smt root", "error", err)
			return
		}
		leafCount, _ := deps.LeafStore.Count()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"root":       hex.EncodeToString(root[:]),
			"leaf_count": leafCount,
		})
	}
}
