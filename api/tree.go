/*
FILE PATH: api/tree.go

Tree head distribution and Merkle proof endpoints.

CHANGES FROM PHASE 4 PREP:
  - NewTreeHeadHandler now accepts ?size=N query parameter.
    GET /v1/tree/head         → latest cosigned tree head (existing)
    GET /v1/tree/head?size=N  → tree head at specific size (NEW)
    Falls through to existing Latest() when no parameter.
    Uses TreeHeadStore.GetBySize() which already exists (store/tree_heads.go).
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// ConsistencyProver generates consistency proofs.
type ConsistencyProver interface {
	ConsistencyProof(oldSize, newSize uint64) (any, error)
}

// InclusionProver generates inclusion proofs for HTTP passthrough.
type InclusionProver interface {
	RawInclusionProof(position, treeSize uint64) (any, error)
}

// TreeDeps holds dependencies for tree handlers.
type TreeDeps struct {
	TreeHeadStore TreeHeadFetcher
	Inclusion     InclusionProver
	Consistency   ConsistencyProver
	Logger        *slog.Logger
}

// NewTreeHeadHandler creates GET /v1/tree/head[?size=N].
// Without ?size=N: returns latest cosigned tree head (existing behavior).
// With ?size=N: returns tree head at that specific size via GetBySize().
func NewTreeHeadHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var head *apitypes.CosignedTreeHead
		var err error

		// Check for ?size=N parameter (blocks fraud_proofs).
		sizeStr := r.URL.Query().Get("size")
		if sizeStr != "" {
			size, parseErr := strconv.ParseUint(sizeStr, 10, 64)
			if parseErr != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
					http.StatusBadRequest, "invalid size parameter")
				return
			}
			// GetBySize exists in store/tree_heads.go — returns tree head
			// at specific size, used by equivocation monitor and fraud proofs.
			head, err = deps.TreeHeadStore.GetBySize(ctx, size)
		} else {
			head, err = deps.TreeHeadStore.Latest(ctx)
		}

		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "failed to fetch tree head")
			deps.Logger.Error("tree head fetch", "error", err)
			return
		}
		if head == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "no cosigned tree head available")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, head.TreeSize))
		w.Header().Set("Cache-Control", "public, max-age=5")

		sigs := make([]map[string]any, len(head.Signatures))
		for i, s := range head.Signatures {
			sigs[i] = map[string]any{
				"signer":    s.Signer,
				"sig_algo":  s.SigAlgo,
				"signature": hex.EncodeToString(s.Signature),
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size":  head.TreeSize,
			"root_hash":  hex.EncodeToString(head.RootHash[:]),
			"hash_algo":  head.HashAlgo,
			"signatures": sigs,
		})
	}
}

// NewTreeInclusionHandler creates GET /v1/tree/inclusion/{seq}.
func NewTreeInclusionHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		seqStr := r.PathValue("seq")
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid sequence number")
			return
		}

		head, err := deps.TreeHeadStore.Latest(ctx)
		if err != nil || head == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusServiceUnavailable, "no tree head available")
			return
		}

		if deps.Inclusion == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusServiceUnavailable, "inclusion proofs not available")
			return
		}

		proof, err := deps.Inclusion.RawInclusionProof(seq, head.TreeSize)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusNotFound,
				fmt.Sprintf("inclusion proof: %s", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}

// NewTreeConsistencyHandler creates GET /v1/tree/consistency/{old}/{new}.
func NewTreeConsistencyHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oldStr := r.PathValue("old")
		newStr := r.PathValue("new")
		oldSize, err1 := strconv.ParseUint(oldStr, 10, 64)
		newSize, err2 := strconv.ParseUint(newStr, 10, 64)
		if err1 != nil || err2 != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid tree sizes")
			return
		}
		if oldSize >= newSize {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "old size must be less than new size")
			return
		}

		if deps.Consistency == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusServiceUnavailable, "consistency proofs not available")
			return
		}

		proof, err := deps.Consistency.ConsistencyProof(oldSize, newSize)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusNotFound,
				fmt.Sprintf("consistency proof: %s", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}
