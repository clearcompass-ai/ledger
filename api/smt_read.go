/*
FILE PATH: api/smt_read.go

SMT leaf data endpoints. Returns OriginTip and AuthorityTip for a given
subject key. Distinct from /v1/smt/proof/{key} which returns Merkle proofs.

Routes:
  GET  /v1/smt/leaf/{key}   → single LeafResponse
  POST /v1/smt/leaves       → []LeafResponse (batch)

Delegates to PostgresLeafStore.Get() which returns *types.SMTLeaf
(store/smt_state.go). Reuses SMTDeps from proofs.go.
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/apitypes"
)

const maxLeafBatchSize = 100

type LeafResponse struct {
	Key          string            `json:"key"`
	OriginTip    *PositionResponse `json:"origin_tip,omitempty"`
	AuthorityTip *PositionResponse `json:"authority_tip,omitempty"`
	Exists       bool              `json:"exists"`
}

type PositionResponse struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}

func positionToResponse(pos types.LogPosition) *PositionResponse {
	if pos.LogDID == "" && pos.Sequence == 0 {
		return nil
	}
	return &PositionResponse{LogDID: pos.LogDID, Sequence: pos.Sequence}
}

func NewSMTLeafHandler(deps *SMTDeps) http.HandlerFunc {
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

		leaf, err := deps.LeafStore.Get(key)
		if err != nil {
			deps.Logger.Error("smt leaf get", "key", keyHex[:16], "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, "leaf lookup failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(smtLeafToResponse(key, leaf))
	}
}

func NewSMTLeafBatchHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedBody,
				http.StatusBadRequest, "read body failed")
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
		if len(req.Keys) == 0 || len(req.Keys) > maxLeafBatchSize {
			writeTypedError(ctx, w, apitypes.ErrorClassBatchTooLarge,
				http.StatusBadRequest, "keys count must be 1-100")
			return
		}

		responses := make([]LeafResponse, 0, len(req.Keys))
		for _, keyHex := range req.Keys {
			keyBytes, err := hex.DecodeString(keyHex)
			if err != nil || len(keyBytes) != 32 {
				writeTypedError(ctx, w, apitypes.ErrorClassBadHexLength,
					http.StatusBadRequest, "each key must be 64 hex characters")
				return
			}
			var key [32]byte
			copy(key[:], keyBytes)
			leaf, err := deps.LeafStore.Get(key)
			if err != nil {
				deps.Logger.Error("smt leaf batch get", "error", err)
				writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
					http.StatusInternalServerError, "leaf lookup failed")
				return
			}
			responses = append(responses, smtLeafToResponse(key, leaf))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses)
	}
}

func smtLeafToResponse(key [32]byte, leaf *types.SMTLeaf) LeafResponse {
	if leaf == nil {
		return LeafResponse{Key: hex.EncodeToString(key[:]), Exists: false}
	}
	return LeafResponse{
		Key:          hex.EncodeToString(key[:]),
		OriginTip:    positionToResponse(leaf.OriginTip),
		AuthorityTip: positionToResponse(leaf.AuthorityTip),
		Exists:       true,
	}
}
