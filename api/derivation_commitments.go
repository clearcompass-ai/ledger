/*
FILE PATH: api/derivation_commitments.go

SMT batch DERIVATION commitment query endpoint:

	GET /v1/derivation-commitments?seq=N → commitment whose range covers sequence N

This file is NOT about v7.75 cryptographic Pedersen commitments;
see store/derivation_commitments.go for the concept disambiguation.
The v7.75 cryptographic-commitment surface lives in api/commitments.go
(GET /v1/commitments/by-split-id/{schema_id}/{hex}).
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// DerivationCommitmentDeps groups the derivation-commitment query handler
// dependencies. Distinct from CryptographicCommitmentDeps (api/commitments.go),
// which serves the v7.75 cryptographic-commitment lookup endpoint.
type DerivationCommitmentDeps struct {
	CommitmentStore DerivationCommitmentFetcher
	Logger          *slog.Logger
}

// NewDerivationCommitmentQueryHandler returns the GET
// /v1/derivation-commitments?seq=N HTTP handler.
func NewDerivationCommitmentQueryHandler(deps *DerivationCommitmentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		seqStr := r.URL.Query().Get("seq")
		if seqStr == "" {
			writeTypedError(ctx, w, apitypes.ErrorClassMissingQueryParam,
				http.StatusBadRequest, "seq parameter required")
			return
		}
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid seq parameter")
			return
		}

		row, err := deps.CommitmentStore.QueryBySequence(ctx, seq)
		if err != nil {
			deps.Logger.Error("derivation commitment query", "seq", seq, "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
			return
		}
		if row == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "no derivation commitment covers this sequence")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"range_start_seq": row.RangeStartSeq,
			"range_end_seq":   row.RangeEndSeq,
			"prior_smt_root":  hex.EncodeToString(row.PriorSMTRoot[:]),
			"post_smt_root":   hex.EncodeToString(row.PostSMTRoot[:]),
			"mutations_json":  json.RawMessage(row.MutationsJSON),
			"commentary_seq":  row.CommentarySeq,
			"created_at":      row.CreatedAt,
		})
	}
}
