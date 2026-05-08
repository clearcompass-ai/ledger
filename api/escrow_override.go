/*
FILE PATH: api/escrow_override.go

POST /v1/escrow-override — ledger endpoint accepting an escrow
override request, collecting K-of-N witness cosignatures, and
broadcasting the cosigned authorization as a
KindEscrowOverrideAuth gossip event.

# REQUEST SHAPE

	POST /v1/escrow-override HTTP/1.1
	Content-Type: application/json

	{
	  "escrow_id":     "<64 hex chars (32 bytes)>",
	  "decision_hash": "<64 hex chars (32 bytes)>",
	  "effective":     <unix-seconds; uint64>
	}

# RESPONSE SHAPES

	200 OK — the override was authorized; body carries the gossip
	           event ID + the K signatures' aggregate count.
	400 — malformed request (bad JSON / non-hex / wrong length).
	502 — K-of-N collection or gossip publish failed; details
	           in the body. The HTTP layer treats this as a
	           retriable upstream failure.

# AUTH

This endpoint must NOT be exposed unauthenticated in production.
The current implementation is the ledger-internal mechanism;
caller authentication / rate-limiting is the responsibility of
the deployment's reverse-proxy / mTLS layer or future
api/middleware additions. Documenting here so a casual reader
doesn't assume open access is intended.

# IDEMPOTENCY

The gossip Store enforces per-originator chain-discipline: a
re-submission with the same content produces the same canonical
bytes → same EventID → idempotent Append. The collector,
however, makes a fresh round of HTTP calls to witnesses on each
request — callers should not retry tightly without a backoff.
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// EscrowOverrideRequest is the JSON request body shape.
type EscrowOverrideRequest struct {
	EscrowID     string `json:"escrow_id"`
	DecisionHash string `json:"decision_hash"`
	Effective    uint64 `json:"effective"`
}

// EscrowOverrideResponse is the JSON success response shape.
type EscrowOverrideResponse struct {
	EventID    string `json:"event_id"`
	Signatures int    `json:"signatures"`
	Lamport    uint64 `json:"lamport"`
}

// EscrowOverrideHandler returns an http.HandlerFunc backed by
// the supplied service. Returns nil + no-op handler when the
// service is nil — callers nil-guard against an unconfigured
// service (gossip disabled, witness mode disabled).
//
// Request body cap: 4 KiB. The wire shape is fixed-size hex
// strings + a uint64; anything larger is malformed.
func EscrowOverrideHandler(service EscrowOverrideProcessor, logger *slog.Logger) http.HandlerFunc {
	if service == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			writeTypedJSONError(ctx, w, apitypes.ErrorClassMalformedBody,
				http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		var req EscrowOverrideRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeTypedJSONError(ctx, w, apitypes.ErrorClassMalformedJSON,
				http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}

		var escrowID, decisionHash [32]byte
		if err := decodeHex32(req.EscrowID, &escrowID); err != nil {
			writeTypedJSONError(ctx, w, apitypes.ErrorClassBadHexEncoding,
				http.StatusBadRequest, "escrow_id: "+err.Error())
			return
		}
		if err := decodeHex32(req.DecisionHash, &decisionHash); err != nil {
			writeTypedJSONError(ctx, w, apitypes.ErrorClassBadHexEncoding,
				http.StatusBadRequest, "decision_hash: "+err.Error())
			return
		}
		if req.Effective == 0 {
			writeTypedJSONError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "effective must be non-zero")
			return
		}

		result, err := service.ProcessOverride(ctx, escrowID, decisionHash, req.Effective)
		if err != nil {
			logger.Warn("escrow override failed", "error", err)
			writeTypedJSONError(ctx, w, apitypes.ErrorClassEscrowOverrideFailed,
				http.StatusBadGateway, "process override: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(EscrowOverrideResponse{
			EventID:    hex.EncodeToString(result.EventID[:]),
			Signatures: result.Signatures,
			Lamport:    result.Lamport,
		})
	}
}

// decodeHex32 parses a 64-char hex string into a 32-byte array.
func decodeHex32(s string, out *[32]byte) error {
	if len(s) != 64 {
		return errBadHex32
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(out[:], raw)
	return nil
}

var errBadHex32 = &hexLengthError{}

type hexLengthError struct{}

func (*hexLengthError) Error() string { return "expected 64 hex chars (32 bytes)" }

// writeJSONError emits a {"error": "..."} body with the supplied
// status code.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
