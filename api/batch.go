package api

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/admission"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

const MaxBatchSize = 256
const maxBatchPayloadBytes = 4 << 20

type BatchEntry struct {
	WireBytesHex string `json:"wire_bytes_hex"`
}

type BatchSubmissionRequest struct {
	Entries []BatchEntry `json:"entries"`
}

type BatchResultEntry struct {
	SCT SignedCertificateTimestamp `json:"sct"`
}

type BatchSubmissionResponse struct {
	Results []BatchResultEntry `json:"results"`
}

type preparedEntry struct {
	entry             *envelope.Entry
	canonical         []byte
	canonicalHash     [32]byte
	logTime           time.Time
	extractedSplitID  *[32]byte
	extractedSchemaID string
}

type preflightError struct {
	status int
	msg    string
}

func (e *preflightError) Error() string { return e.msg }
func preflightFail(status int, format string, args ...any) *preflightError {
	return &preflightError{status: status, msg: fmt.Sprintf(format, args...)}
}

func NewBatchSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionDeps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionDeps.LogDID must be non-empty (destination-binding enforcement)")
	}
	if deps.OperatorDID == "" {
		panic("api: SubmissionDeps.OperatorDID must be non-empty for batch SCT signing")
	}
	if deps.OperatorSignerPriv == nil {
		panic("api: SubmissionDeps.OperatorSignerPriv must be non-nil for batch SCT signing")
	}

	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}
	effectiveBatchPayloadCap := int64(MaxBatchSize)*((deps.MaxEntrySize+512)*2+128) + 1024
	if effectiveBatchPayloadCap < maxBatchPayloadBytes {
		effectiveBatchPayloadCap = maxBatchPayloadBytes
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := io.ReadAll(io.LimitReader(r.Body, effectiveBatchPayloadCap))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		var req BatchSubmissionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %s", err))
			return
		}
		if len(req.Entries) == 0 {
			writeError(w, http.StatusBadRequest, "empty batch")
			return
		}
		if len(req.Entries) > MaxBatchSize {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("batch size %d exceeds max %d", len(req.Entries), MaxBatchSize))
			return
		}

		prepared := make([]*preparedEntry, 0, len(req.Entries))
		for i, be := range req.Entries {
			rawWire, decodeErr := hex.DecodeString(be.WireBytesHex)
			if decodeErr != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("entry %d: hex decode: %s", i, decodeErr))
				return
			}
			pe, perr := preflightEntry(ctx, rawWire, deps, freshness)
			if perr != nil {
				writeError(w, perr.status, fmt.Sprintf("entry %d: %s", i, perr.msg))
				return
			}
			prepared = append(prepared, pe)
		}

		results := make([]BatchResultEntry, 0, len(prepared))
		for i, pe := range prepared {
			if err := deductCreditModeA(ctx, deps, middleware.IsAuthenticated(ctx), middleware.ExchangeDID(ctx)); err != nil {
				if errors.Is(err, store.ErrInsufficientCredits) {
					writeError(w, http.StatusPaymentRequired, fmt.Sprintf("insufficient write credits at entry %d/%d", i, len(prepared)))
					return
				}
				deps.Logger.Error("batch credit deduction failed", "index", i, "error", err)
				writeError(w, http.StatusInternalServerError, "credit deduction failed")
				return
			}

			if err := deps.Storage.WAL.Submit(ctx, pe.canonicalHash, pe.canonical); err != nil {
				if errors.Is(err, wal.ErrQueueFull) {
					w.Header().Set("Retry-After", "5")
					writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("backpressure at entry %d/%d: WAL queue full", i, len(prepared)))
					return
				}
				deps.Logger.Error("batch wal submit failed", "index", i, "error", err)
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("batch admission failed at entry %d/%d", i, len(prepared)))
				return
			}

			sct, signErr := SignSCT(deps.OperatorSignerPriv, deps.OperatorDID, deps.LogDID, pe.canonicalHash, pe.logTime)
			if signErr != nil {
				deps.Logger.Error("batch SCT signing failed", "index", i, "error", signErr)
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("batch admission failed at entry %d/%d", i, len(prepared)))
				return
			}
			results = append(results, BatchResultEntry{SCT: *sct})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(BatchSubmissionResponse{Results: results})
	}
}

func preflightEntry(ctx context.Context, rawWire []byte, deps *SubmissionDeps, freshness time.Duration) (*preparedEntry, *preflightError) {
	if len(rawWire) < 6 {
		return nil, preflightFail(http.StatusUnprocessableEntity, "entry too short for preamble")
	}
	protocolVersion := binary.BigEndian.Uint16(rawWire[0:2])
	if protocolVersion != envelope.CurrentProtocolVersion() {
		return nil, preflightFail(http.StatusUnprocessableEntity, "unsupported protocol version %d (expected %d)", protocolVersion, envelope.CurrentProtocolVersion())
	}
	entry, err := envelope.Deserialize(rawWire)
	if err != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity, "deserialize: %s", err)
	}
	canonical := rawWire
	algoID := entry.Signatures[0].AlgoID
	sigBytes := entry.Signatures[0].Bytes
	if err := envelope.ValidateAlgorithmID(algoID); err != nil {
		return nil, preflightFail(http.StatusUnauthorized, "%s", err)
	}
	if err := entry.Validate(); err != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity, "entry validation: %s", err)
	}
	if err := admission.CheckNFC(entry); err != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity, "NFC: %s", err)
	}
	if entry.Header.Destination != deps.LogDID {
		return nil, preflightFail(http.StatusForbidden, "entry destination %q does not match log %q", entry.Header.Destination, deps.LogDID)
	}
	if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity, "freshness: %s", err)
	}
	if entry.Header.SignerDID == "" {
		return nil, preflightFail(http.StatusUnprocessableEntity, "empty signer DID")
	}
	if err := admission.VerifyEntrySignature(ctx, entry, sigBytes, deps.Identity.DIDResolver); err != nil {
		switch {
		case errors.Is(err, admission.ErrSignerDIDResolution):
			return nil, preflightFail(http.StatusUnauthorized, "%s", err)
		case errors.Is(err, admission.ErrSignatureInvalid):
			return nil, preflightFail(http.StatusUnauthorized, "%s", err)
		default:
			return nil, preflightFail(http.StatusInternalServerError, "signature verification path failed")
		}
	}
	extractedSplitID, extractedSchemaID, dispatchErr := dispatchCommitmentSchema(entry)
	if dispatchErr != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity, "commitment schema: %s", dispatchErr)
	}
	if int64(len(canonical)) > deps.MaxEntrySize {
		return nil, preflightFail(http.StatusRequestEntityTooLarge, "canonical bytes %d exceed max %d", len(canonical), deps.MaxEntrySize)
	}
	if !middleware.CheckEvidenceCap(entry) {
		return nil, preflightFail(http.StatusUnprocessableEntity, "Evidence_Pointers %d exceeds cap %d (non-snapshot)", len(entry.Header.EvidencePointers), middleware.MaxEvidencePointers)
	}
	canonicalHash := envelope.EntryIdentity(entry)
	if !middleware.IsAuthenticated(ctx) {
		h := &entry.Header
		if h.AdmissionProof == nil {
			return nil, preflightFail(http.StatusForbidden, "unauthenticated submission requires compute stamp")
		}
		apiProof := sdkadmission.ProofFromWire(h.AdmissionProof, deps.LogDID)
		currentDifficulty := deps.Admission.DiffController.CurrentDifficulty()
		hashFuncName := deps.Admission.DiffController.HashFunction()
		var hashFunc sdkadmission.HashFunc
		switch hashFuncName {
		case "argon2id":
			hashFunc = sdkadmission.HashArgon2id
		default:
			hashFunc = sdkadmission.HashSHA256
		}
		currentEpoch := sdkadmission.CurrentEpoch(uint64(deps.Admission.EpochWindowSeconds))
		acceptanceWindow := uint64(deps.Admission.EpochAcceptanceWindow)
		if err := sdkadmission.VerifyStamp(apiProof, canonicalHash, deps.LogDID, currentDifficulty, hashFunc, nil, currentEpoch, acceptanceWindow); err != nil {
			return nil, preflightFail(http.StatusForbidden, "stamp verification failed: %s", err)
		}
	}
	logTime := time.Now().UTC()
	return &preparedEntry{entry: entry, canonical: canonical, canonicalHash: canonicalHash, logTime: logTime, extractedSplitID: extractedSplitID, extractedSchemaID: extractedSchemaID}, nil
}
