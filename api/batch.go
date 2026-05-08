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

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkadmission "github.com/clearcompass-ai/attesta/crypto/admission"
	sdksct "github.com/clearcompass-ai/attesta/crypto/sct"
	"github.com/clearcompass-ai/attesta/exchange/policy"

	"github.com/clearcompass-ai/ledger/admission"
	"github.com/clearcompass-ai/ledger/api/middleware"
	"github.com/clearcompass-ai/ledger/apitypes"
	"github.com/clearcompass-ai/ledger/wal"
)

const (
	// MaxBatchSize caps the number of entries per batch request.
	MaxBatchSize = 256

	// AbsoluteMaxBatchPayloadBytes is the hard ceiling on the
	// HTTP request body size for /v1/entries/batch. Caps heap
	// pressure under malicious payloads regardless of the per-entry
	// MaxEntrySize configuration: a 1 MB single-entry cap can still
	// admit 256 entries × ~2× hex overhead, but the total request
	// body never exceeds this absolute ceiling.
	AbsoluteMaxBatchPayloadBytes = 64 << 20 // 64 MiB

	// maxBatchPayloadBytes is the floor used when a tiny per-entry
	// MaxEntrySize would otherwise produce a request-body cap below
	// the minimum useful size. Pre-existing constant kept for
	// backwards compatibility with callers expecting a fixed floor.
	maxBatchPayloadBytes = 4 << 20 // 4 MiB
)

type BatchEntry struct {
	WireBytesHex string `json:"wire_bytes_hex"`
}

type BatchSubmissionRequest struct {
	Entries []BatchEntry `json:"entries"`
}

type BatchResultEntry struct {
	SCT sdksct.SignedCertificateTimestamp `json:"sct"`
}

type BatchSubmissionResponse struct {
	Results []BatchResultEntry `json:"results"`
}

type preparedEntry struct {
	entry         *envelope.Entry
	canonical     []byte
	canonicalHash [32]byte
	logTime       time.Time
}

type preflightError struct {
	status int
	msg    string
	class  apitypes.ErrorClass
}

func (e *preflightError) Error() string { return e.msg }
func preflightFail(class apitypes.ErrorClass, status int, format string, args ...any) *preflightError {
	return &preflightError{status: status, msg: fmt.Sprintf(format, args...), class: class}
}

// computeEffectiveBatchPayloadCap derives the io.LimitReader cap
// for a batch request body from the per-entry MaxEntrySize.
//
// Bounds:
//   - Floor at maxBatchPayloadBytes (4 MiB): a tiny per-entry cap
//     would otherwise produce a request-body cap below the minimum
//     useful size; raise to 4 MiB so legitimate small-entry callers
//     are not artificially capped.
//   - Ceiling at AbsoluteMaxBatchPayloadBytes (64 MiB): defends
//     against OOM via crafted batches. The naive formula
//     (MaxBatchSize × per-entry × 2 + headroom) yields ~512 MiB at
//     the default 1 MiB MaxEntrySize, far above any legitimate
//     batch payload size.
func computeEffectiveBatchPayloadCap(maxEntrySize int64) int64 {
	cap := int64(MaxBatchSize)*((maxEntrySize+512)*2+128) + 1024
	if cap < maxBatchPayloadBytes {
		cap = maxBatchPayloadBytes
	}
	if cap > AbsoluteMaxBatchPayloadBytes {
		cap = AbsoluteMaxBatchPayloadBytes
	}
	return cap
}

func NewBatchSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionDeps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionDeps.LogDID must be non-empty (destination-binding enforcement)")
	}
	if deps.LedgerDID == "" {
		panic("api: SubmissionDeps.LedgerDID must be non-empty for batch SCT signing")
	}
	if deps.LedgerSignerPriv == nil {
		panic("api: SubmissionDeps.LedgerSignerPriv must be non-nil for batch SCT signing")
	}

	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}
	effectiveBatchPayloadCap := computeEffectiveBatchPayloadCap(deps.MaxEntrySize)

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := io.ReadAll(io.LimitReader(r.Body, effectiveBatchPayloadCap))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedBody,
				http.StatusBadRequest, "failed to read request body")
			return
		}
		var req BatchSubmissionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedJSON,
				http.StatusBadRequest, fmt.Sprintf("invalid JSON: %s", err))
			return
		}
		if len(req.Entries) == 0 {
			writeTypedError(ctx, w, apitypes.ErrorClassEmptyBatch,
				http.StatusBadRequest, "empty batch")
			return
		}
		if len(req.Entries) > MaxBatchSize {
			writeTypedError(ctx, w, apitypes.ErrorClassBatchTooLarge,
				http.StatusBadRequest,
				fmt.Sprintf("batch size %d exceeds max %d", len(req.Entries), MaxBatchSize))
			return
		}

		prepared := make([]*preparedEntry, 0, len(req.Entries))
		// Intra-batch dedup: rejecting a same-batch duplicate before
		// credit deduction prevents the caller from paying twice for
		// the same canonical hash. Historical dedup (entry_index)
		// happens immediately after — both return 409 Conflict so the
		// caller can fix the batch and retry without partial state.
		seen := make(map[[32]byte]int, len(req.Entries))
		for i, be := range req.Entries {
			rawWire, decodeErr := hex.DecodeString(be.WireBytesHex)
			if decodeErr != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassBadHexEncoding,
					http.StatusBadRequest, fmt.Sprintf("entry %d: hex decode: %s", i, decodeErr))
				return
			}
			pe, perr := preflightEntry(ctx, rawWire, deps, freshness)
			if perr != nil {
				writeTypedError(ctx, w, perr.class,
					perr.status, fmt.Sprintf("entry %d: %s", i, perr.msg))
				return
			}
			// In-batch dedup.
			if firstIdx, dup := seen[pe.canonicalHash]; dup {
				writeTypedError(ctx, w, apitypes.ErrorClassDuplicateEntry,
					http.StatusConflict,
					fmt.Sprintf("entry %d duplicates entry %d in same batch", i, firstIdx))
				return
			}
			// Historical dedup against entry_index. Skipped when
			// EntryStore is nil (unit-test path); production wiring
			// always provides one. Mirrors api/submission.go step 8a.
			if deps.Storage.EntryStore != nil {
				if existingSeq, found, fetchErr := deps.Storage.EntryStore.FetchByHash(ctx, pe.canonicalHash); fetchErr == nil && found {
					writeTypedError(ctx, w, apitypes.ErrorClassDuplicateEntry,
						http.StatusConflict,
						fmt.Sprintf("entry %d duplicate entry: existing sequence %d", i, existingSeq))
					return
				}
			}
			seen[pe.canonicalHash] = i
			prepared = append(prepared, pe)
		}

		results := make([]BatchResultEntry, 0, len(prepared))
		for i, pe := range prepared {
			if err := deductCreditModeA(ctx, deps, middleware.IsAuthenticated(ctx), middleware.ExchangeDID(ctx)); err != nil {
				if errors.Is(err, apitypes.ErrInsufficientCredits) {
					writeTypedError(ctx, w, apitypes.ErrorClassInsufficientCredits,
						http.StatusPaymentRequired,
						fmt.Sprintf("insufficient write credits at entry %d/%d", i, len(prepared)))
					return
				}
				deps.Logger.Error("batch credit deduction failed", "index", i, "error", err)
				writeTypedError(ctx, w, apitypes.ErrorClassCreditDeductFailed,
					http.StatusInternalServerError, "credit deduction failed")
				return
			}

			if err := deps.Storage.WAL.Submit(ctx, pe.canonicalHash, pe.canonical, pe.logTime.UnixMicro()); err != nil {
				if errors.Is(err, wal.ErrQueueFull) {
					w.Header().Set("Retry-After", "5")
					writeTypedError(ctx, w, apitypes.ErrorClassWALBackpressure,
						http.StatusServiceUnavailable,
						fmt.Sprintf("backpressure at entry %d/%d: WAL queue full", i, len(prepared)))
					return
				}
				deps.Logger.Error("batch wal submit failed", "index", i, "error", err)
				writeTypedError(ctx, w, apitypes.ErrorClassWALPersistFailed,
					http.StatusInternalServerError,
					fmt.Sprintf("batch admission failed at entry %d/%d", i, len(prepared)))
				return
			}

			sct, signErr := SignSCT(deps.LedgerSignerPriv, deps.LedgerDID, deps.LogDID, pe.canonicalHash, pe.logTime)
			if signErr != nil {
				deps.Logger.Error("batch SCT signing failed", "index", i, "error", signErr)
				writeTypedError(ctx, w, apitypes.ErrorClassSCTSigningFailed,
					http.StatusInternalServerError,
					fmt.Sprintf("batch admission failed at entry %d/%d", i, len(prepared)))
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
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "entry too short for preamble")
	}
	protocolVersion := binary.BigEndian.Uint16(rawWire[0:2])
	if protocolVersion != envelope.CurrentProtocolVersion() {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "unsupported protocol version %d (expected %d)", protocolVersion, envelope.CurrentProtocolVersion())
	}
	entry, err := envelope.Deserialize(rawWire)
	if err != nil {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "deserialize: %s", err)
	}
	canonical := rawWire
	algoID := entry.Signatures[0].AlgoID
	sigBytes := entry.Signatures[0].Bytes
	if err := envelope.ValidateAlgorithmID(algoID); err != nil {
		return nil, preflightFail(apitypes.ErrorClassSignatureInvalid, http.StatusUnauthorized, "%s", err)
	}
	if err := entry.Validate(); err != nil {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "entry validation: %s", err)
	}
	if err := admission.CheckNFC(entry); err != nil {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "NFC: %s", err)
	}
	if entry.Header.Destination != deps.LogDID {
		return nil, preflightFail(apitypes.ErrorClassDestinationMismatch, http.StatusForbidden, "entry destination %q does not match log %q", entry.Header.Destination, deps.LogDID)
	}
	if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
		return nil, preflightFail(apitypes.ErrorClassFreshnessExpired, http.StatusUnprocessableEntity, "freshness: %s", err)
	}
	if entry.Header.SignerDID == "" {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "empty signer DID")
	}
	if err := admission.VerifyEntrySignature(ctx, entry, sigBytes, deps.Identity.DIDResolver); err != nil {
		switch {
		case errors.Is(err, admission.ErrSignerDIDResolution):
			return nil, preflightFail(apitypes.ErrorClassSignatureInvalid, http.StatusUnauthorized, "%s", err)
		case errors.Is(err, admission.ErrSignatureInvalid):
			return nil, preflightFail(apitypes.ErrorClassSignatureInvalid, http.StatusUnauthorized, "%s", err)
		default:
			return nil, preflightFail(apitypes.ErrorClassDBQueryFailed, http.StatusInternalServerError, "signature verification path failed")
		}
	}
	if int64(len(canonical)) > deps.MaxEntrySize {
		return nil, preflightFail(apitypes.ErrorClassBodyTooLarge, http.StatusRequestEntityTooLarge, "canonical bytes %d exceed max %d", len(canonical), deps.MaxEntrySize)
	}
	if !middleware.CheckEvidenceCap(entry) {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "Evidence_Pointers %d exceeds cap %d (non-snapshot)", len(entry.Header.EvidencePointers), middleware.MaxEvidencePointers)
	}
	canonicalHash, err := envelope.EntryIdentity(entry)
	if err != nil {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "EntryIdentity: %s", err)
	}
	if !middleware.IsAuthenticated(ctx) {
		h := &entry.Header
		if h.AdmissionProof == nil {
			return nil, preflightFail(apitypes.ErrorClassAdmissionProofInvalid, http.StatusForbidden, "unauthenticated submission requires compute stamp")
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
			return nil, preflightFail(apitypes.ErrorClassAdmissionProofInvalid, http.StatusForbidden, "stamp verification failed: %s", err)
		}
	}
	logTime := time.Now().UTC()
	return &preparedEntry{entry: entry, canonical: canonical, canonicalHash: canonicalHash, logTime: logTime}, nil
}
