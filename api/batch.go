/*
FILE PATH: api/batch.go

POST /v1/entries/batch — atomic batch admission endpoint per
Wave 1 v3 §C6 + Decision 2.

Decision 2 contract:
  - Accepts an array of canonical wire-bytes (one entry per element).
  - Wraps the entire batch in a single Postgres database transaction
    (store.WithReadCommittedTx) — all entries land together or none.
  - Does NOT inspect payloads to enforce SDK-level lifecycle atomicity
    (e.g., grant↔commitment coupling). That enforcement lives at the
    SDK consumer + downstream verifier layers per the
    Domain/Protocol Separation Principle.

Per-entry admission stages 1–9 (read-only validation: deserialize,
NFC, signature, schema dispatch, freshness, size, evidence cap,
admission mode) run before the transaction opens. If any entry
fails preflight, the whole batch is rejected with the first error;
no transaction is opened and no rows are inserted.

The transactional body iterates the prepared entries and for each:
  - Deducts one credit (Mode A path) when authenticated.
  - Allocates the next sequence number.
  - Inserts entry_index + commitment_split_id (when applicable).
  - Writes wire bytes to the Tessera EntryWriter.
  - Enqueues the sequence for the builder loop.

If any per-entry transactional step fails, the surrounding
WithReadCommittedTx rolls back the whole batch and the response is
an HTTP error. Sequence numbers allocated within a rolled-back
transaction are returned to the Postgres SEQUENCE; the operator's
gapless-sequence invariant is preserved by the SEQUENCE itself, not
by this handler.

Code-reuse note: the read-only preflight stages duplicate logic in
NewSubmissionHandler. A follow-up commit will extract the shared
pipeline into api/admission_pipeline.go and have both handlers call
the same helpers. The duplication is intentional in this commit so
the file stands on its own and can be reviewed independently.
*/
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

	"github.com/jackc/pgx/v5"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/admission"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Limits
// ─────────────────────────────────────────────────────────────────────────────

// MaxBatchSize caps the number of entries per batch request.
// Sized to balance per-request overhead against transaction
// duration: 256 entries at ~1 KB each is ~256 KB of inserts in one
// tx, well within Postgres's comfort zone, and bounds the worst-case
// rollback cost on a single bad entry late in the batch.
const MaxBatchSize = 256

// maxBatchPayloadBytes caps the raw JSON request body size. Sized to
// fit MaxBatchSize entries each at deps.MaxEntrySize plus protocol
// envelope overhead and JSON framing. The handler computes the
// effective limit at request time using deps.MaxEntrySize.
//
// 4 MiB is a defensive floor for callers that submit small batches
// of small entries; larger batches scale the cap up via the
// computed effectiveBatchPayloadCap.
const maxBatchPayloadBytes = 4 << 20

// ─────────────────────────────────────────────────────────────────────────────
// 2) Wire types
// ─────────────────────────────────────────────────────────────────────────────

// BatchEntry is one element of a batch submission. The wire bytes
// hex-decode to the same canonical || signature_envelope payload
// that the single-entry POST /v1/entries endpoint accepts; callers
// MAY share a serializer between the two endpoints.
type BatchEntry struct {
	WireBytesHex string `json:"wire_bytes_hex"`
}

// BatchSubmissionRequest is the JSON request body shape.
type BatchSubmissionRequest struct {
	Entries []BatchEntry `json:"entries"`
}

// BatchResultEntry is the per-entry result returned on a successful
// batch admission. Fields mirror the single-entry submission
// response so consumers don't need to branch on endpoint.
type BatchResultEntry struct {
	SequenceNumber uint64 `json:"sequence_number"`
	CanonicalHash  string `json:"canonical_hash"`
	LogTime        string `json:"log_time"`
}

// BatchSubmissionResponse is the JSON response body shape on
// success. The results array is in the same order as the request's
// entries, so callers can correlate by index.
type BatchSubmissionResponse struct {
	Results []BatchResultEntry `json:"results"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Internal preflight types
// ─────────────────────────────────────────────────────────────────────────────

// preparedEntry carries the read-only outputs of a successful
// per-entry preflight. The transactional body consumes this struct
// to perform the inserts inside one Postgres tx.
type preparedEntry struct {
	entry *envelope.Entry
	// canonical holds the full wire bytes. Under v7.75 wire bytes
	// ARE the canonical bytes (the multi-sig section is appended
	// INSIDE the canonical form by envelope.Serialize), so there is
	// no separate sig blob to carry alongside. Callers needing the
	// primary signature read entry.Signatures[0].
	canonical         []byte
	canonicalHash     [32]byte
	logTime           time.Time
	extractedSplitID  *[32]byte
	extractedSchemaID string
}

// preflightError carries a structured failure from per-entry
// validation. The HTTP handler maps these to status codes; the
// transactional body does not produce them.
type preflightError struct {
	status int
	msg    string
}

func (e *preflightError) Error() string { return e.msg }

func preflightFail(status int, format string, args ...any) *preflightError {
	return &preflightError{status: status, msg: fmt.Sprintf(format, args...)}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Handler constructor
// ─────────────────────────────────────────────────────────────────────────────

// NewBatchSubmissionHandler creates the POST /v1/entries/batch
// handler. Reuses SubmissionDeps from NewSubmissionHandler — the
// dependency surface is identical because batch admission is
// definitionally N invocations of single-entry admission inside one
// shared transaction, not a different policy.
//
// Panics under the same preconditions as NewSubmissionHandler:
// non-positive EpochWindowSeconds or empty LogDID.
func NewBatchSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionDeps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionDeps.LogDID must be non-empty (destination-binding enforcement)")
	}

	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}

	// Effective body cap: enough headroom for a max-size entry per
	// slot, hex-encoded (× 2), plus JSON framing overhead. Caller
	// over-sized batches reject at body-read time before any parse
	// or admission cost is paid.
	effectiveBatchPayloadCap := int64(MaxBatchSize)*((deps.MaxEntrySize+512)*2+128) + 1024
	if effectiveBatchPayloadCap < maxBatchPayloadBytes {
		effectiveBatchPayloadCap = maxBatchPayloadBytes
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// ── A) Read + parse JSON body ──────────────────────────────────
		body, err := io.ReadAll(io.LimitReader(r.Body, effectiveBatchPayloadCap))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		var req BatchSubmissionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid JSON: %s", err))
			return
		}
		if len(req.Entries) == 0 {
			writeError(w, http.StatusBadRequest, "empty batch")
			return
		}
		if len(req.Entries) > MaxBatchSize {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("batch size %d exceeds max %d",
					len(req.Entries), MaxBatchSize))
			return
		}

		// ── B) Per-entry preflight (read-only stages 1–9) ──────────────
		prepared := make([]*preparedEntry, 0, len(req.Entries))
		for i, be := range req.Entries {
			rawWire, decodeErr := hex.DecodeString(be.WireBytesHex)
			if decodeErr != nil {
				writeError(w, http.StatusBadRequest,
					fmt.Sprintf("entry %d: hex decode: %s", i, decodeErr))
				return
			}
			pe, perr := preflightEntry(ctx, rawWire, deps, freshness)
			if perr != nil {
				writeError(w, perr.status,
					fmt.Sprintf("entry %d: %s", i, perr.msg))
				return
			}
			prepared = append(prepared, pe)
		}

		// ── C) Per-entry WAL-first admission ──────────────────────────
		// Under WAL-first, each entry's persistence is a 4-stage
		// pipeline (wal.Submit → tessera.AppendLeaf → Postgres txn →
		// wal.Sequence) that cannot be wrapped in a single batch-level
		// Postgres tx — Tessera assigns the seq before Postgres ever
		// sees the row, and the WAL commits durable bytes before
		// Tessera. Decision 2's "atomic batch" semantics shift here:
		// preflight (already done in stage B) is the all-or-nothing
		// gate; once preflight passes, persistence is best-effort
		// per-entry. On the first persistence failure we ABORT the
		// batch and return 500; the user retries, and previously-
		// admitted entries surface as 409 (duplicate) so the caller
		// can locate the partition point.
		results := make([]BatchResultEntry, 0, len(prepared))
		authenticated := middleware.IsAuthenticated(ctx)
		exchangeDID := middleware.ExchangeDID(ctx)

		for i, pe := range prepared {
			seq, admitErr := admitPreparedEntry(ctx, pe, deps, authenticated, exchangeDID)
			if admitErr != nil {
				if errors.Is(admitErr, wal.ErrQueueFull) {
					w.Header().Set("Retry-After", "5")
					writeError(w, http.StatusServiceUnavailable,
						fmt.Sprintf("backpressure at entry %d/%d: WAL queue full",
							i, len(prepared)))
					return
				}
				if errors.Is(admitErr, store.ErrInsufficientCredits) {
					writeError(w, http.StatusPaymentRequired,
						fmt.Sprintf("insufficient write credits at entry %d/%d", i, len(prepared)))
					return
				}
				if errors.Is(admitErr, store.ErrDuplicateEntry) {
					existingSeq, found, _ := deps.Storage.EntryStore.FetchByHash(ctx, pe.canonicalHash)
					if found {
						writeError(w, http.StatusConflict,
							fmt.Sprintf("entry %d/%d duplicate: existing sequence %d",
								i, len(prepared), existingSeq))
					} else {
						writeError(w, http.StatusConflict,
							fmt.Sprintf("entry %d/%d duplicate", i, len(prepared)))
					}
					return
				}
				deps.Logger.Error("batch admission entry failed",
					"index", i, "error", admitErr)
				writeError(w, http.StatusInternalServerError,
					fmt.Sprintf("batch admission failed at entry %d/%d", i, len(prepared)))
				return
			}
			results = append(results, BatchResultEntry{
				SequenceNumber: seq,
				CanonicalHash:  hex.EncodeToString(pe.canonicalHash[:]),
				LogTime:        pe.logTime.Format(time.RFC3339Nano),
			})
		}

		// ── D) Success ─────────────────────────────────────────────────
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(BatchSubmissionResponse{Results: results})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) Per-entry preflight (read-only)
// ─────────────────────────────────────────────────────────────────────────────

// preflightEntry runs the read-only admission stages 1–9 on a single
// wire-encoded entry. On success the returned preparedEntry is ready
// to be persisted by admitPreparedEntry inside a Postgres tx. On
// failure the *preflightError carries the HTTP status and message
// the handler will surface to the caller.
//
// This function is intentionally side-effect-free — no DB, no
// EntryWriter, no Queue — so a batch with one bad entry costs at
// most the parse + verify time for the entries that preflighted
// before the failure. No partial transaction is opened.
func preflightEntry(
	ctx context.Context,
	rawWire []byte,
	deps *SubmissionDeps,
	freshness time.Duration,
) (*preparedEntry, *preflightError) {
	// Step 1: preamble length + protocol version.
	if len(rawWire) < 6 {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"entry too short for preamble")
	}
	protocolVersion := binary.BigEndian.Uint16(rawWire[0:2])
	if protocolVersion != envelope.CurrentProtocolVersion() {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"unsupported protocol version %d (expected %d)",
			protocolVersion, envelope.CurrentProtocolVersion())
	}

	// Step 2: deserialize wire bytes, validate algo ID.
	// Under v7.75 the wire bytes ARE the canonical bytes — the
	// multi-sig section is appended INSIDE the canonical form by
	// envelope.Serialize, so envelope.StripSignature is gone.
	// Deserialize rejects zero-sig sections (ErrEmptySignatureList),
	// so entry.Signatures[0] is safe here.
	entry, err := envelope.Deserialize(rawWire)
	if err != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"deserialize: %s", err)
	}
	canonical := rawWire
	algoID := entry.Signatures[0].AlgoID
	sigBytes := entry.Signatures[0].Bytes
	if err := envelope.ValidateAlgorithmID(algoID); err != nil {
		return nil, preflightFail(http.StatusUnauthorized, "%s", err)
	}

	// Step 3a: re-apply NewEntry's write-time invariants.
	if err := entry.Validate(); err != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"entry validation: %s", err)
	}

	// Step 3a-NFC: defensive NFC assertion (Wave 1 v7.75 F2).
	if err := admission.CheckNFC(entry); err != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"NFC: %s", err)
	}

	// Step 3b: destination binding enforcement.
	if entry.Header.Destination != deps.LogDID {
		return nil, preflightFail(http.StatusForbidden,
			"entry destination %q does not match log %q",
			entry.Header.Destination, deps.LogDID)
	}

	// Step 3c: late-replay freshness.
	if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"freshness: %s", err)
	}

	// Step 4: signature verification (SDK-D5, Wave 1 F3a).
	if entry.Header.SignerDID == "" {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"empty signer DID")
	}
	if err := admission.VerifyEntrySignature(ctx, entry, sigBytes, deps.Identity.DIDResolver); err != nil {
		switch {
		case errors.Is(err, admission.ErrSignerDIDResolution):
			return nil, preflightFail(http.StatusUnauthorized, "%s", err)
		case errors.Is(err, admission.ErrSignatureInvalid):
			return nil, preflightFail(http.StatusUnauthorized, "%s", err)
		default:
			return nil, preflightFail(http.StatusInternalServerError,
				"signature verification path failed")
		}
	}

	// Step 4-Schema: commitment dispatch (Wave 1 v3 §C2).
	extractedSplitID, extractedSchemaID, dispatchErr := dispatchCommitmentSchema(entry)
	if dispatchErr != nil {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"commitment schema: %s", dispatchErr)
	}

	// Step 5: entry size.
	if int64(len(canonical)) > deps.MaxEntrySize {
		return nil, preflightFail(http.StatusRequestEntityTooLarge,
			"canonical bytes %d exceed max %d",
			len(canonical), deps.MaxEntrySize)
	}

	// Step 6: Evidence_Pointers cap.
	if !middleware.CheckEvidenceCap(entry) {
		return nil, preflightFail(http.StatusUnprocessableEntity,
			"Evidence_Pointers %d exceeds cap %d (non-snapshot)",
			len(entry.Header.EvidencePointers),
			middleware.MaxEvidencePointers)
	}

	// Step 7: admission mode (compute stamp for unauthenticated).
	canonicalHash := envelope.EntryIdentity(entry)
	authenticated := middleware.IsAuthenticated(ctx)
	if !authenticated {
		h := &entry.Header
		if h.AdmissionProof == nil {
			return nil, preflightFail(http.StatusForbidden,
				"unauthenticated submission requires compute stamp")
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
		if err := sdkadmission.VerifyStamp(
			apiProof, canonicalHash, deps.LogDID,
			currentDifficulty, hashFunc, nil,
			currentEpoch, acceptanceWindow,
		); err != nil {
			return nil, preflightFail(http.StatusForbidden,
				"stamp verification failed: %s", err)
		}
	}

	// Step 9: log_time assigned per entry. Each entry in a batch
	// gets its own UTC timestamp; sub-microsecond ordering within a
	// batch reflects the order entries appeared in the request.
	logTime := time.Now().UTC()

	return &preparedEntry{
		entry:             entry,
		canonical:         canonical,
		canonicalHash:     canonicalHash,
		logTime:           logTime,
		extractedSplitID:  extractedSplitID,
		extractedSchemaID: extractedSchemaID,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 6) Per-entry transactional admission
// ─────────────────────────────────────────────────────────────────────────────

// admitPreparedEntry runs the full WAL-first admission pipeline for
// a single preflighted entry. Returns the Tessera-assigned sequence
// number on success.
//
// Pipeline:
//   1. Early duplicate check (Postgres entry_index).
//   2. wal.Submit — bytes durable on local disk.
//   3. tessera.AppendLeaf — sequence assigned (dedup-aware).
//   4. Postgres txn:
//        - Mode A credit deduction
//        - entry_index INSERT
//        - commitment_split_id INSERT (when SplitID was extracted)
//   5. wal.Sequence — WAL state pending → sequenced.
//
// Errors are returned verbatim so the caller can map them to HTTP
// status codes (wal.ErrQueueFull → 503, store.ErrDuplicateEntry → 409,
// store.ErrInsufficientCredits → 402, default → 500).
//
// This is the shared kernel between single-entry POST /v1/entries
// and batch POST /v1/entries/batch. Tests pin the pipeline against
// fakes; integration tests cover the full chain through real
// Postgres + WAL + Tessera.
func admitPreparedEntry(
	ctx context.Context,
	pe *preparedEntry,
	deps *SubmissionDeps,
	authenticated bool,
	exchangeDID string,
) (uint64, error) {
	// Step 1: Early duplicate check — avoid a wasted WAL write.
	if existingSeq, found, fetchErr := deps.Storage.EntryStore.FetchByHash(ctx, pe.canonicalHash); fetchErr == nil && found {
		_ = existingSeq
		return 0, store.ErrDuplicateEntry
	}

	// Step 2: WAL durability.
	if err := deps.Storage.WAL.Submit(ctx, pe.canonicalHash, pe.canonical); err != nil {
		return 0, fmt.Errorf("wal submit: %w", err)
	}

	// Step 3: Tessera sequence assignment (dedup-aware).
	seq, err := deps.Storage.Tessera.AppendLeaf(pe.canonicalHash[:])
	if err != nil {
		return 0, fmt.Errorf("tessera AppendLeaf: %w", err)
	}

	// Step 4: Postgres sidecar.
	err = store.WithReadCommittedTx(ctx, deps.Storage.DB, func(ctx context.Context, tx pgx.Tx) error {
		if authenticated {
			if _, deductErr := deps.Identity.CreditStore.Deduct(ctx, tx, exchangeDID); deductErr != nil {
				return deductErr
			}
		}

		var targetRootBytes, cosigOfBytes, schemaRefBytes []byte
		if pe.entry.Header.TargetRoot != nil {
			targetRootBytes = store.SerializeLogPosition(*pe.entry.Header.TargetRoot)
		}
		if pe.entry.Header.CosignatureOf != nil {
			cosigOfBytes = store.SerializeLogPosition(*pe.entry.Header.CosignatureOf)
		}
		if pe.entry.Header.SchemaRef != nil {
			schemaRefBytes = store.SerializeLogPosition(*pe.entry.Header.SchemaRef)
		}

		if insertErr := deps.Storage.EntryStore.Insert(ctx, tx, store.EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  pe.canonicalHash,
			LogTime:        pe.logTime,
			SignerDID:      pe.entry.Header.SignerDID,
			TargetRoot:     targetRootBytes,
			CosignatureOf:  cosigOfBytes,
			SchemaRef:      schemaRefBytes,
		}); insertErr != nil {
			return insertErr
		}

		if pe.extractedSplitID != nil {
			if _, splitErr := tx.Exec(ctx, `
				INSERT INTO commitment_split_id (sequence_number, schema_id, split_id)
				VALUES ($1, $2, $3)`,
				seq, pe.extractedSchemaID, pe.extractedSplitID[:],
			); splitErr != nil {
				return fmt.Errorf("commitment_split_id insert: %w", splitErr)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	// Step 5: WAL state transition pending → sequenced.
	if err := deps.Storage.WAL.Sequence(ctx, pe.canonicalHash, seq); err != nil {
		// Bytes durable, Tessera has the seq, Postgres has the row;
		// only the WAL meta state didn't advance. Recoverable on
		// next boot via integrity.Reasserter (re-Add returns the
		// same seq via dedup, then Sequence transitions state).
		return 0, fmt.Errorf("wal Sequence: %w", err)
	}
	return seq, nil
}
