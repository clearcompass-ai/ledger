/*
FILE PATH: api/submission.go

Entry submission endpoint — the complete admission pipeline.
Fail-fast: first failure terminates with appropriate HTTP status.

KEY ARCHITECTURAL DECISIONS:
  - Sequential pipeline: order matters (sig before size, size before enqueue).
  - SDK-D5 contract established HERE: signature verified before persistence.
  - Decision 50: Log_Time assigned at step 9, never in canonical bytes.
  - Decision 51: Evidence_Pointers cap checked at step 7.
  - Atomic persist+enqueue: single Postgres tx prevents orphaned entries.
  - Live difficulty: reads from DifficultyController per-request, not snapshot.
  - Protocol version validated at step 1 (preamble check).
  - Canonical hash via envelope.EntryIdentity (SDK v0.3.0 single source of truth).
  - Duplicate hash mapped to HTTP 409 (not generic 500).

SDK v0.3.0 HARDENING:
  - Step 3a: entry.Validate() re-applies NewEntry's write-time invariants.
  - Step 3b: destination binding enforcement.
  - Step 3c: late-replay freshness via exchange/policy.CheckFreshness.
  - Step 5/8: envelope.EntryIdentity for the canonical hash primitive.

v7.75 WAVE 1 ADMISSION PACKAGE:
  - Step 3a-NFC: admission.CheckNFC asserts NFC normalization on every
    DID-shaped header field. Defensive only — no normalization on the
    caller's behalf (SDK Decision 52 caller-normalizes contract).
  - Step 4: admission.VerifyEntrySignature wraps SDK signatures.VerifyEntry
    and preserves the Phase 2 nil-resolver passthrough internally.
  - Step 4-Schema (NEW, Wave 1 v3 §C2): commitment-schema dispatch.
    Peeks the entry's payload schema_id and routes recognized
    cryptographic-commitment payloads through the SDK Parse* validators
    to extract the SplitID for index population at Step 11. Unrecognized
    payloads pass through untouched (load-bearing invariant — see the
    "Passthrough invariant" docblock at the dispatch site).
    NOTE: parsing here exposes the SplitID for Step 11 indexing only;
    the operator does not interpret payload semantics for coupling,
    contestability, or governance. Domain-payload semantics remain
    opaque to the operator per the Domain/Protocol Separation Principle.
  - Step 11 (UPDATED): admission tx now also INSERTs into
    commitment_split_id when a SplitID was extracted at Step 4-Schema.
    Population is in the same Postgres transaction as the entry_index
    insert so the index never references a non-existent sequence.

  - DIDResolver: nil = Phase 2 wire format trust model.
    set = Phase 4 full DID→pubkey→VerifyEntry. Future migration can
    replace this with did.DefaultVerifierRegistry.VerifyEntry.

INVARIANTS:
  - Past step 3a-NFC: all entries have NFC-normalized DID-shaped fields.
  - Past step 3b: all entries are bound to THIS log's LogDID.
  - Past step 4: all entries have verified signatures (SDK-D5).
  - Past step 4-Schema: any pre-grant or escrow-split commitment entry
    has a structurally valid payload and an extracted SplitID.
  - Log_Time is monotonically non-decreasing within single-operator deployment.
  - Sequence numbers are gapless (Postgres sequence).
*/
package api

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"
	sdkschema "github.com/clearcompass-ai/ortholog-sdk/schema"

	"github.com/clearcompass-ai/ortholog-operator/admission"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) DID Resolution Interface (Phase 4 signature verification)
// ─────────────────────────────────────────────────────────────────────────────

// DIDResolver resolves a signer DID to its current secp256k1 public key.
// Phase 4 SDK provides the concrete implementation (did/resolver.go).
//
// nil = Phase 2 trust model (wire format integrity only).
// set = Phase 4 full verification (DID → pubkey → sdk VerifyEntry).
//
// Structurally compatible with admission.DIDResolver — the operator's
// admission package defines the same single-method interface, and Go
// auto-converts at the call site to admission.VerifyEntrySignature.
type DIDResolver interface {
	ResolvePublicKey(ctx context.Context, did string) (*ecdsa.PublicKey, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Submission Dependencies — grouped by cohesion
// ─────────────────────────────────────────────────────────────────────────────

// StorageDeps groups persistence dependencies for the submission handler.
type StorageDeps struct {
	DB          *pgxpool.Pool
	EntryStore  *store.EntryStore
	EntryWriter tessera.EntryWriter
}

// AdmissionConfig groups parameters that govern admission proof verification.
type AdmissionConfig struct {
	DiffController        *middleware.DifficultyController
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
}

// IdentityDeps groups credential and DID resolution dependencies.
type IdentityDeps struct {
	CreditStore *store.CreditStore
	DIDResolver DIDResolver
}

// SubmissionDeps is the dependency surface for the POST /v1/entries handler.
type SubmissionDeps struct {
	Storage      StorageDeps
	Admission    AdmissionConfig
	Identity     IdentityDeps
	LogDID       string
	MaxEntrySize int64
	Logger       *slog.Logger

	// FreshnessTolerance configures the late-replay rejection window
	// at admission time. Zero defaults to policy.FreshnessInteractive.
	FreshnessTolerance time.Duration
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Schema dispatch (C2 — commitment SplitID extraction)
// ─────────────────────────────────────────────────────────────────────────────

// commitmentPayloadPeek mirrors the leading "schema_id" field shared
// by both pre-grant-commitment-v1 and escrow-split-commitment-v1
// payload envelopes. Any other field in the payload is ignored at
// the peek stage; full validation lives in the SDK's Parse*
// functions which are only invoked when the schema_id matches a
// recognized commitment schema.
type commitmentPayloadPeek struct {
	SchemaID string `json:"schema_id"`
}

// dispatchCommitmentSchema inspects the entry's DomainPayload for a
// recognized commitment schema_id and, when matched, routes the entry
// through the appropriate SDK Parse* validator to extract the
// 32-byte SplitID for downstream index population.
//
// Return contract:
//
//   - (nil, "", nil): no commitment schema matched. The entry is not
//     a v7.75 cryptographic-commitment entry; admission proceeds
//     unchanged. This is the Passthrough invariant case (see below).
//   - (&splitID, schemaID, nil): a recognized commitment schema
//     parsed cleanly; the SplitID will be inserted into
//     commitment_split_id at Step 11.
//   - (nil, "", err): a recognized commitment schema_id was present
//     but the payload failed structural validation. Admission MUST
//     reject the entry — a malformed commitment entry would surface
//     to verifiers as missing or unparseable on lookup.
//
// Passthrough invariant (Wave 1 v3 §C2). An entry whose payload has
// no schema_id field, an unrecognized schema_id, or no DomainPayload
// at all MUST flow through this stage unchanged. The dispatch is a
// switch on KNOWN cryptographic-commitment schema_ids; the default
// branch is a no-op return. This is what allows the F4 bootstrap
// script to flow schema-definition entries through admission before
// any commitment entry has ever been admitted, and it preserves the
// Domain/Protocol Separation Principle: the operator never inspects
// payload semantics it does not own.
func dispatchCommitmentSchema(entry *envelope.Entry) (*[32]byte, string, error) {
	if entry == nil || len(entry.DomainPayload) == 0 {
		return nil, "", nil
	}
	var peek commitmentPayloadPeek
	// json.Unmarshal failure on the peek is treated as passthrough,
	// not as rejection: domain payloads are not required to be JSON,
	// and malformed payloads in unrelated schemas should not be
	// policed here. The recognized-schema branches below re-decode
	// and surface their own structural errors via the SDK Parse*
	// functions.
	if err := json.Unmarshal(entry.DomainPayload, &peek); err != nil {
		return nil, "", nil
	}
	switch peek.SchemaID {
	case artifact.PREGrantCommitmentSchemaID:
		commitment, err := sdkschema.ParsePREGrantCommitmentEntry(entry)
		if err != nil {
			return nil, "", err
		}
		sid := commitment.SplitID
		return &sid, artifact.PREGrantCommitmentSchemaID, nil
	case escrow.EscrowSplitCommitmentSchemaID:
		commitment, err := sdkschema.ParseEscrowSplitCommitmentEntry(entry)
		if err != nil {
			return nil, "", err
		}
		sid := commitment.SplitID
		return &sid, escrow.EscrowSplitCommitmentSchemaID, nil
	default:
		// Passthrough — see invariant docblock above.
		return nil, "", nil
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Submission Handler
// ─────────────────────────────────────────────────────────────────────────────

// NewSubmissionHandler creates the POST /v1/entries handler.
//
// Panics if AdmissionConfig.EpochWindowSeconds is non-positive — without
// a valid epoch window, the handler cannot validate Mode B admission proofs
// and the operator should refuse to start.
func NewSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
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

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// ── Step 1: Read raw bytes + validate preamble ─────────────────
		sigOverhead := int64(512)
		raw, err := io.ReadAll(io.LimitReader(r.Body, deps.MaxEntrySize+sigOverhead))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		if len(raw) < 6 {
			writeError(w, http.StatusUnprocessableEntity, "entry too short for preamble")
			return
		}
		protocolVersion := binary.BigEndian.Uint16(raw[0:2])
		if protocolVersion != envelope.CurrentProtocolVersion() {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("unsupported protocol version %d (expected %d)",
					protocolVersion, envelope.CurrentProtocolVersion()))
			return
		}

		// ── Step 2: Deserialize wire bytes, validate algo ID ───────────
		// Under v7.75 the wire bytes ARE the canonical bytes — the
		// multi-sig section is appended INSIDE the canonical form by
		// envelope.Serialize, so envelope.StripSignature is gone.
		// Deserialize rejects zero-sig sections (ErrEmptySignatureList),
		// so entry.Signatures[0] is safe here.
		entry, err := envelope.Deserialize(raw)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("deserialize: %s", err))
			return
		}
		algoID := entry.Signatures[0].AlgoID
		sigBytes := entry.Signatures[0].Bytes

		if err := envelope.ValidateAlgorithmID(algoID); err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		// ── Step 3a: Re-apply NewEntry's write-time invariants ─────────
		if err := entry.Validate(); err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("entry validation: %s", err))
			return
		}

		// ── Step 3a-NFC: Defensive NFC assertion (Wave 1 v7.75 F2) ─────
		if err := admission.CheckNFC(entry); err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("NFC: %s", err))
			return
		}

		// ── Step 3b: Destination binding enforcement ───────────────────
		if entry.Header.Destination != deps.LogDID {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("entry destination %q does not match log %q",
					entry.Header.Destination, deps.LogDID))
			return
		}

		// ── Step 3c: Late-replay freshness ─────────────────────────────
		if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("freshness: %s", err))
			return
		}

		// ── Step 4: Signature verification (SDK-D5, Wave 1 F3a) ────────
		if entry.Header.SignerDID == "" {
			writeError(w, http.StatusUnprocessableEntity, "empty signer DID")
			return
		}
		if err := admission.VerifyEntrySignature(ctx, entry, sigBytes, deps.Identity.DIDResolver); err != nil {
			switch {
			case errors.Is(err, admission.ErrSignerDIDResolution):
				writeError(w, http.StatusUnauthorized, err.Error())
			case errors.Is(err, admission.ErrSignatureInvalid):
				writeError(w, http.StatusUnauthorized, err.Error())
			default:
				deps.Logger.Error("signature verification path failed", "error", err)
				writeError(w, http.StatusInternalServerError, "signature verification failed")
			}
			return
		}

		// ── Step 4-Schema: Commitment dispatch (Wave 1 v3 §C2) ─────────
		// Recognized cryptographic-commitment payloads route through
		// the SDK Parse* validators to extract the SplitID. Recognized
		// failures (ErrCommitmentPayloadMalformed, ErrCommitmentSchemaIDMismatch)
		// reject with HTTP 422. Unrecognized schemas pass through —
		// see dispatchCommitmentSchema's Passthrough invariant.
		extractedSplitID, extractedSchemaID, dispatchErr := dispatchCommitmentSchema(entry)
		if dispatchErr != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("commitment schema: %s", dispatchErr))
			return
		}

		// ── Step 5: Entry size (SDK-D11) ───────────────────────────────
		// Wire bytes ARE the canonical bytes under v7.75 (multi-sig
		// section is part of the canonical form).
		if int64(len(raw)) > deps.MaxEntrySize {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("canonical bytes %d exceed max %d",
					len(raw), deps.MaxEntrySize))
			return
		}

		// ── Step 6: Evidence_Pointers cap (Decision 51) ────────────────
		if !middleware.CheckEvidenceCap(entry) {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("Evidence_Pointers %d exceeds cap %d (non-snapshot)",
					len(entry.Header.EvidencePointers),
					middleware.MaxEvidencePointers))
			return
		}

		// ── Step 7: Admission mode ─────────────────────────────────────
		authenticated := middleware.IsAuthenticated(ctx)
		exchangeDID := middleware.ExchangeDID(ctx)

		if !authenticated {
			h := &entry.Header
			if h.AdmissionProof == nil {
				writeError(w, http.StatusForbidden,
					"unauthenticated submission requires compute stamp")
				return
			}

			apiProof := sdkadmission.ProofFromWire(h.AdmissionProof, deps.LogDID)

			canonicalHash := envelope.EntryIdentity(entry)
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
				apiProof,
				canonicalHash,
				deps.LogDID,
				currentDifficulty,
				hashFunc,
				nil,
				currentEpoch,
				acceptanceWindow,
			); err != nil {
				writeError(w, http.StatusForbidden,
					fmt.Sprintf("stamp verification failed: %s", err))
				return
			}
		}

		// ── Step 8: Canonical hash (Tessera-aligned vocabulary) ────────
		canonicalHash := envelope.EntryIdentity(entry)

		// ── Step 9: Log_Time assignment (SDK-D1, Decision 50) ──────────
		logTime := time.Now().UTC()

		// ── Steps 10-12: Atomic persist + index + enqueue ──────────────
		var seq uint64
		err = store.WithReadCommittedTx(ctx, deps.Storage.DB, func(ctx context.Context, tx pgx.Tx) error {
			// Mode A credit deduction (inside transaction).
			if authenticated {
				if _, deductErr := deps.Identity.CreditStore.Deduct(ctx, tx, exchangeDID); deductErr != nil {
					return deductErr
				}
			}

			var seqErr error
			seq, seqErr = deps.Storage.EntryStore.NextSequence(ctx, tx)
			if seqErr != nil {
				return seqErr
			}

			var targetRootBytes, cosigOfBytes, schemaRefBytes []byte
			if entry.Header.TargetRoot != nil {
				targetRootBytes = store.SerializeLogPosition(*entry.Header.TargetRoot)
			}
			if entry.Header.CosignatureOf != nil {
				cosigOfBytes = store.SerializeLogPosition(*entry.Header.CosignatureOf)
			}
			if entry.Header.SchemaRef != nil {
				schemaRefBytes = store.SerializeLogPosition(*entry.Header.SchemaRef)
			}

			insertErr := deps.Storage.EntryStore.Insert(ctx, tx, store.EntryRow{
				SequenceNumber: seq,
				CanonicalHash:  canonicalHash,
				LogTime:        logTime,
				SignerDID:      entry.Header.SignerDID,
				TargetRoot:     targetRootBytes,
				CosignatureOf:  cosigOfBytes,
				SchemaRef:      schemaRefBytes,
			})
			if insertErr != nil {
				return insertErr
			}

			// ── Step 11: SplitID index population (Wave 1 v3 §C2/C3) ─
			// When Step 4-Schema extracted a SplitID, persist the
			// (sequence, schema_id, split_id) tuple inside the same
			// transaction so the index never references a non-existent
			// sequence. The (schema_id, split_id) tuple is intentionally
			// non-unique (Decision 3); duplicates here are equivocation
			// evidence, not a constraint violation.
			if extractedSplitID != nil {
				if _, splitErr := tx.Exec(ctx, `
					INSERT INTO commitment_split_id (sequence_number, schema_id, split_id)
					VALUES ($1, $2, $3)`,
					seq, extractedSchemaID, extractedSplitID[:],
				); splitErr != nil {
					return fmt.Errorf("commitment_split_id insert: %w", splitErr)
				}
			}

			if deps.Storage.EntryWriter != nil {
				// Wire bytes ARE the canonical bytes under v7.75; the
				// signatures section lives inside `raw`. The legacy
				// (canonical, sig) split is no longer meaningful — pass
				// the full wire bytes as canonical and a nil sig.
				if writeErr := deps.Storage.EntryWriter.WriteEntry(seq, raw, nil); writeErr != nil {
					return fmt.Errorf("write entry bytes: %w", writeErr)
				}
			}

			// Cursor mode: the entry_index INSERT IS the enqueue —
			// the log itself is the queue. The builder cursor reader
			// tails entry_index and advances builder_cursor in its
			// own atomic commit. No separate queue write needed.
			return nil
		})

		if err != nil {
			if errors.Is(err, store.ErrInsufficientCredits) {
				writeError(w, http.StatusPaymentRequired, "insufficient write credits")
				return
			}
			if errors.Is(err, store.ErrDuplicateEntry) {
				existingSeq, found, _ := deps.Storage.EntryStore.FetchByHash(ctx, canonicalHash)
				if found {
					writeError(w, http.StatusConflict,
						fmt.Sprintf("duplicate entry: existing sequence %d", existingSeq))
				} else {
					writeError(w, http.StatusConflict, "duplicate entry")
				}
				return
			}
			deps.Logger.Error("admission failed", "error", err)
			writeError(w, http.StatusInternalServerError, "admission failed")
			return
		}

		// ── Step 13: Success ───────────────────────────────────────────
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sequence_number": seq,
			"canonical_hash":  hex.EncodeToString(canonicalHash[:]),
			"log_time":        logTime.Format(time.RFC3339Nano),
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
