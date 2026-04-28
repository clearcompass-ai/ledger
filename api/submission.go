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
	"github.com/clearcompass-ai/ortholog-operator/wal"
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
// 2) WAL + Tessera interfaces (minimal admission-side surfaces)
// ─────────────────────────────────────────────────────────────────────────────

// WALCommitter is the WAL surface admission needs.
// *wal.Committer satisfies it.
type WALCommitter interface {
	// Submit blocks until wire bytes are durably persisted to local
	// disk. Returns wal.ErrQueueFull when the in-memory queue is
	// saturated; admission maps this to HTTP 503 + Retry-After.
	Submit(ctx context.Context, hash [32]byte, wire []byte) error

	// Sequence transitions the WAL state pending → sequenced after
	// Tessera assigned a sequence number for the entry. Used by the
	// sequencer; v1 facade reads MetaState only.
	Sequence(ctx context.Context, hash [32]byte, seq uint64) error

	// MetaState returns the current WAL state record for an entry.
	// The v1 facade polls this to wait for the background Sequencer
	// to advance Pending → Sequenced.
	MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error)
}

// TesseraAppender is the Tessera surface admission needs.
// *tessera.EmbeddedAppender satisfies it. AppendLeaf is dedup-aware
// when the appender is constructed with tessera.WithDeduplication
// (wired in cmd/operator/main.go) — re-Add of an existing identity
// returns the previously-assigned sequence rather than integrating
// again. This is the load-bearing safety property under concurrent
// admission of the same content.
type TesseraAppender interface {
	AppendLeaf(data []byte) (uint64, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Submission Dependencies — grouped by cohesion
// ─────────────────────────────────────────────────────────────────────────────

// StorageDeps groups persistence dependencies for the submission
// handler. The byte-store writer that lived here in v1 is gone:
// admission writes wire bytes to the WAL only; the Shipper migrates
// them to the byte store asynchronously.
type StorageDeps struct {
	DB         *pgxpool.Pool
	EntryStore *store.EntryStore
	WAL        WALCommitter
	Tessera    TesseraAppender
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
	OperatorDID  string
	MaxEntrySize int64
	Logger       *slog.Logger

	// OperatorSignerPriv signs SCTs returned by asynchronous
	// submission endpoints, including POST /v1/entries/batch.
	OperatorSignerPriv *ecdsa.PrivateKey

	// FreshnessTolerance configures the late-replay rejection window
	// at admission time. Zero defaults to policy.FreshnessInteractive.
	FreshnessTolerance time.Duration

	// V1Timeout caps how long the v1 facade polls WAL.MetaState for
	// the Sequencer to advance the entry to StateSequenced. Zero
	// defaults to DefaultV1Timeout. On expiry the handler returns
	// HTTP 504 with a structured payload pointing the client at
	// GET /v1/entries/hash/{hash} for a follow-up.
	V1Timeout time.Duration
}

// V1 facade timing constants. The facade pattern preserves the
// historical /v1/entries synchronous contract under the SCT/MMD
// architecture: wal.Submit completes synchronously, then the
// handler polls WAL.MetaState until the background Sequencer
// transitions the entry to StateSequenced (or the timeout
// elapses).
const (
	DefaultV1Timeout     = 30 * time.Second
	V1FacadePollInterval = 50 * time.Millisecond
)

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

// preparedSubmission is the result of running steps 1-9 of the
// admission fast path. v1 (facade) and v2 (SCT) handlers both call
// prepareSubmission and then diverge at step 10+ — v1 polls WAL,
// v2 returns an SCT.
type preparedSubmission struct {
	raw               []byte
	entry             *envelope.Entry
	canonicalHash     [32]byte
	logTime           time.Time
	authenticated     bool
	exchangeDID       string
	extractedSplitID  *[32]byte
	extractedSchemaID string
}

// submissionError carries the HTTP status + message a fast-path
// validation failure should surface to the caller. The handler
// (v1 or v2) is responsible for writing the response — keeping
// the helper free of *http.ResponseWriter so it can be unit-tested
// without httptest plumbing.
type submissionError struct {
	Status  int
	Message string
}

// prepareSubmission runs admission steps 1-9: read body, validate
// preamble, deserialize, NFC, destination binding, freshness,
// signature, schema dispatch, size, evidence cap, mode dispatch,
// canonical hash, early-dup check, log_time. Returns either a
// fully-populated preparedSubmission ready for wal.Submit, or
// a submissionError to be written to the client.
//
// Identical for v1 and v2 — the SCT/MMD architecture only changes
// what happens AFTER wal.Submit (steps 10+).
func prepareSubmission(
	ctx context.Context,
	deps *SubmissionDeps,
	r *http.Request,
	freshness time.Duration,
) (*preparedSubmission, *submissionError) {
	// ── Step 1: Read raw bytes + validate preamble ─────────────────
	sigOverhead := int64(512)
	raw, err := io.ReadAll(io.LimitReader(r.Body, deps.MaxEntrySize+sigOverhead))
	if err != nil {
		return nil, &submissionError{http.StatusBadRequest, "failed to read request body"}
	}
	if len(raw) < 6 {
		return nil, &submissionError{http.StatusUnprocessableEntity, "entry too short for preamble"}
	}
	protocolVersion := binary.BigEndian.Uint16(raw[0:2])
	if protocolVersion != envelope.CurrentProtocolVersion() {
		return nil, &submissionError{
			http.StatusUnprocessableEntity,
			fmt.Sprintf("unsupported protocol version %d (expected %d)",
				protocolVersion, envelope.CurrentProtocolVersion()),
		}
	}

	// ── Step 2: Deserialize wire bytes, validate algo ID ───────────
	entry, err := envelope.Deserialize(raw)
	if err != nil {
		return nil, &submissionError{http.StatusUnprocessableEntity,
			fmt.Sprintf("deserialize: %s", err)}
	}
	algoID := entry.Signatures[0].AlgoID
	sigBytes := entry.Signatures[0].Bytes
	if err := envelope.ValidateAlgorithmID(algoID); err != nil {
		return nil, &submissionError{http.StatusUnauthorized, err.Error()}
	}

	// ── Step 3a: Re-apply NewEntry's write-time invariants ─────────
	if err := entry.Validate(); err != nil {
		return nil, &submissionError{http.StatusUnprocessableEntity,
			fmt.Sprintf("entry validation: %s", err)}
	}
	// ── Step 3a-NFC ────────────────────────────────────────────────
	if err := admission.CheckNFC(entry); err != nil {
		return nil, &submissionError{http.StatusUnprocessableEntity,
			fmt.Sprintf("NFC: %s", err)}
	}
	// ── Step 3b: Destination binding ───────────────────────────────
	if entry.Header.Destination != deps.LogDID {
		return nil, &submissionError{http.StatusForbidden,
			fmt.Sprintf("entry destination %q does not match log %q",
				entry.Header.Destination, deps.LogDID)}
	}
	// ── Step 3c: Late-replay freshness ─────────────────────────────
	if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
		return nil, &submissionError{http.StatusUnprocessableEntity,
			fmt.Sprintf("freshness: %s", err)}
	}

	// ── Step 4: Signature verification ─────────────────────────────
	if entry.Header.SignerDID == "" {
		return nil, &submissionError{http.StatusUnprocessableEntity, "empty signer DID"}
	}
	if err := admission.VerifyEntrySignature(ctx, entry, sigBytes, deps.Identity.DIDResolver); err != nil {
		switch {
		case errors.Is(err, admission.ErrSignerDIDResolution),
			errors.Is(err, admission.ErrSignatureInvalid):
			return nil, &submissionError{http.StatusUnauthorized, err.Error()}
		default:
			deps.Logger.Error("signature verification path failed", "error", err)
			return nil, &submissionError{http.StatusInternalServerError, "signature verification failed"}
		}
	}

	// ── Step 4-Schema: Commitment dispatch ─────────────────────────
	extractedSplitID, extractedSchemaID, dispatchErr := dispatchCommitmentSchema(entry)
	if dispatchErr != nil {
		return nil, &submissionError{http.StatusUnprocessableEntity,
			fmt.Sprintf("commitment schema: %s", dispatchErr)}
	}

	// ── Step 5: Entry size ─────────────────────────────────────────
	if int64(len(raw)) > deps.MaxEntrySize {
		return nil, &submissionError{http.StatusRequestEntityTooLarge,
			fmt.Sprintf("canonical bytes %d exceed max %d", len(raw), deps.MaxEntrySize)}
	}

	// ── Step 6: Evidence_Pointers cap ──────────────────────────────
	if !middleware.CheckEvidenceCap(entry) {
		return nil, &submissionError{http.StatusUnprocessableEntity,
			fmt.Sprintf("Evidence_Pointers %d exceeds cap %d (non-snapshot)",
				len(entry.Header.EvidencePointers), middleware.MaxEvidencePointers)}
	}

	// ── Step 7: Admission mode (Mode B stamp verify; auth probe) ───
	authenticated := middleware.IsAuthenticated(ctx)
	exchangeDID := middleware.ExchangeDID(ctx)
	if !authenticated {
		h := &entry.Header
		if h.AdmissionProof == nil {
			return nil, &submissionError{http.StatusForbidden,
				"unauthenticated submission requires compute stamp"}
		}
		apiProof := sdkadmission.ProofFromWire(h.AdmissionProof, deps.LogDID)
		canonicalHash := envelope.EntryIdentity(entry)
		var hashFunc sdkadmission.HashFunc
		switch deps.Admission.DiffController.HashFunction() {
		case "argon2id":
			hashFunc = sdkadmission.HashArgon2id
		default:
			hashFunc = sdkadmission.HashSHA256
		}
		if err := sdkadmission.VerifyStamp(
			apiProof,
			canonicalHash,
			deps.LogDID,
			deps.Admission.DiffController.CurrentDifficulty(),
			hashFunc,
			nil,
			sdkadmission.CurrentEpoch(uint64(deps.Admission.EpochWindowSeconds)),
			uint64(deps.Admission.EpochAcceptanceWindow),
		); err != nil {
			return nil, &submissionError{http.StatusForbidden,
				fmt.Sprintf("stamp verification failed: %s", err)}
		}
	}

	// ── Step 8: Canonical hash ─────────────────────────────────────
	canonicalHash := envelope.EntryIdentity(entry)

	// ── Step 8a: Early duplicate check ─────────────────────────────
	// Skipped when EntryStore is nil (unit-test path where there is
	// no Postgres pool). Real production wiring always provides one.
	if deps.Storage.EntryStore != nil {
		if existingSeq, found, fetchErr := deps.Storage.EntryStore.FetchByHash(ctx, canonicalHash); fetchErr == nil && found {
			return nil, &submissionError{http.StatusConflict,
				fmt.Sprintf("duplicate entry: existing sequence %d", existingSeq)}
		}
	}

	// ── Step 9: Log_Time assignment ────────────────────────────────
	logTime := time.Now().UTC()

	return &preparedSubmission{
		raw:               raw,
		entry:             entry,
		canonicalHash:     canonicalHash,
		logTime:           logTime,
		authenticated:     authenticated,
		exchangeDID:       exchangeDID,
		extractedSplitID:  extractedSplitID,
		extractedSchemaID: extractedSchemaID,
	}, nil
}

// deductCreditModeA decrements one credit for the authenticated
// exchange DID inside its own Postgres transaction. Called by
// both v1 and v2 handlers BEFORE wal.Submit so a credit-exhausted
// caller never gets an SCT (v2) or a slot in the WAL (v1).
//
// Returns nil for unauthenticated callers (Mode B), or for the
// dev/test path where DB and CreditStore are nil. Returns
// store.ErrInsufficientCredits to surface as HTTP 402.
func deductCreditModeA(
	ctx context.Context,
	deps *SubmissionDeps,
	authenticated bool,
	exchangeDID string,
) error {
	if !authenticated {
		return nil
	}
	if deps.Storage.DB == nil || deps.Identity.CreditStore == nil {
		return nil
	}
	return store.WithReadCommittedTx(ctx, deps.Storage.DB, func(ctx context.Context, tx pgx.Tx) error {
		_, err := deps.Identity.CreditStore.Deduct(ctx, tx, exchangeDID)
		return err
	})
}

// NewSubmissionHandler creates the POST /v1/entries handler.
//
// Panics if AdmissionConfig.EpochWindowSeconds is non-positive — without
// a valid epoch window, the handler cannot validate Mode B admission proofs
// and the operator should refuse to start.
//
// Under the SCT/MMD architecture, this handler is now a polling
// FACADE over the asynchronous Sequencer. Steps 1-10 run inline
// (durable wal.Submit), then the handler polls WAL.MetaState
// until the background Sequencer transitions the entry to
// StateSequenced. The legacy {sequence_number, canonical_hash,
// log_time} JSON shape is preserved for backwards compatibility.
//
// Clients that want an immediate non-blocking response should
// migrate to POST /v2/entries which returns an SCT after wal.Submit
// without polling.
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
	v1Timeout := deps.V1Timeout
	if v1Timeout <= 0 {
		v1Timeout = DefaultV1Timeout
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// ── Steps 1-9 (validation + early-dup + log_time) ──────────────
		prep, errResp := prepareSubmission(ctx, deps, r, freshness)
		if errResp != nil {
			writeError(w, errResp.Status, errResp.Message)
			return
		}

		// ── Step 7-credit: Mode A credit deduction ─────────────────────
		// Moved out of the original step-12 entry_index transaction so
		// the SCT/MMD architecture has a single writer to entry_index
		// (the Sequencer). Failure modes preserved:
		//   - insufficient credits → 402
		//   - transient DB error  → 500
		if err := deductCreditModeA(ctx, deps, prep.authenticated, prep.exchangeDID); err != nil {
			if errors.Is(err, store.ErrInsufficientCredits) {
				writeError(w, http.StatusPaymentRequired, "insufficient write credits")
				return
			}
			deps.Logger.Error("credit deduction", "error", err)
			writeError(w, http.StatusInternalServerError, "credit deduction failed")
			return
		}

		// ── Step 10: WAL durability ────────────────────────────────────
		if err := deps.Storage.WAL.Submit(ctx, prep.canonicalHash, prep.raw); err != nil {
			if errors.Is(err, wal.ErrQueueFull) {
				w.Header().Set("Retry-After", "5")
				writeError(w, http.StatusServiceUnavailable,
					"backpressure: WAL queue full, retry shortly")
				return
			}
			deps.Logger.Error("wal submit", "error", err)
			writeError(w, http.StatusInternalServerError, "WAL persist failed")
			return
		}

		// ── Step 11 (facade): Poll WAL for the Sequencer to advance ────
		//
		// The background Sequencer drains StatePending entries in its
		// own pollInterval cadence (default 1s; tunable to ~10ms in
		// tests). The v1 facade pattern: tick every
		// V1FacadePollInterval (50ms) on WAL.MetaState; return on
		// StateSequenced; bail on r.Context().Done() (client
		// disconnect) OR after V1Timeout (sequencer wedged).
		seq, ok := pollForSequenced(ctx, deps, prep.canonicalHash, v1Timeout)
		if !ok {
			// 504 with a structured payload pointing at the
			// follow-up endpoint — clients can ask hash-side at
			// their leisure to confirm sequencing eventually
			// completed.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGatewayTimeout)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":           "sequencer_lag",
				"hash":            hex.EncodeToString(prep.canonicalHash[:]),
				"wal_state":       "pending",
				"follow_up":       "/v1/entries/hash/" + hex.EncodeToString(prep.canonicalHash[:]),
				"timeout_seconds": v1Timeout.Seconds(),
			})
			return
		}

		// ── Step 12 (facade): Format legacy v1 response ────────────────
		// log_time comes from the Sequencer's entry_index INSERT, which
		// uses entry.Header.EventTime. We could re-fetch it from the
		// row but for the facade response shape we just echo what we
		// admitted — same value the Sequencer is going to write.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sequence_number": seq,
			"canonical_hash":  hex.EncodeToString(prep.canonicalHash[:]),
			"log_time":        prep.logTime.Format(time.RFC3339Nano),
		})
	}
}

// pollForSequenced is the v1 facade's wait loop. Returns the
// Sequencer-assigned seq when WAL.MetaState reports
// StateSequenced/Shipped, or (0, false) on context cancellation or
// timeout expiry. Polls every V1FacadePollInterval; respects both
// r.Context().Done() (client disconnect) and a hard
// context.WithTimeout(ctx, v1Timeout) deadline.
func pollForSequenced(
	parent context.Context,
	deps *SubmissionDeps,
	hash [32]byte,
	v1Timeout time.Duration,
) (uint64, bool) {
	ctx, cancel := context.WithTimeout(parent, v1Timeout)
	defer cancel()
	ticker := time.NewTicker(V1FacadePollInterval)
	defer ticker.Stop()

	// Quick first probe — common case: the sequencer drained while
	// wal.Submit was still grouping its batch, so MetaState is
	// already StateSequenced when the v1 handler reaches here.
	if seq, ok := readSequencedSeq(parent, deps, hash); ok {
		return seq, true
	}
	for {
		select {
		case <-ctx.Done():
			return 0, false
		case <-ticker.C:
			if seq, ok := readSequencedSeq(parent, deps, hash); ok {
				return seq, true
			}
		}
	}
}

// readSequencedSeq returns the entry's Sequencer-assigned seq when
// WAL.MetaState reports StateSequenced (or any post-Sequenced
// state). Returns (0, false) for any other state, transport error,
// or wal.ErrNotFound (transient race between Submit and meta read).
func readSequencedSeq(ctx context.Context, deps *SubmissionDeps, hash [32]byte) (uint64, bool) {
	meta, err := deps.Storage.WAL.MetaState(ctx, hash)
	if err != nil {
		return 0, false
	}
	switch meta.State {
	case wal.StateSequenced, wal.StateShipped:
		return meta.Sequence, true
	default:
		return 0, false
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
