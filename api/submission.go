/*
FILE PATH: api/submission.go

POST /v1/entries — the unified asynchronous SCT/MMD entry point.
Fail-fast: first failure terminates with appropriate HTTP status.

CONTRACT:

	On success, returns 202 Accepted with a SignedCertificateTimestamp.
	The SCT is the operator's binding promise to sequence the entry
	into the log within Maximum Merge Delay (OPERATOR_MMD). It is
	signed by the operator's secp256k1 ECDSA identity key and is
	offline-verifiable against the operator's published public key.

	The handler never blocks on Tessera or Postgres. Sequence-number
	assignment, entry_index INSERT, and commitment_split_id extraction
	all happen asynchronously in the background Sequencer.

	Consumers waiting for sequencing confirmation poll
	GET /v1/entries-hash/{canonical_hash} — the same endpoint used by
	monitors, audit jobs, and the SDK's HTTP entry fetcher.

FAST-PATH SHAPE (admission steps run inline):

	1. Read & validate preamble                  (prepareSubmission step 1)
	2. Deserialize wire bytes                    (step 2)
	3. NFC normalization check                   (step 3a)
	4. Destination binding                       (step 3b)
	5. Late-replay freshness                     (step 3c)
	6. Signature verification                    (step 4)
	7. Entry size + Evidence_Pointers cap        (steps 5, 6)
	8. Mode A auth probe / Mode B PoW verify     (step 7)
	9. Canonical hash + early duplicate probe    (steps 8, 8a)
	10. Mode A credit deduction                  (its own pg tx; pre-WAL)
	11. WAL.Submit (durable)                     (step 10)
	12. Sign + return SCT                        (step 11)

	Mode A credit deduction stays synchronous in the fast path so a
	credit-exhausted caller receives 402 before the WAL is touched —
	an SCT is never issued without payment authorization.

INVARIANTS:

  - Past step 3a-NFC: all entries have NFC-normalized DID-shaped fields.
  - Past step 3b: all entries are bound to THIS log's LogDID.
  - Past step 4: all entries have verified signatures (SDK-D5).
  - Past step 11 (WAL.Submit): bytes are durably persisted; the
    Sequencer will assign a sequence number and write entry_index
    + commitment_split_id atomically in its own pg transaction.
  - Sequence numbers are gapless (Postgres sequence; assigned by
    sequencer/loop.go, not this handler).

COMMITMENT SCHEMA DISPATCH:

	The Sequencer is the sole owner of dispatchCommitmentSchema —
	commitment_split_id population happens in the same pg transaction
	as the entry_index INSERT. Admission does not parse domain
	payloads here, in keeping with the Domain/Protocol Separation
	Principle.
*/
package api

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/admission"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/apitypes"
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
	// logTimeMicros is the operator-assigned admission time
	// persisted in Meta for the P5 deterministic-idempotency
	// path (re-issuing the same SCT bytes on byte-identical
	// resubmission).
	Submit(ctx context.Context, hash [32]byte, wire []byte, logTimeMicros int64) error

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
//
// PT-7 — Pure CQRS: EntryStore is the api.EntryStore interface
// (defined in ports.go); the field used to be *store.EntryStore.
// The DB field is gone — credit deduction now uses the self-tx
// CreditDeducter interface and admission's only Postgres write
// (entry_index INSERT) lives entirely in the sequencer goroutine.
type StorageDeps struct {
	EntryStore EntryStore
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
//
// PT-7 — Pure CQRS: Credits is the api.CreditDeducter interface
// (defined in ports.go); the field used to be *store.CreditStore.
// The interface's tx-less Deduct(ctx, exchangeDID) signature lets
// the api package hold zero pgx imports.
type IdentityDeps struct {
	Credits     CreditDeducter
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

	// BLSQuorumVerifier validates K-of-N witness cosignatures on
	// any tree head EMBEDDED inside an admitted entry's payload
	// (anchor entries authored by peer operators, witness-attestation
	// commentary, cross-log proof entries). Wave 1 v3 §S1.
	//
	// Optional: nil disables the check entirely (existing v7.75
	// commitment-entry surfaces don't embed tree heads, so the
	// detector returns false unconditionally and the verifier is
	// dead code today). Wired by cmd/operator/main.go iff a
	// witness key set is loaded.
	BLSQuorumVerifier *admission.BLSQuorumVerifier
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Submission Handler
// ─────────────────────────────────────────────────────────────────────────────

// preparedSubmission is the result of running steps 1-9 of the
// admission fast path. The handler diverges at step 10+ to deduct
// credits, persist to the WAL, and sign the SCT.
type preparedSubmission struct {
	raw           []byte
	entry         *envelope.Entry
	canonicalHash [32]byte
	logTime       time.Time
	authenticated bool
	exchangeDID   string

	// idempotentReplay is true when the canonical hash already
	// has a Meta record in the WAL (byte-identical resubmission).
	// logTime is the persisted value — re-issuing the SCT with
	// it produces byte-identical SCT bytes. The handler skips
	// wal.Submit + credit deduction in this case (P5).
	idempotentReplay bool
}

// submissionError carries the HTTP status + message a fast-path
// validation failure should surface to the caller. The handler
// (v1 or v2) is responsible for writing the response — keeping
// the helper free of *http.ResponseWriter so it can be unit-tested
// without httptest plumbing.
type submissionError struct {
	Status  int
	Message string
	Class   apitypes.ErrorClass
}

// submissionFail constructs a typed *submissionError. PT-6: every
// admission-side error carries an apitypes.ErrorClass so the
// HTTP handler increments the right OTel counter dimension.
func submissionFail(class apitypes.ErrorClass, status int, format string, args ...any) *submissionError {
	return &submissionError{
		Status:  status,
		Message: fmt.Sprintf(format, args...),
		Class:   class,
	}
}

// prepareSubmission runs admission steps 1-9: read body, validate
// preamble, deserialize, NFC, destination binding, freshness,
// signature, size, evidence cap, mode dispatch, canonical hash,
// early-dup check, log_time. Returns either a fully-populated
// preparedSubmission ready for wal.Submit, or a submissionError
// to be written to the client.
//
// Body size handling (Tier-2 BUG #3 alignment): the request is
// expected to arrive through the SizeLimit middleware (server.go),
// which wraps r.Body with http.MaxBytesReader at MaxEntrySize+1024.
// As defense-in-depth — and so direct callers (handler tests that
// bypass the middleware chain) get the same behavior — we wrap a
// second MaxBytesReader at the slightly tighter handler-local cap
// MaxEntrySize+sigOverhead. Either trigger surfaces as
// *http.MaxBytesError on Read, which we map to 413 instead of the
// legacy 400 "failed to read request body" + silent truncation.
func prepareSubmission(
	ctx context.Context,
	deps *SubmissionDeps,
	w http.ResponseWriter,
	r *http.Request,
	freshness time.Duration,
) (*preparedSubmission, *submissionError) {
	// ── Step 1: Read raw bytes + validate preamble ─────────────────
	sigOverhead := int64(512)
	r.Body = http.MaxBytesReader(w, r.Body, deps.MaxEntrySize+sigOverhead)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, submissionFail(apitypes.ErrorClassBodyTooLarge,
				http.StatusRequestEntityTooLarge,
				"entry exceeds %d bytes", maxErr.Limit)
		}
		return nil, submissionFail(apitypes.ErrorClassMalformedBody,
			http.StatusBadRequest, "failed to read request body")
	}
	if len(raw) < 6 {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "entry too short for preamble")
	}
	protocolVersion := binary.BigEndian.Uint16(raw[0:2])
	if protocolVersion != envelope.CurrentProtocolVersion() {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity,
			"unsupported protocol version %d (expected %d)",
			protocolVersion, envelope.CurrentProtocolVersion())
	}

	// ── Step 2: Deserialize wire bytes, validate algo ID ───────────
	entry, err := envelope.Deserialize(raw)
	if err != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "deserialize: %s", err)
	}
	algoID := entry.Signatures[0].AlgoID
	sigBytes := entry.Signatures[0].Bytes
	if err := envelope.ValidateAlgorithmID(algoID); err != nil {
		return nil, submissionFail(apitypes.ErrorClassSignatureInvalid,
			http.StatusUnauthorized, "%s", err)
	}

	// ── Step 3a: Re-apply NewEntry's write-time invariants ─────────
	if err := entry.Validate(); err != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "entry validation: %s", err)
	}
	// ── Step 3a-NFC ────────────────────────────────────────────────
	if err := admission.CheckNFC(entry); err != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "NFC: %s", err)
	}
	// ── Step 3b: Destination binding ───────────────────────────────
	if entry.Header.Destination != deps.LogDID {
		return nil, submissionFail(apitypes.ErrorClassDestinationMismatch,
			http.StatusForbidden,
			"entry destination %q does not match log %q",
			entry.Header.Destination, deps.LogDID)
	}
	// ── Step 3c: Late-replay freshness ─────────────────────────────
	if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
		return nil, submissionFail(apitypes.ErrorClassFreshnessExpired,
			http.StatusUnprocessableEntity, "freshness: %s", err)
	}

	// ── Step 4: Signature verification ─────────────────────────────
	if entry.Header.SignerDID == "" {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "empty signer DID")
	}
	if err := admission.VerifyEntrySignature(ctx, entry, sigBytes, deps.Identity.DIDResolver); err != nil {
		switch {
		case errors.Is(err, admission.ErrSignerDIDResolution),
			errors.Is(err, admission.ErrSignatureInvalid):
			return nil, submissionFail(apitypes.ErrorClassSignatureInvalid,
				http.StatusUnauthorized, "%s", err)
		default:
			deps.Logger.Error("signature verification path failed", "error", err)
			return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "signature verification failed")
		}
	}

	// ── Step 4b: Embedded tree head K-of-N verification ───────────
	// For entries that carry a cosigned tree head in their payload
	// (peer-anchor entries, witness commentary, cross-log proofs),
	// the BLSQuorumVerifier routes through cosign.Verify against
	// the deployment's witness key set + K-of-N quorum.
	if deps.BLSQuorumVerifier != nil {
		if err := deps.BLSQuorumVerifier.VerifyEntry(entry); err != nil {
			switch {
			case errors.Is(err, admission.ErrWitnessQuorumInsufficient),
				errors.Is(err, admission.ErrWitnessKeySetUnavailable):
				return nil, submissionFail(apitypes.ErrorClassSignatureInvalid,
					http.StatusUnauthorized, "%s", err)
			default:
				deps.Logger.Error("embedded tree head verification failed", "error", err)
				return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
					http.StatusInternalServerError, "tree head verification failed")
			}
		}
	}

	// ── Step 5: Entry size ─────────────────────────────────────────
	if int64(len(raw)) > deps.MaxEntrySize {
		return nil, submissionFail(apitypes.ErrorClassBodyTooLarge,
			http.StatusRequestEntityTooLarge,
			"canonical bytes %d exceed max %d", len(raw), deps.MaxEntrySize)
	}

	// ── Step 6: Evidence_Pointers cap ──────────────────────────────
	if !middleware.CheckEvidenceCap(entry) {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity,
			"Evidence_Pointers %d exceeds cap %d (non-snapshot)",
			len(entry.Header.EvidencePointers), middleware.MaxEvidencePointers)
	}

	// ── Step 7: Admission mode (Mode B stamp verify; auth probe) ───
	authenticated := middleware.IsAuthenticated(ctx)
	exchangeDID := middleware.ExchangeDID(ctx)
	if !authenticated {
		h := &entry.Header
		if h.AdmissionProof == nil {
			return nil, submissionFail(apitypes.ErrorClassAdmissionProofInvalid,
				http.StatusForbidden,
				"unauthenticated submission requires compute stamp")
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
			return nil, submissionFail(apitypes.ErrorClassAdmissionProofInvalid,
				http.StatusForbidden, "stamp verification failed: %s", err)
		}
	}

	// ── Step 8: Canonical hash ─────────────────────────────────────
	canonicalHash := envelope.EntryIdentity(entry)

	// ── Step 8a: Deterministic-idempotency probe (P5) ──────────────
	// A byte-identical resubmission MUST return the SAME SCT bytes
	// (not 409 Conflict). We probe the WAL's Meta record for the
	// persisted log_time; if found, the caller short-circuits the
	// new logTime assignment + the wal.Submit (re-Submit is
	// byte-idempotent but skipping saves IOPS) and re-issues the
	// SCT with the original log_time → identical wire bytes.
	if deps.Storage.WAL != nil {
		if meta, err := deps.Storage.WAL.MetaState(ctx, canonicalHash); err == nil &&
			meta.State != wal.StateUnknown && meta.LogTimeMicros > 0 {
			return &preparedSubmission{
				raw:              raw,
				entry:            entry,
				canonicalHash:    canonicalHash,
				logTime:          time.UnixMicro(meta.LogTimeMicros).UTC(),
				idempotentReplay: true,
				authenticated:    authenticated,
				exchangeDID:      exchangeDID,
			}, nil
		}
	}

	// ── Step 9: Log_Time assignment ────────────────────────────────
	logTime := time.Now().UTC()

	return &preparedSubmission{
		raw:           raw,
		entry:         entry,
		canonicalHash: canonicalHash,
		logTime:       logTime,
		authenticated: authenticated,
		exchangeDID:   exchangeDID,
	}, nil
}

// deductCreditModeA decrements one credit for the authenticated
// exchange DID. Called by both v1 and batch handlers BEFORE
// wal.Submit so a credit-exhausted caller never gets an SCT or a
// slot in the WAL.
//
// Returns nil for unauthenticated callers (Mode B), or for the
// dev/test path where Credits is nil. Returns
// apitypes.ErrInsufficientCredits to surface as HTTP 402.
//
// PT-7: api/ holds no pgx import — the CreditDeducter interface
// (api/ports.go) hides the txn boundary inside the store impl.
func deductCreditModeA(
	ctx context.Context,
	deps *SubmissionDeps,
	authenticated bool,
	exchangeDID string,
) error {
	if !authenticated {
		return nil
	}
	if deps.Identity.Credits == nil {
		return nil
	}
	return deps.Identity.Credits.Deduct(ctx, exchangeDID)
}

// NewSubmissionHandler creates the POST /v1/entries handler.
//
// Panics if any of these are missing — without them the handler
// cannot honor its contract and the operator should refuse to start:
//   - AdmissionConfig.EpochWindowSeconds (Mode B stamp verification)
//   - LogDID                              (destination-binding)
//   - OperatorDID                         (SCT signer identity)
//   - OperatorSignerPriv                  (SCT signing key)
//
// Returns 202 + SignedCertificateTimestamp on success. The SCT is
// signed by OperatorSignerPriv against the operator-published
// public key reachable via OperatorDID.
//
// Mode A credit deduction stays synchronous in the fast path: the
// handler returns 402 before WAL.Submit if the caller is out of
// credits, so an SCT is never issued without payment authorization.
func NewSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	if deps == nil {
		panic("api: SubmissionDeps must be non-nil")
	}
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionDeps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionDeps.LogDID must be non-empty (destination-binding enforcement)")
	}
	if deps.OperatorDID == "" {
		panic("api: SubmissionDeps.OperatorDID must be non-empty — SCT signer identity")
	}
	if deps.OperatorSignerPriv == nil {
		panic("api: SubmissionDeps.OperatorSignerPriv must be non-nil — SCT signing")
	}

	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// ── Steps 1-9 (validation + early-dup + log_time) ──────────────
		prep, errResp := prepareSubmission(ctx, deps, w, r, freshness)
		if errResp != nil {
			writeTypedError(ctx, w, errResp.Class, errResp.Status, errResp.Message)
			return
		}

		// ── P5 idempotent-replay short-circuit ────────────────────────
		// Byte-identical resubmission: skip credit deduction (the
		// caller paid on the first submission) AND skip wal.Submit
		// (already durable). Re-issue the SAME SCT bytes by signing
		// with the persisted log_time.
		if prep.idempotentReplay {
			sct, err := SignSCT(deps.OperatorSignerPriv, deps.OperatorDID, deps.LogDID, prep.canonicalHash, prep.logTime)
			if err != nil {
				deps.Logger.Error("SignSCT (idempotent replay)", "error", err)
				writeTypedError(ctx, w, apitypes.ErrorClassSCTSigningFailed,
					http.StatusInternalServerError, "SCT signing failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(sct)
			return
		}

		// ── Step 10-credit: Mode A credit deduction ────────────────────
		// Pre-WAL so a credit-exhausted caller never gets an SCT.
		// Failure modes:
		//   - insufficient credits → 402
		//   - transient DB error   → 500
		if err := deductCreditModeA(ctx, deps, prep.authenticated, prep.exchangeDID); err != nil {
			if errors.Is(err, apitypes.ErrInsufficientCredits) {
				writeTypedError(ctx, w, apitypes.ErrorClassInsufficientCredits,
					http.StatusPaymentRequired, "insufficient write credits")
				return
			}
			deps.Logger.Error("credit deduction", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassCreditDeductFailed,
				http.StatusInternalServerError, "credit deduction failed")
			return
		}

		// ── Step 11: WAL durability ────────────────────────────────────
		if err := deps.Storage.WAL.Submit(ctx, prep.canonicalHash, prep.raw, prep.logTime.UnixMicro()); err != nil {
			if errors.Is(err, wal.ErrQueueFull) {
				w.Header().Set("Retry-After", "5")
				writeTypedError(ctx, w, apitypes.ErrorClassWALBackpressure,
					http.StatusServiceUnavailable,
					"backpressure: WAL queue full, retry shortly")
				return
			}
			deps.Logger.Error("wal submit", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassWALPersistFailed,
				http.StatusInternalServerError, "WAL persist failed")
			return
		}

		// ── Step 12: Sign + return SCT ─────────────────────────────────
		// log_time was assigned at step 9 (prepareSubmission) and is
		// signed-over via LogTimeMicros in the SCT canonical packing.
		sct, err := SignSCT(deps.OperatorSignerPriv, deps.OperatorDID, deps.LogDID, prep.canonicalHash, prep.logTime)
		if err != nil {
			deps.Logger.Error("SignSCT", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassSCTSigningFailed,
				http.StatusInternalServerError, "SCT signing failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(sct)
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
