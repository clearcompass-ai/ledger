/*
FILE PATH: api/submission_v2.go

POST /v2/entries — the SCT/MMD entry point. Returns a Signed
Certificate Timestamp immediately after WAL fsync, deferring
Tessera sequencing and entry_index INSERT to the background
Sequencer (sequencer/).

CONTRACT VS V1:

	v1 (legacy, facade): synchronous {sequence_number, canonical_hash,
	    log_time}. Caller blocks until the Sequencer advances the
	    entry to StateSequenced; on V1Timeout expiry caller gets
	    HTTP 504 with a follow-up pointer to GET /v1/entries/hash/{hash}.

	v2 (this handler): asynchronous SignedCertificateTimestamp.
	    Caller never blocks on Tessera or Postgres. The SCT is the
	    operator's binding promise to sequence within MMD
	    (OPERATOR_MMD, default 24h). Consumers verify the SCT
	    signature against the operator's public key (reachable via
	    cfg.OperatorDID, a did:key:z...).

FAST-PATH SHAPE (matches the user's locked design):

 1. Read & Parse                         (steps 1-2 in
    prepareSubmission)
 2. Validate Signature                   (step 4)
 3. Check Freshness                      (step 3c — late-replay defense)
 4. Calculate Hash & Check Duplicates    (steps 8 + 8a — immediate
    replay defense)
 5. Mode A credit deduction              (own tx, before WAL)
 6. Write to local NVMe WAL              (step 10)
 7. Sign and Return the SCT              (this file)

What's missing from the fast path (vs the old v1 inline pipeline):
Tessera AppendLeaf, Postgres entry_index INSERT, WAL.Sequence.
All three move to the Sequencer.

DEPENDENCIES:

	SubmissionV2Deps wraps SubmissionDeps for prepareSubmission +
	deductCreditModeA reuse, then adds:

	  OperatorSignerPriv — secp256k1 ECDSA key (the same one
	                        OPERATOR_SIGNER_KEY_FILE loads). Signs
	                        the SCT canonical payload.
*/
package api

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// SubmissionV2Deps is the dependency surface for POST /v2/entries.
// Embeds SubmissionDeps for shared fast-path validation (steps 1-9
// + Mode A credit deduction); adds the SCT signing key.
type SubmissionV2Deps struct {
	*SubmissionDeps
	OperatorSignerPriv *ecdsa.PrivateKey
}

// NewSubmissionV2Handler creates the POST /v2/entries handler.
//
// Panics if OperatorSignerPriv is nil — without it the handler
// can't sign SCTs and the operator should refuse to start.
//
// Same Mode A / Mode B dispatch as v1: presence of a Bearer token
// in the auth middleware short-circuits Mode B PoW verification.
// Both modes pay the credit deduction (Mode A) or PoW stamp
// (Mode B) BEFORE WAL.Submit so an SCT is never issued for a
// caller that wasn't entitled to one.
func NewSubmissionV2Handler(deps *SubmissionV2Deps) http.HandlerFunc {
	if deps == nil || deps.SubmissionDeps == nil {
		panic("api: SubmissionV2Deps requires non-nil SubmissionDeps")
	}
	if deps.OperatorSignerPriv == nil {
		panic("api: SubmissionV2Deps.OperatorSignerPriv must be non-nil — SCT signing")
	}
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionV2Deps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionV2Deps.LogDID must be non-empty")
	}
	if deps.OperatorDID == "" {
		panic("api: SubmissionV2Deps.OperatorDID must be non-empty")
	}

	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// ── Steps 1-9: validation + early-dup + log_time ───────────────
		// Identical to v1 — same defenses, same error mapping.
		prep, errResp := prepareSubmission(ctx, deps.SubmissionDeps, r, freshness)
		if errResp != nil {
			writeError(w, errResp.Status, errResp.Message)
			return
		}

		// ── Step 7-credit: Mode A credit deduction ─────────────────────
		// Pre-deduct so the SCT is only issued to entitled callers.
		// A WAL.Submit failure after this debits the user's balance
		// without admitting the entry — rare; acceptable for a
		// transient WAL error. Refund logic out of scope here.
		if err := deductCreditModeA(ctx, deps.SubmissionDeps, prep.authenticated, prep.exchangeDID); err != nil {
			if errors.Is(err, store.ErrInsufficientCredits) {
				writeError(w, http.StatusPaymentRequired, "insufficient write credits")
				return
			}
			deps.Logger.Error("v2: credit deduction", "error", err)
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
			deps.Logger.Error("v2: wal submit", "error", err)
			writeError(w, http.StatusInternalServerError, "WAL persist failed")
			return
		}

		// ── Step 11: Sign + return SCT ─────────────────────────────────
		// log_time was assigned by prepareSubmission (step 9); the
		// SCT carries it as the operator-asserted admission time.
		// Sequencer-side log_time (entry_index.log_time) is a
		// separate value; both are operator-asserted, the v2 SCT
		// preserves the earlier admission-time value.
		sct, err := SignSCT(deps.OperatorSignerPriv, deps.OperatorDID, deps.LogDID, prep.canonicalHash, prep.logTime)
		if err != nil {
			deps.Logger.Error("v2: SignSCT", "error", err)
			writeError(w, http.StatusInternalServerError, "SCT signing failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(sct)
	}
}

