/*
FILE PATH: admission/bls_quorum_verifier.go

BLS quorum verification at admission time per Wave 1 v3 §S1.

Scope (Wave 1 v3, intentionally narrow): this verifier fires ONLY for
entries whose payload embeds a cosigned tree head — anchor entries
authored by peer ledgers, witness-attestation commentary, cross-log
proof entries. Plain submissions that do not carry an embedded
checkpoint skip this stage entirely; the commitment-entry surface
(pre-grant-commitment-v1, escrow-split-commitment-v1) does not embed
tree heads and therefore never triggers S1.

The verifier routes through cosign.Verify against the SDK's universal
cosignature surface. cosign.Verify enforces, in one path:

  - Per-signature scheme dispatch (rejects SchemeTag==0 with
    cosign.ErrSchemeUnspecified; rejects unknown schemes with
    cosign.ErrSchemeUnsupported).
  - Per-signature pubkey membership in the *cosign.WitnessKeySet
    (rejects unknown PubKeyID with per-signature
    cosign.ErrUnknownPublicKey).
  - K-of-N quorum read from set.Quorum() (rejects below-threshold
    counts with top-level cosign.ErrQuorumNotReached).

All three are mandatory in cosign.Verify; they are not gated mutation
switches. The ledger's job is to invoke the primitive and map its
quorum-class errors to the admission-layer's
ErrWitnessQuorumInsufficient.

# v0.1.1 API SHAPE

The verifier holds a *cosign.WitnessKeySet directly — keys,
NetworkID, K-of-N quorum, and BLS aggregate verifier are all
encapsulated topology constructed once at boot via
cosign.NewWitnessKeySet. The previous (keys, K, networkID,
blsVerifier) parameter group is collapsed into one argument; the
single-impl WitnessKeySet interface and StaticWitnessKeySet wrapper
that existed to bridge v0.1.0's separate-args shape are removed.

Detection vs. verification (separation of concerns):

  - EntryEmbedsTreeHead reports whether an entry's schema is one
    the ledger knows carries a cosigned tree head. Currently a
    closed-set predicate that returns false for every schema; future
    commits add specific schema_id matches as the ledger's
    cross-log proof and peer-anchor surfaces grow. As long as the
    predicate returns false, this verifier is dead code and Wave 1
    ships with the admission pipeline correctly skipping S1 — which
    is the intended behavior for the entry surface introduces.

  - ExtractEmbeddedTreeHead parses the embedded head from the
    payload. Schema-specific. Stubbed for the same reason as the
    detector.

  - VerifyEmbeddedTreeHead is the actual cryptographic check. Real
    and complete — it would fire correctly the moment the detector
    matches a real schema.

Active witness key set: loaded from ledger config at startup as a
*cosign.WitnessKeySet (config-backed construction lives in
cmd/ledger/main.go wiring, not here). Refresh-on-rotation is the
ledger wiring's responsibility — atomic.Pointer[cosign.WitnessKeySet]
is the canonical pattern when rotation lands; v0.1.1 is single-set.
*/
package admission

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrWitnessQuorumInsufficient is returned when an entry carrying
// an embedded cosigned tree head fails to meet the active witness
// set's quorum threshold. The HTTP layer maps this to 401.
//
// Wraps the SDK's cosign.ErrQuorumNotReached and
// cosign.ErrEmptySignatures via the %w verb so callers can
// errors.Is on either the ledger-side sentinel or the underlying
// SDK cause.
var ErrWitnessQuorumInsufficient = errors.New(
	"admission: witness quorum insufficient")

// ErrWitnessKeySetUnavailable is returned when the verifier was
// constructed without a *cosign.WitnessKeySet. The HTTP layer
// maps this to 503 — the entry is structurally valid but the
// ledger cannot presently verify it.
var ErrWitnessKeySetUnavailable = errors.New(
	"admission: witness key set unavailable")

// ─────────────────────────────────────────────────────────────────────
// Verifier
// ─────────────────────────────────────────────────────────────────────

// BLSQuorumVerifier verifies cosigned tree heads embedded in
// admission-time entry payloads. Constructed once at ledger
// startup with a *cosign.WitnessKeySet built from
// LEDGER_WITNESS_QUORUM_K + the genesis witness DIDs, and shared
// across every admission request; safe for concurrent use because
// *cosign.WitnessKeySet is immutable after construction.
type BLSQuorumVerifier struct {
	set *cosign.WitnessKeySet
}

// NewBLSQuorumVerifier constructs a verifier with the supplied
// *cosign.WitnessKeySet. The keyset encapsulates the witness
// public keys, NetworkID, K-of-N quorum threshold, and BLS
// aggregate verifier — all of which were separate constructor
// arguments under v0.1.0 and are now topology held by the set
// itself.
//
// set MUST be non-nil. Construction time is the right place to
// fail on a missing set; VerifyEntry / VerifyEmbeddedTreeHead
// surface a missing set as ErrWitnessKeySetUnavailable so the
// HTTP layer can map to 503 instead of crashing the admission
// goroutine.
func NewBLSQuorumVerifier(set *cosign.WitnessKeySet) *BLSQuorumVerifier {
	return &BLSQuorumVerifier{set: set}
}

// VerifyEmbeddedTreeHead is the cryptographic check: invoke
// cosign.Verify against a PurposeTreeHead payload. Maps
// cosign.Verify's quorum-class errors (ErrQuorumNotReached,
// ErrEmptySignatures) to ErrWitnessQuorumInsufficient so the
// admission layer can route a single status code without
// branching on the SDK error vocabulary.
//
// All structural checks (scheme dispatch, pubkey membership,
// signature length) are enforced inside cosign.Verify; this
// wrapper does not duplicate them.
func (v *BLSQuorumVerifier) VerifyEmbeddedTreeHead(
	head types.CosignedTreeHead,
) error {
	if v == nil {
		return errors.New("admission: nil BLSQuorumVerifier")
	}
	if v.set == nil {
		return fmt.Errorf("%w: nil *cosign.WitnessKeySet",
			ErrWitnessKeySetUnavailable)
	}

	payload := cosign.NewTreeHeadPayload(head.TreeHead)
	_, verifyErr := cosign.Verify(
		payload, v.set, cosign.HashAlgoSHA256, head.Signatures,
	)
	if verifyErr == nil {
		return nil
	}

	// Map quorum-class SDK errors to a single admission-layer
	// sentinel. The HTTP layer renders this as 401; ledgers
	// inspecting the wrapped chain via errors.Unwrap can still
	// see the specific SDK cause for diagnostics.
	switch {
	case errors.Is(verifyErr, cosign.ErrQuorumNotReached),
		errors.Is(verifyErr, cosign.ErrEmptySignatures):
		// Multi-%w preserves both sentinels in the unwrap chain so
		// callers can errors.Is on either ErrWitnessQuorumInsufficient
		// (the ledger-side dispatch sentinel for HTTP 401) OR the
		// underlying cosign cause for diagnostics.
		return fmt.Errorf("%w: %w", ErrWitnessQuorumInsufficient, verifyErr)
	default:
		// A non-quorum SDK failure (config bug, malformed head,
		// signature math failure) surfaces unchanged. The HTTP
		// layer treats these as 401 the same way — a failed
		// quorum-class assertion is functionally equivalent to a
		// failed cryptographic check at the trust boundary —
		// but log lines preserve the distinction.
		return fmt.Errorf("admission: witness verify: %w", verifyErr)
	}
}

// VerifyEntry is the convenience wrapper the admission handler
// calls per request. It checks whether the entry embeds a tree
// head; if not, it returns nil unchanged (passthrough). If it
// does, ExtractEmbeddedTreeHead parses the head and
// VerifyEmbeddedTreeHead checks it.
//
// Decoupling the detector from the verifier means future commits
// can grow EntryEmbedsTreeHead's closed-set match without
// touching the cryptographic path, and conversely a new
// signature scheme on the verifier side does not have to know
// about every embedding schema.
func (v *BLSQuorumVerifier) VerifyEntry(entry *envelope.Entry) error {
	if entry == nil {
		return nil
	}
	if !EntryEmbedsTreeHead(entry) {
		return nil
	}
	head, ok, extractErr := ExtractEmbeddedTreeHead(entry)
	if extractErr != nil {
		return fmt.Errorf("admission: extract embedded tree head: %w", extractErr)
	}
	if !ok {
		// Detector matched but extractor did not — the schema is
		// known to embed a head but the payload was malformed in
		// a way the extractor surfaces as "not present" rather
		// than a parse error. Treat as quorum failure: the
		// cryptographic guarantee the embedding promises is not
		// available, so admission must reject.
		return fmt.Errorf("%w: schema declares embedded tree head but payload had none",
			ErrWitnessQuorumInsufficient)
	}
	return v.VerifyEmbeddedTreeHead(head)
}

// ─────────────────────────────────────────────────────────────────────
// Schema-specific detection + extraction (extension points)
// ─────────────────────────────────────────────────────────────────────

// EntryEmbedsTreeHead reports whether an entry's payload schema is
// one the ledger knows to carry a cosigned tree head. Currently
// a closed-set predicate that returns false for every schema; the
// commitment-entry surface (pre-grant-commitment-v1, escrow-split-
// commitment-v1) does NOT embed tree heads, so S1 verification is
// correctly a no-op for those entries.
//
// Future commits add matches for:
//
//   - Cross-log proof entries (when a domain network adds a schema
//     for them)
//   - Peer-authored anchor entries (when the ledger starts
//     accepting external anchors)
//   - Witness-attestation commentary (ledger-owned schema)
//
// Each addition is a trivial schema_id match against the entry's
// SchemaRef-resolved manifest or a known-DID match on the signer
// for ledger-owned schemas. The closed-set discipline ensures
// the ledger never invokes S1 on payloads it does not own —
// the Domain/Protocol Separation Principle remains intact.
func EntryEmbedsTreeHead(entry *envelope.Entry) bool {
	if entry == nil {
		return false
	}
	// Closed-set passthrough. No schemas yet.
	return false
}

// ExtractEmbeddedTreeHead parses a cosigned tree head from the
// entry's DomainPayload. Returns (zero, false, nil) when the
// schema is unrecognized — the typical case for Wave 1 because
// EntryEmbedsTreeHead also returns false for every schema. Wired
// alongside detector additions in future commits.
//
// Errors are reserved for genuine parse failures on payloads whose
// schema IS recognized as carrying a tree head — schema mismatch
// or wire-format corruption. Unrecognized schemas are not errors;
// they are passthroughs at the detector layer.
func ExtractEmbeddedTreeHead(entry *envelope.Entry) (types.CosignedTreeHead, bool, error) {
	if entry == nil {
		return types.CosignedTreeHead{}, false, nil
	}
	// Closed-set passthrough — extractor is symmetric with
	// EntryEmbedsTreeHead. No schemas yet.
	return types.CosignedTreeHead{}, false, nil
}
