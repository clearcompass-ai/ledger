/*
FILE PATH: witnessclient/rotation_handler.go

Witness set rotation handling. Accepts rotation findings, runs
the SDK's cryptographic Verify, persists to the witness_sets
table, swaps the in-memory set, and emits a KindWitnessRotation
gossip event so tailing auditors learn about the change.

# KEY DESIGN DECISIONS

  - The handler consumes attesta v0.7.0's findings.WitnessRotation
    Finding directly. The pre-v0.7.0 ledger-local "structural-
    only" path is gone — every rotation runs the SDK's full
    cryptographic recipe (set-hash rebind → scheme enforcement
    → OLD K-of-N quorum → optional NEW dual-sign quorum) via
    (*WitnessRotationFinding).Verify(set).

  - The handler owns the *cosign.WitnessKeySet, not a flat
    []types.WitnessPublicKey. The WitnessKeySet encapsulates
    NetworkID + Quorum + BLSVerifier alongside the keys — the
    SAME topology the EquivocationMonitor uses, so the two
    surfaces stay aligned by construction.

  - Verify runs BEFORE persist, persist runs BEFORE emit. Order
    is load-bearing: an unverified rotation must never reach the
    DB, and an emitted event implies durable local persistence
    (peers can trust that downloading from this ledger's
    by-binding endpoint will find the same event).

# WHAT'S OUT OF SCOPE (NEXT-TODO)

Inbound consumption of peer ledgers' KindWitnessRotation events
(cross-ledger witness-set consistency auditing) is a separate
surface that mirrors the upcoming KindCrossLogInclusion
consumption: both require polling peers + decoding + verifying
under our trusted set. Deferred together so the inbound
mechanism is shipped as one coherent feature.
*/
package witnessclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// RotationHandler manages witness set rotations.
type RotationHandler struct {
	db             *pgxpool.Pool
	currentSet     *cosign.WitnessKeySet
	schemeTag      byte
	ledgerEndpoint string
	logger         *slog.Logger

	// emitter broadcasts each successful rotation as a gossip
	// event. nil = gossip-disabled deployment (the rotation still
	// applies locally; auditors will catch up via anti-entropy
	// when an emitter is wired). See rotation_emitter.go.
	emitter WitnessRotationEmitter
}

// NewRotationHandler creates a rotation handler with the current
// witness set + the ledger's externally-visible endpoint (carried
// in the rotation finding so auditors can crawl back to this
// ledger for follow-up state).
//
// currentSet MUST be non-nil — the handler is useless without
// the topology the SDK Verify needs (NetworkID, Quorum,
// BLSVerifier all live inside the WitnessKeySet).
func NewRotationHandler(
	db *pgxpool.Pool,
	currentSet *cosign.WitnessKeySet,
	schemeTag byte,
	ledgerEndpoint string,
	logger *slog.Logger,
) *RotationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &RotationHandler{
		db:             db,
		currentSet:     currentSet,
		schemeTag:      schemeTag,
		ledgerEndpoint: ledgerEndpoint,
		logger:         logger,
	}
}

// WithEmitter wires the gossip-emitter. nil is permitted
// (gossip-disabled). Returns the receiver so callers can chain.
// Mirrors the sequencer's WithGhostLeafEmitter pattern.
func (rh *RotationHandler) WithEmitter(e WitnessRotationEmitter) *RotationHandler {
	rh.emitter = e
	return rh
}

// ProcessRotation validates a rotation cryptographically, persists
// it to the witness_sets table, swaps the in-memory set, and emits
// a KindWitnessRotation gossip event. Returns the new witness set
// on success.
//
// Order of operations is load-bearing:
//
//  1. Build the SDK finding (runs Validate — bounds-checks every
//     wire-shaped field; rejects oversize NewSet, oversize keys,
//     oversize sigs, etc.).
//  2. Cryptographically verify against the CURRENT set (runs the
//     SDK's full 4-step recipe via witness.VerifyRotation).
//  3. Persist to DB.
//  4. Swap the in-memory WitnessKeySet to the NEW set, inheriting
//     NetworkID + Quorum + BLSVerifier from the current set.
//  5. Emit to gossip (best-effort; failure does NOT roll back the
//     rotation — the local audit trail is durable, and peers will
//     catch up via anti-entropy).
//
// Any failure in steps 1–4 leaves the handler in its previous
// state. The rotation has not been applied.
func (rh *RotationHandler) ProcessRotation(
	ctx context.Context,
	rotation types.WitnessRotation,
) ([]types.WitnessPublicKey, error) {
	if rh.currentSet == nil {
		return nil, fmt.Errorf("witness/rotation: handler has no current witness set")
	}

	// Step 1: build the SDK finding. NewWitnessRotationFinding
	// runs Validate internally — every structural + size-cap
	// check from findings/witness_rotation.go fires here.
	finding, err := findings.NewWitnessRotationFinding(rotation, rh.ledgerEndpoint)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: build finding: %w", err)
	}

	// Step 2: cryptographic Verify against the current set. The
	// SDK's witness.VerifyRotation runs the canonical 4-step
	// recipe: set-hash rebind, scheme enforcement, OLD K-of-N
	// quorum, optional NEW dual-sign quorum.
	if err := finding.Verify(rh.currentSet); err != nil {
		return nil, fmt.Errorf("witness/rotation: verify: %w", err)
	}

	// Step 3: persist the new set. The keys_json column is the
	// authoritative on-disk form; set_hash references the OLD
	// set (the rotation's authorization anchor).
	keysJSON, err := json.Marshal(rotation.NewSet)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: marshal new set: %w", err)
	}
	newScheme := rotation.SchemeTagOld
	if rotation.SchemeTagNew != 0 {
		newScheme = rotation.SchemeTagNew
	}
	if _, err = rh.db.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag)
		VALUES ($1, $2, $3)`,
		rotation.CurrentSetHash[:], keysJSON, int16(newScheme),
	); err != nil {
		return nil, fmt.Errorf("witness/rotation: persist: %w", err)
	}

	// Step 4: swap the in-memory set. Inherit NetworkID + Quorum
	// + BLSVerifier from the current set — same V1 contract the
	// SDK's witness.VerifyRotation uses for the dual-sign
	// transient construction (network policy is topology, not
	// payload).
	newSet, err := cosign.NewWitnessKeySet(
		rotation.NewSet,
		rh.currentSet.NetworkID(),
		rh.currentSet.Quorum(),
		rh.currentSet.BLSVerifier(),
	)
	if err != nil {
		// This should be unreachable: Verify already ran Validate
		// on every key, and the SDK's NewWitnessKeySet only
		// rejects structural shapes Validate already enforced.
		// Treat as a contract drift between the SDK's Verify and
		// NewWitnessKeySet — surface loudly.
		return nil, fmt.Errorf("witness/rotation: construct new set "+
			"(SDK contract drift between Verify and NewWitnessKeySet): %w", err)
	}
	rh.currentSet = newSet
	rh.schemeTag = newScheme

	rh.logger.InfoContext(ctx, "witness rotation applied",
		"new_keys", len(rotation.NewSet),
		"scheme_tag", newScheme,
		"dual_sign", rotation.IsDualSigned(),
	)

	// Step 5: emit. Best-effort, nil-safe. Peers will catch up
	// via anti-entropy if the broadcast fails (durable locally).
	if rh.emitter != nil {
		rh.emitter.Emit(ctx, finding)
	}

	return rotation.NewSet, nil
}

// CurrentSet returns the active witness key set's public keys.
// The returned slice is a copy of the keys held inside the
// *cosign.WitnessKeySet; the WitnessKeySet itself is immutable so
// concurrent callers see consistent state.
func (rh *RotationHandler) CurrentSet() []types.WitnessPublicKey {
	if rh.currentSet == nil {
		return nil
	}
	keys := rh.currentSet.Keys()
	out := make([]types.WitnessPublicKey, len(keys))
	copy(out, keys)
	return out
}

// CurrentWitnessKeySet exposes the active *cosign.WitnessKeySet
// for callers that need the full topology (NetworkID + Quorum +
// BLSVerifier in addition to keys). The returned pointer is the
// live keyset; callers MUST NOT mutate (the type is immutable by
// construction, but a future refactor that exposes a mutator
// would silently de-sync from the handler's invariants).
func (rh *RotationHandler) CurrentWitnessKeySet() *cosign.WitnessKeySet {
	return rh.currentSet
}

// SchemeTag returns the active signature scheme.
func (rh *RotationHandler) SchemeTag() byte {
	return rh.schemeTag
}

// LoadCurrentSet loads the latest witness set from Postgres. The
// caller uses this output to construct the boot-time
// *cosign.WitnessKeySet (via cosign.NewWitnessKeySet) and hand it
// to NewRotationHandler.
func LoadCurrentSet(ctx context.Context, db *pgxpool.Pool) ([]types.WitnessPublicKey, byte, error) {
	var keysJSON []byte
	var schemeTag int16
	err := db.QueryRow(ctx,
		"SELECT keys_json, scheme_tag FROM witness_sets ORDER BY version DESC LIMIT 1",
	).Scan(&keysJSON, &schemeTag)
	if err != nil {
		return nil, 0, fmt.Errorf("witness/rotation: load current set: %w", err)
	}

	var keys []types.WitnessPublicKey
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		return nil, 0, fmt.Errorf("witness/rotation: unmarshal keys: %w", err)
	}
	return keys, byte(schemeTag), nil
}
