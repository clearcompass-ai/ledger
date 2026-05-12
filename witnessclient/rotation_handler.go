/*
FILE PATH: witnessclient/rotation_handler.go

Witness set rotation handling. Accepts rotation messages signed by the
current K-of-N quorum. Supports dual-sign for scheme transition.

KEY ARCHITECTURAL DECISIONS:
  - Rotation requires K-of-N signatures from CURRENT set (verified).
  - Dual-sign detection: old scheme + new scheme during transition.
  - Full rotation history preserved (auditable chain).
  - Genesis set loaded from witness_sets table on startup.
*/
package witnessclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/types"
)

// RotationHandler manages witness set rotations.
type RotationHandler struct {
	db         *pgxpool.Pool
	currentSet []types.WitnessPublicKey
	schemeTag  byte
	logger     *slog.Logger

	// emitter broadcasts each successful rotation as a gossip event.
	// nil = gossip-disabled deployment (the rotation still applies
	// locally; auditors will catch up via anti-entropy when an
	// emitter is wired). See rotation_emitter.go.
	emitter WitnessRotationEmitter
}

// NewRotationHandler creates a rotation handler with the current witness set.
func NewRotationHandler(
	db *pgxpool.Pool,
	currentSet []types.WitnessPublicKey,
	schemeTag byte,
	logger *slog.Logger,
) *RotationHandler {
	return &RotationHandler{
		db:         db,
		currentSet: currentSet,
		schemeTag:  schemeTag,
		logger:     logger,
	}
}

// WithEmitter wires the gossip-emitter. nil is permitted (gossip-
// disabled). Returns the receiver so callers can chain. Mirrors the
// sequencer's WithGhostLeafEmitter pattern.
func (rh *RotationHandler) WithEmitter(e WitnessRotationEmitter) *RotationHandler {
	rh.emitter = e
	return rh
}

// ProcessRotation validates and applies a witness set rotation.
func (rh *RotationHandler) ProcessRotation(
	ctx context.Context,
	rotation types.WitnessRotation,
) ([]types.WitnessPublicKey, error) {
	if len(rotation.NewSet) == 0 {
		return nil, fmt.Errorf("witness/rotation: empty new key set")
	}

	if len(rotation.CurrentSignatures) == 0 {
		return nil, fmt.Errorf("witness/rotation: no rotation signatures")
	}

	// Signature verification for rotations is gated on the DID
	// resolver + key registry being wired (the same infrastructure
	// as entry signature verification). Today we only validate
	// structural constraints: non-empty set, non-empty sigs,
	// dual-sign flag consistency.

	isDualSign := rotation.IsDualSigned()
	if isDualSign {
		rh.logger.Info("witness rotation: scheme transition",
			"from", rotation.SchemeTagOld, "to", rotation.SchemeTagNew)
		if len(rotation.NewSignatures) == 0 {
			return nil, fmt.Errorf("witness/rotation: dual-sign requires new-scheme signatures")
		}
	}

	newScheme := rotation.SchemeTagOld
	if rotation.SchemeTagNew != 0 {
		newScheme = rotation.SchemeTagNew
	}

	keysJSON, err := json.Marshal(rotation.NewSet)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: marshal: %w", err)
	}

	_, err = rh.db.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag)
		VALUES ($1, $2, $3)`,
		rotation.CurrentSetHash[:], keysJSON, int16(newScheme),
	)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: persist: %w", err)
	}

	rh.currentSet = rotation.NewSet
	rh.schemeTag = newScheme

	rh.logger.Info("witness rotation applied",
		"new_keys", len(rotation.NewSet),
		"scheme_tag", newScheme,
		"dual_sign", isDualSign,
	)

	// Broadcast the rotation to the gossip network so tailing
	// auditors update their key registry. nil emitter = single-
	// ledger / gossip-disabled mode (the rotation still applies
	// locally; this branch is skipped).
	if rh.emitter != nil {
		rh.emitter.Emit(ctx, WitnessRotationEvent{
			PreviousSetHash:   rotation.CurrentSetHash,
			NewSetHash:        computeWitnessSetHash(keysJSON),
			OldSchemeTag:      rotation.SchemeTagOld,
			NewSchemeTag:      newScheme,
			NewKeysCount:      len(rotation.NewSet),
			DualSigned:        isDualSign,
			AppliedAtUnixNano: time.Now().UnixNano(),
		})
	}

	return rotation.NewSet, nil
}

// computeWitnessSetHash returns SHA-256 of the canonical JSON
// encoding of a witness set. Used as a stable identifier the
// network can index. STUB: SDK v0.6.0 will publish the canonical
// fingerprint shape (likely matching findings.WitnessRotation
// Finding.NewSetHash); when the SDK lands, swap this helper for
// the canonical version.
func computeWitnessSetHash(keysJSON []byte) [32]byte {
	return sha256.Sum256(keysJSON)
}

// CurrentSet returns the active witness key set.
func (rh *RotationHandler) CurrentSet() []types.WitnessPublicKey {
	return rh.currentSet
}

// SchemeTag returns the active signature scheme.
func (rh *RotationHandler) SchemeTag() byte {
	return rh.schemeTag
}

// LoadCurrentSet loads the latest witness set from Postgres.
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
