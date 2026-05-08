/*
FILE PATH: lifecycle/shard_manager.go

DESCRIPTION:

	Shard management — spawns a new shard (new log DID) with a genesis
	commentary entry that carries forward the prior shard's final state.

SDK ALIGNMENT:
  - envelope.NewEntry(header, payload, signatures)  — fully signed
  - envelope.NewUnsignedEntry(header, payload)      — sign-then-attach
    The genesis commentary is constructed here and signed downstream
    (the ledger that calls StartNewShard owns the institutional key
    and signs the GenesisEntry before announcing the new shard's
    DID), so this file uses NewUnsignedEntry.
  - EventTime set to frozen-at timestamp to anchor the shard rotation
    in wall-clock time (freshness policy uses this).

INVARIANTS:
  - NewShardDID MUST differ from PriorLogDID — rotating to the same DID
    would collapse the shard boundary.
  - PriorFrozenRoot is recorded in the genesis payload so consumers can
    cryptographically bind the new shard to the old one.
  - Genesis entry is pure commentary (no Target_Root, no Authority_Path) —
    zero SMT impact. State carries forward via replay, not by reference.
*/
package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// NewShardConfig configures a shard rotation.
type NewShardConfig struct {
	LedgerDID       string
	PriorLogDID     string
	NewShardDID     string
	PriorFrozenSeq  uint64
	PriorFrozenRoot [32]byte
	FrozenAt        time.Time
	Reason          string // "capacity", "governance", "recovery", etc.
}

// ShardRotationResult is the output of StartNewShard.
//
// GenesisCanonical is the result of envelope.Serialize on the
// unsigned entry; under envelope.Serialize requires at least
// one signature (Entry.Signatures invariant: len >= 1). Callers MUST
// attach a signature to GenesisEntry.Signatures before invoking
// envelope.Serialize themselves; the field on this struct is left
// for compatibility but will be empty when the genesis is unsigned.
//
// A future iteration can split this into two stages:
//   - StartNewShard returns the unsigned envelope.Entry
//   - Caller signs and re-serializes
//
// For now, GenesisCanonical is best-effort: it serializes only when
// the entry is in a state that envelope.Serialize accepts.
type ShardRotationResult struct {
	NewShardDID       string
	GenesisEntry      *envelope.Entry
	GenesisCanonical  []byte
	RotationTimestamp time.Time
}

// StartNewShard produces the genesis commentary entry for a new shard.
//
// The genesis entry:
//   - Is signed by the ledger (SignerDID = LedgerDID) DOWNSTREAM —
//     this function returns an unsigned entry; the caller attaches the
//     signature.
//   - Is bound to the NEW shard (Destination = NewShardDID).
//   - Carries the prior shard's final root + sequence in its payload.
//   - Is pure commentary — zero SMT impact on either shard.
//   - EventTime anchors the rotation to wall-clock time for freshness.
//
// Caller is responsible for signing GenesisEntry, persisting it to the
// NEW shard's storage, and announcing the new DID via out-of-band
// discovery.
func StartNewShard(cfg NewShardConfig) (*ShardRotationResult, error) {
	if err := validateShardConfig(cfg); err != nil {
		return nil, err
	}

	frozenAt := cfg.FrozenAt
	if frozenAt.IsZero() {
		frozenAt = time.Now().UTC()
	}

	payloadMap := map[string]any{
		"rotation_type":     "shard_spawn",
		"prior_log_did":     cfg.PriorLogDID,
		"prior_frozen_seq":  cfg.PriorFrozenSeq,
		"prior_frozen_root": fmt.Sprintf("%x", cfg.PriorFrozenRoot[:]),
		"frozen_at":         frozenAt.Format(time.RFC3339Nano),
		"reason":            cfg.Reason,
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/shard: marshal genesis payload: %w", err)
	}

	// NewUnsignedEntry per the envelope API split:
	//   - NewEntry(header, payload, signatures) for fully-signed callers
	//   - NewUnsignedEntry(header, payload)     for build-then-sign callers
	// StartNewShard's contract is to PRODUCE the genesis; signing
	// happens in the calling layer (ledger's institutional-key
	// signing path, distinct from this lifecycle helper).
	genesisEntry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   cfg.LedgerDID,
		Destination: cfg.NewShardDID, // required field — destination-binding
		EventTime:   frozenAt.Unix(), // Binds rotation to wall-clock time.
		// Target_Root=nil, Authority_Path=nil → commentary.
	}, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/shard: build genesis entry: %w", err)
	}

	// envelope.Serialize on an unsigned entry will fail under 	// because Entry.Signatures invariant requires len >= 1. Leave
	// GenesisCanonical empty here; the caller serializes after
	// attaching a signature.
	return &ShardRotationResult{
		NewShardDID:       cfg.NewShardDID,
		GenesisEntry:      genesisEntry,
		GenesisCanonical:  nil,
		RotationTimestamp: frozenAt,
	}, nil
}

// validateShardConfig checks the rotation invariants before entry construction.
// Fail-loud: all error paths return sentinel-wrapped errors for dispatch.
func validateShardConfig(cfg NewShardConfig) error {
	if cfg.LedgerDID == "" {
		return errors.New("lifecycle/shard: LedgerDID required")
	}
	if cfg.PriorLogDID == "" {
		return errors.New("lifecycle/shard: PriorLogDID required")
	}
	if cfg.NewShardDID == "" {
		return errors.New("lifecycle/shard: NewShardDID required")
	}
	if cfg.NewShardDID == cfg.PriorLogDID {
		return fmt.Errorf("lifecycle/shard: NewShardDID %q must differ from PriorLogDID",
			cfg.NewShardDID)
	}
	return nil
}
