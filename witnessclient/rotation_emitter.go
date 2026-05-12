/*
FILE PATH: witnessclient/rotation_emitter.go

WitnessRotationEmitter — the structural seam for broadcasting
witness-set rotations to the gossip network.

# WHY THIS EXISTS

The ledger's security model depends on tailing auditors verifying
K-of-N witness signatures on every CosignedTreeHead. When the
Originator rotates its keys, the network learns via the SDK's
KindOriginatorRotation gossip event. When the WITNESS SET rotates
(witnesses added, removed, key-rotated, scheme transitioned),
auditors who don't learn about the new set will see signatures
from previously-unknown keys and either flag the head as forged or
silently fall under the K-of-N threshold.

A KindWitnessRotation gossip event closes this gap: every rotation
that lands in the ledger's witness_sets table also emits a signed
gossip event carrying the new set's identity, so tailing auditors
update their key registry through the same channel they already
trust for tree-head + originator events.

# SDK v0.6.0 ALIGNMENT

The SDK is shipping KindWitnessRotation in v0.6.0 (in parallel with
this ledger work). Until that lands, the ledger uses the local
event struct + emitter interface defined here. The swap-over when
v0.6.0 ships is mechanical:

  - Replace WitnessRotationEvent with the SDK's findings.Witness
    RotationFinding (1:1 field copy).
  - Replace the LoggingWitnessRotationEmitter's local fmt with an
    SDK adapter that signs + appends + broadcasts via gossip.Sink
    (mirroring gossipnet/sdk_ghost_leaf_emitter.go).

The interface boundary stays stable — the consumer
(RotationHandler) is unaffected.

# DESIGN PRINCIPLES

  - Optional, not mandatory: a nil emitter is the gossip-disabled
    deployment mode (single-ledger development, integration tests).
    The handler's hot path MUST tolerate nil.
  - Fire-and-forget: emission errors do NOT cascade back into
    rotation processing. The rotation has already landed in the
    DB; the local audit trail is durable even if the broadcast
    fails. Pattern mirrors sequencer/ghost_leaf_emitter.go.
  - Non-blocking by contract: the Emit method MUST return quickly
    enough that the rotation hot path isn't latency-bound by
    network I/O. Implementations that need to do I/O hand off to
    a goroutine.
*/
package witnessclient

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// WitnessRotationEvent is the structural seam between the rotation
// handler and the gossip emitter. Fields mirror what the SDK
// v0.6.0 findings.WitnessRotationFinding is expected to carry.
//
// When the SDK lands, the swap is: rename to findings.Witness
// RotationFinding, import the SDK type, delete this struct. The
// emit call site stays unchanged.
type WitnessRotationEvent struct {
	// PreviousSetHash identifies the witness set the rotation
	// supersedes. From WitnessRotation.CurrentSetHash on the
	// inbound rotation message. Auditors use this to chain
	// rotations into a Merkle-style history.
	PreviousSetHash [32]byte

	// NewSetHash identifies the new active witness set. Tailing
	// auditors should update their key registry to this fingerprint
	// after verifying the rotation's K-of-N signatures.
	NewSetHash [32]byte

	// OldSchemeTag is the scheme of the PREVIOUS witness set.
	// Non-zero only during dual-sign scheme transitions.
	OldSchemeTag byte

	// NewSchemeTag is the scheme of the new witness set.
	NewSchemeTag byte

	// NewKeysCount is the cardinality of the new set. Auditors use
	// this to recompute K = ceil(2*N/3 + 1) under the network's
	// quorum policy.
	NewKeysCount int

	// DualSigned is true when this rotation carries signatures from
	// both the old AND new scheme — the safe path for a scheme
	// transition where old and new schemes coexist briefly.
	DualSigned bool

	// AppliedAtUnixNano is the wall-clock instant the rotation was
	// persisted by the originator. Auditors use this to detect
	// out-of-order rotations.
	AppliedAtUnixNano int64
}

// WitnessRotationEmitter is the interface the RotationHandler
// calls to broadcast a rotation. Implementations:
//
//   - NopWitnessRotationEmitter: gossip-disabled.
//   - LoggingWitnessRotationEmitter: structured-log-only fallback.
//     Useful for dev / integration tests where peers don't exist.
//   - SDKWitnessRotationEmitter (TODO, SDK v0.6.0): sign + append +
//     broadcast via gossip.Sink. To be added when the SDK ships
//     KindWitnessRotation; mirror gossipnet/sdk_ghost_leaf_emitter.go.
//
// Emit MUST NOT block the rotation hot path on network I/O.
// Implementations that need network do the I/O in a goroutine.
type WitnessRotationEmitter interface {
	Emit(ctx context.Context, ev WitnessRotationEvent)
}

// NopWitnessRotationEmitter discards every emit. Used when the
// deployment is single-ledger (no gossip peers) or in tests that
// don't care about the emit side effect.
type NopWitnessRotationEmitter struct{}

// Emit is a no-op.
func (NopWitnessRotationEmitter) Emit(_ context.Context, _ WitnessRotationEvent) {}

// LoggingWitnessRotationEmitter writes a structured slog line per
// rotation. NOT a substitute for KindWitnessRotation gossip —
// auditors cannot subscribe to a ledger's local logs. Provided
// as the default until the SDK v0.6.0 adapter is wired.
//
// Tracks a snapshot of emit counts (Emitted) so callers can
// observe whether the rotation pipeline is firing without
// scraping logs.
type LoggingWitnessRotationEmitter struct {
	logger  *slog.Logger
	mu      sync.Mutex
	emitted atomic.Uint64
}

// NewLoggingWitnessRotationEmitter constructs the slog-backed
// emitter. logger MAY be nil — falls back to slog.Default.
func NewLoggingWitnessRotationEmitter(logger *slog.Logger) *LoggingWitnessRotationEmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoggingWitnessRotationEmitter{logger: logger}
}

// Emit logs the rotation event with all fields. Synchronous — no
// goroutine spawn — because slog writes don't block on the network.
func (e *LoggingWitnessRotationEmitter) Emit(_ context.Context, ev WitnessRotationEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.emitted.Add(1)
	e.logger.Info("witnessclient: rotation event (gossip-pending; SDK v0.6.0 will broadcast)",
		"previous_set_hash", ev.PreviousSetHash[:8],
		"new_set_hash", ev.NewSetHash[:8],
		"old_scheme", ev.OldSchemeTag,
		"new_scheme", ev.NewSchemeTag,
		"new_keys_count", ev.NewKeysCount,
		"dual_signed", ev.DualSigned,
		"applied_at_unix_nano", ev.AppliedAtUnixNano,
	)
}

// Emitted returns the count of Emit calls observed. Pairs with
// future SDK adapter's Snapshot() for symmetric SRE telemetry.
func (e *LoggingWitnessRotationEmitter) Emitted() uint64 {
	return e.emitted.Load()
}

// Compile-time pins.
var _ WitnessRotationEmitter = NopWitnessRotationEmitter{}
var _ WitnessRotationEmitter = (*LoggingWitnessRotationEmitter)(nil)
