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
from previously-unknown keys and either flag the head as forged
or silently fall under the K-of-N threshold.

KindWitnessRotation (shipped in attesta v0.6.0; cryptographic
Verify added in v0.7.0) closes this gap. Every rotation the
ledger processes becomes a signed gossip event that tailing
auditors update their key registry from.

# DESIGN

  - The contract is a single Emit(ctx, finding) — the consumer
    hands over a fully-constructed (and pre-validated) SDK
    findings.WitnessRotationFinding. The emitter owns the
    sign + append + broadcast pipeline.
  - Optional, not mandatory: a nil emitter is the gossip-disabled
    deployment mode (single-ledger development, integration
    tests). The handler's hot path MUST tolerate nil.
  - Fire-and-forget: emission errors do NOT cascade back into
    rotation processing. The rotation has already landed in the
    DB; the local audit trail is durable even if the broadcast
    fails. Pattern mirrors sequencer/ghost_leaf_emitter.go.
  - Non-blocking by contract: Emit MUST return quickly enough
    that the rotation hot path isn't latency-bound by network
    I/O. Implementations that need network do it via the gossip
    Sink, which is already async-safe.

# IMPLEMENTATIONS

  - NopWitnessRotationEmitter: gossip-disabled.
  - LoggingWitnessRotationEmitter: structured-log-only fallback.
    Useful for dev / integration tests where peers don't exist.
  - SDKGossipWitnessRotationEmitter (gossipnet/): production
    adapter that signs + appends + broadcasts via the SDK's
    cosign.WitnessSigner + sdkgossip.Store + sdkgossip.Sink
    pipeline. Mirrors SDKGossipGhostLeafEmitter.
*/
package witnessclient

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/clearcompass-ai/attesta/gossip/findings"
)

// WitnessRotationEmitter is the interface the RotationHandler
// calls to broadcast a successfully-processed rotation.
//
// finding is fully constructed (passed Validate) and verified
// (passed cryptographic Verify against the OLD WitnessKeySet)
// at the call site. Implementations sign + append + broadcast;
// none of them re-verify.
type WitnessRotationEmitter interface {
	Emit(ctx context.Context, finding *findings.WitnessRotationFinding)
}

// NopWitnessRotationEmitter discards every emit. Used when the
// deployment is single-ledger (no gossip peers) or in tests that
// don't care about the emit side effect.
type NopWitnessRotationEmitter struct{}

// Emit is a no-op.
func (NopWitnessRotationEmitter) Emit(_ context.Context, _ *findings.WitnessRotationFinding) {}

// LoggingWitnessRotationEmitter writes a structured slog line
// per rotation. NOT a substitute for KindWitnessRotation gossip —
// auditors cannot subscribe to a ledger's local logs. Provided
// for dev / integration deployments that don't run a gossip Sink.
//
// Tracks an atomic Emitted counter so callers can observe whether
// the rotation pipeline is firing without scraping logs.
type LoggingWitnessRotationEmitter struct {
	logger  *slog.Logger
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

// Emit logs the rotation event with all load-bearing fields.
// Synchronous — no goroutine spawn — because slog writes don't
// block on the network.
func (e *LoggingWitnessRotationEmitter) Emit(ctx context.Context, f *findings.WitnessRotationFinding) {
	if f == nil {
		return
	}
	e.emitted.Add(1)
	e.logger.InfoContext(ctx,
		"witnessclient: rotation event (gossip-disabled deployment; logging only)",
		"current_set_hash", f.Rotation.CurrentSetHash[:8],
		"new_set_size", len(f.Rotation.NewSet),
		"scheme_tag_old", f.Rotation.SchemeTagOld,
		"scheme_tag_new", f.Rotation.SchemeTagNew,
		"current_sigs", len(f.Rotation.CurrentSignatures),
		"new_sigs", len(f.Rotation.NewSignatures),
		"ledger_endpoint", f.LedgerEndpoint,
	)
}

// Emitted returns the count of Emit calls observed. Pairs with
// the SDK gossip adapter's Snapshot for symmetric SRE telemetry.
func (e *LoggingWitnessRotationEmitter) Emitted() uint64 {
	return e.emitted.Load()
}

// Compile-time pins.
var (
	_ WitnessRotationEmitter = NopWitnessRotationEmitter{}
	_ WitnessRotationEmitter = (*LoggingWitnessRotationEmitter)(nil)
)
