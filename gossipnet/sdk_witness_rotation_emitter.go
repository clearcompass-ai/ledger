/*
FILE PATH: gossipnet/sdk_witness_rotation_emitter.go

SDKGossipWitnessRotationEmitter — the production adapter that
satisfies witnessclient.WitnessRotationEmitter by signing the
pre-validated, pre-verified *findings.WitnessRotationFinding and
broadcasting it via the SDK's gossip pipeline. Pairs with the
v0.7.0 attesta SDK release that ships findings.WitnessRotation
Finding.Verify (closing v0.6.0 Gap 1 — Fail-Closed Cryptographic
APIs on the rotation Kind).

# WHEN THIS RUNS

cmd/ledger/boot/wire/wire.go installs this adapter on the
RotationHandler when ALL gossip prerequisites are wired
(GossipStore + Sink + Signer + non-zero NetworkID + non-empty
Originator). The gossip-disabled deployment mode falls back to
witnessclient.LoggingWitnessRotationEmitter — same Emit contract
from the handler's perspective, no broadcast, no panic.

# THE FIVE-STEP EMIT PATH

For each *findings.WitnessRotationFinding the handler hands over:

 1. (Validate — already done) The handler runs the SDK's
    Validate via findings.NewWitnessRotationFinding before
    calling Emit. We don't re-run it.
 2. (Verify — already done) The handler runs
    (*WitnessRotationFinding).Verify against the OLD WitnessKey
    Set before calling Emit. We don't re-run it.
 3. Read the originator's chain head via GossipStore.Head to get
    (prev EventID, last lamport).
 4. Sign via gossip.Sign under cosign.PurposeGossipEventV1.
 5. Append to local GossipStore — populates the
    /v1/gossip/by-binding/{current_set_hash} index so auditors
    querying for "what rotation succeeded the set I know" find
    the event in O(1).
 6. Broadcast via Sink for peer-ledger replication.

Every step's failure is LOGGED and COUNTED but never propagated
back to the handler. Emission is best-effort broadcast
amplification; the witness_sets DB row is the authoritative
record regardless of gossip outcome.

# IDEMPOTENCY

GossipStore.Append is content-addressed by EventID (SHA-256 of
canonical bytes). Re-emitting the same WitnessRotationFinding
produces the same EventID and Append returns nil (or a
"duplicate"-tagged error we treat as success).

# WHY MIRROR THE GHOST-LEAF EMITTER

Two emitters with identical lifecycle + counter shape lets SRE
build one dashboard schema that covers both. The differences are
the event-construction step (Finding type differs) and the
content-binding logged on emit (current_set_hash vs.
canonical_hash). Everything else — Head → Sign → Append →
Broadcast → counter increment — is shared shape.
*/
package gossipnet

import (
	"context"
	"log/slog"
	"sync/atomic"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"

	"github.com/clearcompass-ai/ledger/witnessclient"
)

// SDKGossipWitnessRotationEmitterConfig wires the production
// adapter against the same gossip plumbing the
// EquivocationScanner + SDKGossipGhostLeafEmitter use. All five
// non-Logger fields are REQUIRED — the adapter's constructor
// returns an error rather than silently degrading.
type SDKGossipWitnessRotationEmitterConfig struct {
	// GossipStore is the local gossip store. Head supplies (prev,
	// lamport); Append durably records the signed event and
	// populates the by-binding index keyed on current_set_hash.
	GossipStore sdkgossip.Store

	// Sink broadcasts the signed event to peers. Per-peer
	// failures aggregate inside the Sink implementation;
	// emission is best-effort.
	Sink sdkgossip.Sink

	// Signer is the witness-style signer used by gossip.Sign.
	// Bound to the ledger's originator DID at construction.
	Signer sdkcosign.WitnessSigner

	// NetworkID binds the event to the network's bootstrap
	// document hash. Must be non-zero.
	NetworkID sdkcosign.NetworkID

	// Originator is the ledger's own DID, identical to the value
	// the EquivocationScanner + GhostLeafEmitter use.
	Originator string

	// Logger receives best-effort diagnostic lines. nil falls
	// back to slog.Default.
	Logger *slog.Logger
}

// SDKGossipWitnessRotationEmitter is the production
// WitnessRotationEmitter.
//
// Compile-time pinned at the bottom of the file: this type
// satisfies witnessclient.WitnessRotationEmitter structurally.
// If the handler's interface drifts, the build breaks here, not
// at runtime.
type SDKGossipWitnessRotationEmitter struct {
	cfg SDKGossipWitnessRotationEmitterConfig
	log *slog.Logger

	// Observability counters surface in SRE dashboards. Each is
	// the count of how many emissions reached the corresponding
	// terminal state:
	//
	//   succeeded — full path (Head → Sign → Append → Broadcast).
	//   appendOnly — Append landed but Broadcast failed.
	//   signFailed — Head or Sign returned an error.
	succeeded  atomic.Uint64
	appendOnly atomic.Uint64
	signFailed atomic.Uint64
}

// NewSDKGossipWitnessRotationEmitter constructs the adapter.
// Returns an error when any required field is missing — mirrors
// SDKGossipGhostLeafEmitter's constructor discipline so wiring
// bugs surface at boot, not on the first rotation.
func NewSDKGossipWitnessRotationEmitter(
	cfg SDKGossipWitnessRotationEmitterConfig,
) (*SDKGossipWitnessRotationEmitter, error) {
	if cfg.GossipStore == nil {
		return nil, errSDKWitRotEmitter("GossipStore required")
	}
	if cfg.Sink == nil {
		return nil, errSDKWitRotEmitter("Sink required")
	}
	if cfg.Signer == nil {
		return nil, errSDKWitRotEmitter("Signer required")
	}
	if cfg.NetworkID == (sdkcosign.NetworkID{}) {
		return nil, errSDKWitRotEmitter("NetworkID required (non-zero)")
	}
	if cfg.Originator == "" {
		return nil, errSDKWitRotEmitter("Originator required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &SDKGossipWitnessRotationEmitter{cfg: cfg, log: logger}, nil
}

// Emit signs, appends, and broadcasts the finding. The handler
// has already run Validate (via NewWitnessRotationFinding) and
// the SDK's cryptographic Verify (against the OLD WitnessKeySet)
// before calling Emit; we do NOT re-run either.
//
// Counters increment per terminal state. The handler's hot path
// neither blocks nor propagates errors from this method.
func (e *SDKGossipWitnessRotationEmitter) Emit(
	ctx context.Context,
	finding *findings.WitnessRotationFinding,
) {
	if finding == nil {
		e.log.WarnContext(ctx, "witness-rotation emitter: nil finding; emission skipped")
		return
	}

	// Step 3 — read originator chain head. lamport advances
	// strictly monotonically per the protocol; gossip.Sign
	// rejects a non-strict increase, so we never emit two events
	// at the same lamport for the same originator.
	prev, lamport, err := e.cfg.GossipStore.Head(ctx, e.cfg.Originator)
	if err != nil {
		e.signFailed.Add(1)
		e.log.WarnContext(ctx,
			"witness-rotation emitter: read head failed; emission skipped",
			"error", err,
			"originator", e.cfg.Originator,
		)
		return
	}
	nextLamport := lamport + 1
	if lamport == 0 {
		nextLamport = 1
	}

	// Step 4 — sign under PurposeGossipEventV1. Mirrors the
	// GhostLeafEmitter + EquivocationScanner signing path
	// verbatim.
	signed, err := sdkgossip.Sign(ctx, finding,
		e.cfg.Signer, e.cfg.NetworkID, e.cfg.Originator,
		prev, nextLamport)
	if err != nil {
		e.signFailed.Add(1)
		e.log.WarnContext(ctx,
			"witness-rotation emitter: Sign failed; emission skipped",
			"error", err,
		)
		return
	}

	// Step 5 — Append to local GossipStore. Idempotent: a
	// re-Append of the same EventID returns nil; "duplicate"-
	// flavored errors are also treated as success (handler
	// retries are safe).
	if err := e.cfg.GossipStore.Append(ctx, signed); err != nil {
		if !isAcceptableGhostAppendError(err) {
			e.signFailed.Add(1)
			e.log.WarnContext(ctx,
				"witness-rotation emitter: Append failed; emission skipped",
				"error", err,
			)
			return
		}
	}

	// Step 6 — Broadcast. Best-effort: peer failures aggregate
	// inside the Sink. A failure here counts as appendOnly
	// (durable local record exists; peers will catch up via
	// anti-entropy).
	if err := e.cfg.Sink.Broadcast(ctx, signed); err != nil {
		e.appendOnly.Add(1)
		e.log.WarnContext(ctx,
			"witness-rotation emitter: Broadcast failed (durable locally; peers catch up via /since)",
			"error", err,
			"current_set_hash", finding.Rotation.CurrentSetHash[:8],
		)
		return
	}

	e.succeeded.Add(1)
	e.log.InfoContext(ctx,
		"witness rotation emitted (signed + appended + broadcast)",
		"current_set_hash", finding.Rotation.CurrentSetHash[:8],
		"new_set_size", len(finding.Rotation.NewSet),
		"scheme_tag_old", finding.Rotation.SchemeTagOld,
		"scheme_tag_new", finding.Rotation.SchemeTagNew,
		"lamport", nextLamport,
	)
}

// SDKWitnessRotationEmitterSnapshot is the SRE-visible counter
// snapshot. Three orthogonal counters (succeeded / appendOnly /
// signFailed) let dashboards compute the broadcast-success rate
// independently of the local-persistence-only rate.
type SDKWitnessRotationEmitterSnapshot struct {
	Succeeded  uint64
	AppendOnly uint64
	SignFailed uint64
}

// Snapshot returns the current emit counters.
func (e *SDKGossipWitnessRotationEmitter) Snapshot() SDKWitnessRotationEmitterSnapshot {
	return SDKWitnessRotationEmitterSnapshot{
		Succeeded:  e.succeeded.Load(),
		AppendOnly: e.appendOnly.Load(),
		SignFailed: e.signFailed.Load(),
	}
}

// errSDKWitRotEmitter wraps a constructor error with a stable
// "gossipnet/sdk_witness_rotation_emitter:" prefix. Keeps the
// call site terse and the log lines greppable.
func errSDKWitRotEmitter(msg string) error {
	return &sdkWitRotEmitterError{msg: msg}
}

type sdkWitRotEmitterError struct{ msg string }

func (e *sdkWitRotEmitterError) Error() string {
	return "gossipnet/sdk_witness_rotation_emitter: " + e.msg
}

// Compile-time pin — SDKGossipWitnessRotationEmitter satisfies
// the witnessclient interface. Same pattern as the logging
// emitter; drift surfaces as a build error.
var _ witnessclient.WitnessRotationEmitter = (*SDKGossipWitnessRotationEmitter)(nil)
