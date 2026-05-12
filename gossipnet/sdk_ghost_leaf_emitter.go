/*
FILE PATH: gossipnet/sdk_ghost_leaf_emitter.go

SDKGossipGhostLeafEmitter — the production adapter that satisfies
sequencer.GhostLeafEmitter by constructing a signed
findings.GhostLeafFinding and broadcasting it via the SDK's gossip
pipeline. Pairs with the v0.5.0 attesta SDK release that ships
KindGhostLeaf + WireGhostLeafBody + findings.GhostLeafFinding.

# WHEN THIS RUNS

cmd/ledger/boot/wire/wire.go installs this adapter on the
sequencer when ALL gossip prerequisites are wired
(GossipStore + Sink + Signer + non-zero NetworkID + non-empty
Originator). The gossip-disabled deployment mode falls back to
the in-tree LoggingGhostLeafEmitter — same emit contract from
the sequencer's perspective, no broadcast, no panic.

# THE SIX-STEP EMIT PATH

For each GhostLeafEvent the sequencer hands over:

 1. Validate the event (defense-in-depth — Sequencer's committer
    sets every field correctly today, but a malformed event must
    not trigger a panic deep in cosign.Verify down the chain).
 2. Construct findings.NewGhostLeafFinding(...). The SDK
    constructor performs its own Validate; a Validate error is
    operationally an uninitialized event, not transient.
 3. Read the originator's chain head via GossipStore.Head to get
    (prev EventID, last lamport).
 4. Sign via gossip.Sign under cosign.PurposeGossipEventV1.
 5. Append to local GossipStore — populates the
    /v1/gossip/by-binding/{canonical_hash} index so offline
    auditors can find the confession when they observe the
    duplicate Tessera leaf.
 6. Broadcast via Sink for peer-ledger replication.

Every step's failure is LOGGED and COUNTED but never propagated
back to the sequencer. Emission is best-effort broadcast
amplification; the entry_index ghost row remains the
authoritative record regardless of gossip outcome.

# IDEMPOTENCY

GossipStore.Append is content-addressed by EventID
(SHA-256 of canonical bytes). Re-emitting the same GhostLeafEvent
produces the same EventID and Append returns nil — the
sequencer can call Emit twice for the same recovery (e.g., the
chaos test driving identical batches) without producing
duplicate gossip rows.

# CRYPTOGRAPHIC INVARIANTS HONORED

  - Field copy from sequencer.GhostLeafEvent into
    findings.NewGhostLeafFinding is byte-aligned; uint64
    ObservedAtUnixNano flows through unchanged. No time.Time
    conversion happens here.
  - The signature binds the gossip envelope to the originator's
    DID; a peer can verify the event came from this ledger by
    resolving the LogDID via did.ECDSAKeyResolver and checking
    the signature.
*/
package gossipnet

import (
	"context"
	"log/slog"
	"sync/atomic"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"

	"github.com/clearcompass-ai/ledger/sequencer"
)

// SDKGossipGhostLeafEmitterConfig wires the production adapter
// against the same gossip plumbing the EquivocationScanner uses.
// All five non-Logger fields are REQUIRED — the adapter's
// constructor returns an error rather than silently degrading.
//
// Wired by cmd/ledger/boot/wire/wire.go alongside the existing
// gossip Signer / Sink / GossipStore / NetworkID / Originator —
// the same value set the equivocation scanner consumes. Shared
// instances are correct: ghost-leaf events sign under the same
// originator chain as STH publications + equivocation findings,
// advancing the same lamport scalar.
type SDKGossipGhostLeafEmitterConfig struct {
	// GossipStore is the local gossip store. Head supplies (prev,
	// lamport); Append durably records the signed event and
	// populates the by-binding index keyed on canonical_hash.
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
	// the EquivocationScanner uses for its findings.
	Originator string

	// Logger receives best-effort diagnostic lines. nil falls
	// back to slog.Default.
	Logger *slog.Logger
}

// SDKGossipGhostLeafEmitter is the production GhostLeafEmitter.
//
// Compile-time pinned at the bottom of the file: this type
// satisfies sequencer.GhostLeafEmitter structurally. If the
// sequencer's interface drifts, the build breaks here, not at
// runtime.
type SDKGossipGhostLeafEmitter struct {
	cfg SDKGossipGhostLeafEmitterConfig
	log *slog.Logger

	// Observability counters surface in the chaos harness'
	// post-test diagnostics. Each is the count of how many
	// emissions reached that particular step:
	//
	//   succeeded — full path (Validate → Sign → Append → Broadcast).
	//   appendOnly — Append landed but Broadcast failed.
	//   signFailed — Sign returned an error.
	//   validateFailed — sequencer handed us an invalid event.
	succeeded      atomic.Uint64
	appendOnly     atomic.Uint64
	signFailed     atomic.Uint64
	validateFailed atomic.Uint64
}

// NewSDKGossipGhostLeafEmitter constructs the adapter. Returns
// an error when any required field is missing — mirrors the
// EquivocationScanner's constructor discipline so wiring bugs
// surface at boot, not on the first ghost-recovery.
func NewSDKGossipGhostLeafEmitter(cfg SDKGossipGhostLeafEmitterConfig) (*SDKGossipGhostLeafEmitter, error) {
	if cfg.GossipStore == nil {
		return nil, errSDKEmitter("GossipStore required")
	}
	if cfg.Sink == nil {
		return nil, errSDKEmitter("Sink required")
	}
	if cfg.Signer == nil {
		return nil, errSDKEmitter("Signer required")
	}
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, errSDKEmitter("NetworkID required (non-zero)")
	}
	if cfg.Originator == "" {
		return nil, errSDKEmitter("Originator required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &SDKGossipGhostLeafEmitter{cfg: cfg, log: logger}, nil
}

// Emit implements sequencer.GhostLeafEmitter. Best-effort: every
// failure path logs + bumps a dimensional counter but never
// blocks or propagates the error back to the sequencer.
func (e *SDKGossipGhostLeafEmitter) Emit(ctx context.Context, ev sequencer.GhostLeafEvent) {
	// Step 1 — defense-in-depth validation of the event the
	// sequencer handed us. The downstream SDK constructor
	// repeats most of these checks; the local Validate catches
	// the misuse earlier and lets us attribute the failure to
	// the SEQUENCER call site rather than to the SDK.
	if err := ev.Validate(); err != nil {
		e.validateFailed.Add(1)
		e.log.WarnContext(ctx,
			"ghost-leaf emitter: caller-supplied event failed Validate; emission skipped",
			"error", err,
			"ghost_seq", ev.GhostSeq,
			"canonical_seq", ev.CanonicalSeq,
			"log_did", ev.LogDID,
		)
		return
	}

	// Step 2 — build the SDK finding. The SDK constructor's
	// Validate is structurally identical to step 1; any
	// disagreement signals an SDK contract drift worth
	// investigating at the SRE layer.
	finding, err := findings.NewGhostLeafFinding(
		ev.GhostSeq,
		ev.CanonicalSeq,
		ev.CanonicalHash,
		ev.LogDID,
		ev.ObservedAtUnixNano,
	)
	if err != nil {
		e.validateFailed.Add(1)
		e.log.ErrorContext(ctx,
			"ghost-leaf emitter: SDK constructor rejected event (after local Validate passed — SDK contract drift?)",
			"error", err,
			"ghost_seq", ev.GhostSeq,
			"canonical_seq", ev.CanonicalSeq,
		)
		return
	}

	// Step 3 — read originator chain head. lamport advances
	// strictly monotonically per the protocol; gossip.Sign
	// rejects a non-strict increase, so we never emit two
	// events at the same lamport for the same originator.
	prev, lamport, err := e.cfg.GossipStore.Head(ctx, e.cfg.Originator)
	if err != nil {
		e.signFailed.Add(1)
		e.log.WarnContext(ctx,
			"ghost-leaf emitter: read head failed; emission skipped",
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
	// EquivocationScanner's signing path verbatim.
	signed, err := sdkgossip.Sign(ctx, finding,
		e.cfg.Signer, e.cfg.NetworkID, e.cfg.Originator,
		prev, nextLamport)
	if err != nil {
		e.signFailed.Add(1)
		e.log.WarnContext(ctx,
			"ghost-leaf emitter: Sign failed; emission skipped",
			"error", err,
			"ghost_seq", ev.GhostSeq,
			"canonical_seq", ev.CanonicalSeq,
		)
		return
	}

	// Step 5 — Append to local GossipStore. Idempotent: a
	// re-Append of the same EventID returns nil; other errors
	// signal a state-machine bug.
	if err := e.cfg.GossipStore.Append(ctx, signed); err != nil {
		if !isAcceptableGhostAppendError(err) {
			e.signFailed.Add(1)
			e.log.WarnContext(ctx,
				"ghost-leaf emitter: Append failed; emission skipped",
				"error", err,
			)
			return
		}
	}

	// Step 6 — Broadcast. Best-effort: peer failures aggregate
	// inside the Sink. A failure here counts as appendOnly
	// (durable local record exists; peers will catch up via
	// anti-entropy / /since-cursor).
	if err := e.cfg.Sink.Broadcast(ctx, signed); err != nil {
		e.appendOnly.Add(1)
		e.log.WarnContext(ctx,
			"ghost-leaf emitter: Broadcast failed (durable locally; peers will catch up via /since)",
			"error", err,
			"ghost_seq", ev.GhostSeq,
			"canonical_seq", ev.CanonicalSeq,
		)
		return
	}

	e.succeeded.Add(1)
	e.log.InfoContext(ctx,
		"ghost leaf emitted (signed + appended + broadcast)",
		"ghost_seq", ev.GhostSeq,
		"canonical_seq", ev.CanonicalSeq,
		"canonical_hash", shortHash(ev.CanonicalHash),
		"log_did", ev.LogDID,
		"observed_at_unix_nano", ev.ObservedAtUnixNano,
		"lamport", nextLamport,
	)
}

// Snapshot returns the running emit-disposition counters. Used by
// the chaos harness and SRE dashboards to characterise the
// crash-recovery rate. Snapshot is racy with concurrent Emit
// calls but each individual counter is atomic; the returned
// values are an internally-consistent point-in-time view.
type SDKGhostLeafEmitterSnapshot struct {
	Succeeded      uint64
	AppendOnly     uint64
	SignFailed     uint64
	ValidateFailed uint64
}

// Snapshot returns the current emit counters.
func (e *SDKGossipGhostLeafEmitter) Snapshot() SDKGhostLeafEmitterSnapshot {
	return SDKGhostLeafEmitterSnapshot{
		Succeeded:      e.succeeded.Load(),
		AppendOnly:     e.appendOnly.Load(),
		SignFailed:     e.signFailed.Load(),
		ValidateFailed: e.validateFailed.Load(),
	}
}

// errSDKEmitter wraps a constructor error with a stable
// "gossipnet/ghost_leaf_emitter:" prefix. Keeps the call site
// terse and the log lines greppable.
func errSDKEmitter(msg string) error {
	return &sdkEmitterError{msg: msg}
}

type sdkEmitterError struct{ msg string }

func (e *sdkEmitterError) Error() string {
	return "gossipnet/sdk_ghost_leaf_emitter: " + e.msg
}

// isAcceptableGhostAppendError mirrors the equivocation scanner's
// helper of the same name. I9 idempotency on GossipStore.Append
// produces a nil error today; if the implementation switches to a
// "duplicate"-tagged sentinel, this localizes the policy in one
// place.
func isAcceptableGhostAppendError(err error) bool {
	if err == nil {
		return true
	}
	return containsLower(err.Error(), "duplicate")
}

// containsLower is a tiny case-insensitive substring check used
// once by isAcceptableGhostAppendError; avoids pulling in the
// strings package for this single call.
func containsLower(haystack, needle string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return len(needle) == 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a, b := haystack[i+j], needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Compile-time pin — SDKGossipGhostLeafEmitter satisfies the
// sequencer's local interface. Same pattern the logging emitter
// uses; drift between the two surfaces as a build error.
var _ sequencer.GhostLeafEmitter = (*SDKGossipGhostLeafEmitter)(nil)
