/*
FILE PATH: gossipnet/equivocation_scanner.go

EquivocationScanner — independent goroutine that detects
entry-level commitment equivocation (two distinct entries
admitted under the same (schema_id, split_id) tuple) and
broadcasts cryptographically-verified evidence as a gossip
event of KindEntryCommitmentEquivocation.

# WHY INDEPENDENT GOROUTINE

The commit hot-path (admission → WAL → SCT) MUST stay free of
equivocation math. The sequencer/projector goroutine writes the
splitid index (one Badger PUT) and moves on; collision detection
+ finding construction + signing + broadcast all run on this
SCANNER goroutine, on its own scheduling.

# DETECTION FLOW

 1. badger.DB.Subscribe(prefix=0x0A) wakes on every splitid
    index PUT (the sequencer's Phase 2 commit).
 2. Subscribe callback receives (schema_id, split_id, seq).
 3. Scanner re-loads via gossipstore.ListSplitIDIndexEntriesAt
    (one View transaction, fresh consistent snapshot).
 4. If the list contains < 2 entries: legitimate first
    admission. No-op.
 5. If the list contains >= 2 entries: equivocation. Pick the
    two earliest seqs, build *findings.EntryCommitmentEquivocationFinding
    (v0.1.1 collapsed the previous Verified... phantom-typed wrapper;
    the publish gate is now developer discipline at the call site),
    sign + Append + Broadcast via the ledger's gossip Sink.

# IDEMPOTENCY

The same (schema_id, split_id) collision can fire the subscribe
callback multiple times (as more colliding entries arrive). The
EventID is content-derived from the SignedEvent's canonical
bytes, which include the two earliest sides — so subsequent
collisions at the same (schema, split_id) produce the SAME
EventID (until a third entry arrives, which would change the
sides selected). Gossip Store's I9 idempotency makes
re-broadcast a no-op.

# RESEARCH CONSTRAINTS

  - Per-pair scan is O(N_at_split_id) which is bounded at 2-3
    in practice (a 4th entry from the same equivocator at the
    same SplitID is rare).
  - The scanner runs on a single goroutine; this is fine because
    detection is a low-volume event (equivocation is rare). If
    detection ever becomes throughput-bound, switch to a
    sharded-by-schema worker pool.

# FAILURE MODES

  - Subscribe callback errors: logged and skipped (one bad event
    must not break detection on healthy events). The Badger
    subscription continues running.
  - Sign failure: logged. The collision is recorded in the
    splitid index regardless; a future scanner restart will see
    the entries again and re-attempt detection.
  - Sink Broadcast failure: logged. Anti-entropy in peer
    ledgers backfills the missed event on the next /since
    pull.
*/
package gossipnet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"

	"github.com/clearcompass-ai/ledger/gossipstore"
)

// EquivocationScannerConfig configures the scanner goroutine.
type EquivocationScannerConfig struct {
	// Store is the ledger's BadgerDB-backed gossip store. The
	// scanner subscribes to 0x0A (splitid index), reads from
	// 0x0A on collision, and projects into 0x0B
	// (equivocation projection).
	Store *gossipstore.BadgerStore

	// GossipStore is the gossip Store interface (typically the
	// same value as Store wrapped through gossip.Store) — the
	// scanner Append's the verified finding here too so the
	// gossip handler / FeedHandler / FeedClient surfaces see it
	// alongside any peer-published findings.
	GossipStore sdkgossip.Store

	// Sink is the fan-out destination. Required.
	Sink sdkgossip.Sink

	// Signer signs the gossip envelope under the ledger's
	// originator DID — the SAME DID the sequencer wrote into
	// the splitid index entries (the ledger that admitted
	// both sides is also the equivocator).
	Signer sdkcosign.WitnessSigner

	// NetworkID binds the gossip event to the deployment's
	// network.
	NetworkID sdkcosign.NetworkID

	// Originator is the ledger's own DID (matches Signer).
	Originator string

	Logger *slog.Logger
}

// EquivocationScanner runs the detection loop.
type EquivocationScanner struct {
	cfg EquivocationScannerConfig
	log *slog.Logger
}

// NewEquivocationScanner constructs the scanner. Returns an
// error when any required field is missing.
func NewEquivocationScanner(cfg EquivocationScannerConfig) (*EquivocationScanner, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/equivocation_scanner: Store required")
	}
	if cfg.GossipStore == nil {
		return nil, fmt.Errorf("gossipnet/equivocation_scanner: GossipStore required")
	}
	if cfg.Sink == nil {
		return nil, fmt.Errorf("gossipnet/equivocation_scanner: Sink required")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("gossipnet/equivocation_scanner: Signer required")
	}
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet/equivocation_scanner: NetworkID required (non-zero)")
	}
	if cfg.Originator == "" {
		return nil, fmt.Errorf("gossipnet/equivocation_scanner: Originator required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &EquivocationScanner{cfg: cfg, log: logger}, nil
}

// Run starts the subscribe loop. Blocks until ctx is cancelled.
// Returns ctx.Err() on graceful shutdown; subscribe-level
// errors are logged + ignored to keep the goroutine alive.
func (s *EquivocationScanner) Run(ctx context.Context) error {
	s.log.Info("equivocation scanner: started",
		"originator", s.cfg.Originator,
		"prefix", "0x07 0x0A (splitid index)")

	err := s.cfg.Store.SubscribeSplitIDIndex(ctx,
		func(schemaID string, splitID [32]byte, seq uint64) error {
			s.handle(ctx, schemaID, splitID, seq)
			return nil
		})
	if err != nil {
		s.log.Info("equivocation scanner: stopped", "reason", err)
	}
	return err
}

// handle processes one subscribe wakeup. Re-loads under a fresh
// View transaction to get a consistent snapshot, checks for
// collision, and on collision builds + publishes the finding.
func (s *EquivocationScanner) handle(ctx context.Context, schemaID string, splitID [32]byte, seq uint64) {
	hits, err := s.cfg.Store.ListSplitIDIndexEntriesAt(ctx, schemaID, splitID)
	if err != nil {
		s.log.Warn("equivocation scanner: list failed",
			"schema_id", schemaID,
			"split_id", splitID[:8],
			"error", err)
		return
	}
	if len(hits) < 2 {
		// Legitimate first admission at this (schema, split_id).
		// Most subscribe events resolve here.
		return
	}

	// Collision. Pick the two earliest entries deterministically
	// — the underlying scan returns them in seq-ascending order.
	a, b := hits[0], hits[1]
	if a.Entry.EquivocatorDID != b.Entry.EquivocatorDID {
		// Defensive: two different ledgers' entries at the
		// same SplitID is a different threat model (cross-
		// originator collision). Skip — handled by a separate
		// detector if/when needed.
		s.log.Warn("equivocation scanner: cross-originator collision (out of scope)",
			"schema_id", schemaID,
			"a_did", a.Entry.EquivocatorDID,
			"b_did", b.Entry.EquivocatorDID)
		return
	}

	finding, err := findings.NewEntryCommitmentEquivocationFinding(
		a.Entry.EquivocatorDID, schemaID, splitID,
		findings.EntryEquivocatedSide{
			CanonicalHash: a.Entry.CanonicalHash,
			EntrySeq:      a.EntrySeq,
			SigBytes:      a.Entry.SigBytes,
		},
		findings.EntryEquivocatedSide{
			CanonicalHash: b.Entry.CanonicalHash,
			EntrySeq:      b.EntrySeq,
			SigBytes:      b.Entry.SigBytes,
		},
	)
	if err != nil {
		s.log.Warn("equivocation scanner: build finding failed",
			"schema_id", schemaID, "error", err)
		return
	}

	// Sign the gossip envelope under the ledger's own
	// originator. Reads the chain head from the gossip Store so
	// lamport advances correctly.
	prev, lamport, err := s.cfg.GossipStore.Head(ctx, s.cfg.Originator)
	if err != nil {
		s.log.Warn("equivocation scanner: read head failed", "error", err)
		return
	}
	nextLamport := lamport + 1
	if lamport == 0 {
		nextLamport = 1
	}
	signed, err := sdkgossip.Sign(ctx, finding,
		s.cfg.Signer, s.cfg.NetworkID, s.cfg.Originator, prev, nextLamport)
	if err != nil {
		s.log.Warn("equivocation scanner: sign failed", "error", err)
		return
	}

	// Local Append + projection write. The Append also
	// populates the binding inverted index (0x09) via the
	// BadgerStore's existing Append path so /by-binding queries
	// see this finding too.
	if err := s.cfg.GossipStore.Append(ctx, signed); err != nil {
		// I9 idempotency: a re-detection of the same collision
		// produces the same EventID and Append returns nil.
		// Other errors signal a state-machine bug.
		if !isAcceptableAppendError(err) {
			s.log.Warn("equivocation scanner: Append failed", "error", err)
			return
		}
	}

	// Project into 0x0B for O(1) /by-split-id reads. Use the SDK
	// helper so the projection key is computed identically to
	// every consumer (findings.FetchEquivocationByBinding,
	// SignedEvent.Bindings) — drift-free by construction.
	binding := findings.EntryCommitmentBinding(schemaID, splitID)
	signedBytes, jerr := json.Marshal(signed)
	if jerr != nil {
		s.log.Warn("equivocation scanner: marshal SignedEvent", "error", jerr)
		return
	}
	if err := s.cfg.Store.PutEquivProjection(ctx, binding, signedBytes); err != nil {
		s.log.Warn("equivocation scanner: project failed", "error", err)
		return
	}

	// Broadcast (best-effort).
	if err := s.cfg.Sink.Broadcast(ctx, signed); err != nil {
		s.log.Warn("equivocation scanner: broadcast failed (peers will catch up via /since)",
			"error", err)
	}

	s.log.Error("ENTRY COMMITMENT EQUIVOCATION DETECTED + PUBLISHED",
		"schema_id", schemaID,
		"split_id", fmt.Sprintf("%x", splitID[:8]),
		"equivocator_did", a.Entry.EquivocatorDID,
		"seq_a", a.EntrySeq,
		"seq_b", b.EntrySeq,
		"lamport", nextLamport)
}

// isAcceptableAppendError returns true for the error categories
// that the scanner can safely ignore: idempotent re-receive, or
// chain-discipline rejections that signal upstream issues but
// don't warrant blocking detection. The current set is just I9
// idempotency, but the helper localizes the policy so future
// changes are one-line.
func isAcceptableAppendError(err error) bool {
	if err == nil {
		return true
	}
	// I9 idempotency surfaces as nil from Append per Store
	// contract; if the implementation switches to returning a
	// sentinel, recognize it here.
	return strings.Contains(err.Error(), "duplicate")
}
