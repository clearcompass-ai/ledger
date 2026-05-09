// Gossip wiring.
//
// FILE PATH:
//
//	cmd/ledger/boot/wire/gossip.go
//
// DESCRIPTION:
//
//	wireGossip builds the gossipnet.Bundle, the STH publisher, and
//	the three async observers that ride on top of the bundle: the
//	anti-entropy puller, the equivocation monitor (peer STH
//	divergence), and the equivocation scanner (entry-level split-id
//	collisions).
//
//	All three observers join d.WG so teardown's
//	"background-goroutines" step waits on them once.
//
//	When d.GossipStore is nil (gossip disabled at alloc time) wireGossip
//	returns nil immediately — no Bundle / Publisher set.
package wire

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"

	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/deps"
	"github.com/clearcompass-ai/ledger/gossipnet"
	"github.com/clearcompass-ai/ledger/lifecycle"
	"github.com/clearcompass-ai/ledger/witnessclient"
)

// wireGossip builds the gossipnet.Bundle, STH publisher, and starts
// the three async observers. No-op when d.GossipStore is nil.
func wireGossip(ctx context.Context, cfg Config, d *deps.AppDeps) error {
	if d.GossipStore == nil {
		d.Logger.Info("gossip: not wired (no gossip store from alloc)")
		return nil
	}
	bundle, err := gossipnet.Build(gossipnet.Config{
		Store:         d.GossipStore,
		NetworkID:     cfg.NetworkID,
		PeerEndpoints: cfg.GossipPeerEndpoints,
		Meter:         d.GossipMeter,
		Logger:        d.Logger,
	})
	if err != nil {
		return fmt.Errorf("gossipnet build: %w", err)
	}
	d.GossipBundle = bundle

	// Register the bundle's Closeables onto the closeStack BEFORE the
	// gossip-store closer that alloc registered — so unwind closes
	// the bundle's Sink before the underlying Badger handle.
	for _, cl := range bundle.Closeables {
		clClose := cl.Close
		d.AppendCloser(deps.NamedCloser{
			Name:    "gossip-bundle-closeable",
			Timeout: 5 * time.Second,
			Close: func(ctx context.Context) error {
				return clClose(ctx)
			},
		})
	}

	// STH publisher: signs KindCosignedTreeHead under the ledger DID.
	pub, err := gossipnet.NewSTHPublisher(gossipnet.PublisherConfig{
		Store:          d.GossipStore,
		Sink:           bundle.Sink,
		Signer:         cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
		NetworkID:      cfg.NetworkID,
		Originator:     cfg.LedgerDID,
		LedgerEndpoint: cfg.ServerAddr,
		Logger:         d.Logger,
	})
	if err != nil {
		return fmt.Errorf("gossip STH publisher: %w", err)
	}
	d.GossipPublisher = pub

	d.Logger.Info("gossip endpoints mounted",
		"post_path", "/v1/gossip",
		"feed_path_prefix", "/v1/gossip/",
		"peers", len(cfg.GossipPeerEndpoints),
	)

	// Anti-entropy + equivocation monitor + equivocation scanner.
	startGossipObservers(ctx, cfg, d, bundle, pub)
	return nil
}

// startGossipObservers spawns the three async gossip goroutines. Each
// joins d.WG.
func startGossipObservers(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	bundle *gossipnet.Bundle,
	pub *gossipnet.STHPublisher,
) {
	// Anti-entropy.
	if len(cfg.GossipPeerDIDs) > 0 && len(cfg.GossipPeerDIDs) == len(cfg.GossipPeerEndpoints) {
		peers := make([]gossipnet.AntiEntropyPeer, 0, len(cfg.GossipPeerDIDs))
		for i, did := range cfg.GossipPeerDIDs {
			peers = append(peers, gossipnet.AntiEntropyPeer{
				DID:     did,
				BaseURL: cfg.GossipPeerEndpoints[i],
			})
		}
		ae, aerr := gossipnet.NewAntiEntropy(gossipnet.AntiEntropyConfig{
			Store:  d.GossipStore,
			Peers:  peers,
			Logger: d.Logger,
		})
		if aerr == nil {
			lifecycle.SafeRunInWG(ctx, &d.WG, "anti-entropy", d.Logger, d.Fatal, func() error {
				if rerr := ae.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
					d.Logger.Warn("anti-entropy: exited with error", "error", rerr)
				}
				return nil
			})
			d.Logger.Info("anti-entropy: enabled", "peers", len(peers))
		} else {
			d.Logger.Warn("anti-entropy: construction failed", "error", aerr)
		}
	} else if len(cfg.GossipPeerDIDs) > 0 {
		d.Logger.Warn("anti-entropy: disabled (peer DID/endpoint length mismatch)",
			"dids", len(cfg.GossipPeerDIDs),
			"endpoints", len(cfg.GossipPeerEndpoints))
	}

	// Equivocation monitor.
	if len(cfg.GenesisWitnessSet) > 0 &&
		len(cfg.GossipPeerDIDs) > 0 &&
		len(cfg.GossipPeerDIDs) == len(cfg.GossipPeerEndpoints) &&
		pub != nil {
		startEquivocationMonitor(ctx, cfg, d, bundle)
	} else {
		d.Logger.Info("equivocation monitor: disabled (missing prerequisites)",
			"genesis_witness_set", len(cfg.GenesisWitnessSet),
			"peer_dids", len(cfg.GossipPeerDIDs),
			"peer_endpoints", len(cfg.GossipPeerEndpoints),
			"publisher_wired", pub != nil,
		)
	}

	// Equivocation scanner (entry-level).
	startEquivocationScanner(ctx, cfg, d, bundle)
}

func startEquivocationMonitor(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	bundle *gossipnet.Bundle,
) {
	witnessKeys, werr := gossipnet.WitnessKeysFromDIDs(cfg.GenesisWitnessSet)
	if werr != nil {
		d.Logger.Error("equivocation monitor: witness key resolution",
			"error", werr)
		return
	}
	witnessSet, wsErr := cosign.NewWitnessKeySet(
		witnessKeys,
		cfg.NetworkID,
		cfg.WitnessQuorumK,
		cosign.NewProductionBLSVerifier(),
	)
	if wsErr != nil {
		d.Logger.Error("equivocation monitor: NewWitnessKeySet failed",
			"error", wsErr,
			"keys", len(witnessKeys),
			"quorum_k", cfg.WitnessQuorumK)
		return
	}
	equivPub, perr := gossipnet.NewEquivocationPublisher(gossipnet.EquivocationPublisherConfig{
		Store:      d.GossipStore,
		Sink:       bundle.Sink,
		Signer:     cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
		NetworkID:  cfg.NetworkID,
		Originator: cfg.LedgerDID,
		Logger:     d.Logger,
	})
	if perr != nil {
		d.Logger.Error("equivocation publisher", "error", perr)
		return
	}
	equivPeers := make([]gossipnet.AntiEntropyPeer, 0, len(cfg.GossipPeerDIDs))
	for i, did := range cfg.GossipPeerDIDs {
		equivPeers = append(equivPeers, gossipnet.AntiEntropyPeer{
			DID:     did,
			BaseURL: cfg.GossipPeerEndpoints[i],
		})
	}
	eqMon, eerr := gossipnet.NewEquivocationMonitor(gossipnet.EquivocationMonitorConfig{
		Store:      d.GossipStore,
		Peers:      equivPeers,
		WitnessSet: witnessSet,
		Publisher:  equivPub,
		Logger:     d.Logger,
	})
	if eerr != nil {
		d.Logger.Error("equivocation monitor", "error", eerr)
		return
	}
	lifecycle.SafeRunInWG(ctx, &d.WG, "equivocation-monitor", d.Logger, d.Fatal, func() error {
		if rerr := eqMon.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
			d.Logger.Warn("equivocation monitor: exited with error", "error", rerr)
		}
		return nil
	})
	d.Logger.Info("equivocation monitor: enabled",
		"peers", len(equivPeers),
		"quorum_k", witnessSet.Quorum(),
		"witness_set_size", witnessSet.Size(),
	)
}

func startEquivocationScanner(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	bundle *gossipnet.Bundle,
) {
	if d.GossipStore == nil || bundle == nil {
		return
	}
	scanner, scerr := gossipnet.NewEquivocationScanner(
		gossipnet.EquivocationScannerConfig{
			Store:       d.GossipStore,
			GossipStore: d.GossipStore,
			Sink:        bundle.Sink,
			Signer:      cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
			NetworkID:   cfg.NetworkID,
			Originator:  cfg.LedgerDID,
			Logger:      d.Logger,
		})
	if scerr != nil {
		d.Logger.Error("equivocation scanner construction", "error", scerr)
		return
	}
	lifecycle.SafeRunInWG(ctx, &d.WG, "equivocation-scanner", d.Logger, d.Fatal, func() error {
		if rerr := scanner.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
			d.Logger.Warn("equivocation scanner: exited with error", "error", rerr)
		}
		return nil
	})
	d.Logger.Info("equivocation scanner: enabled (subscribed to splitid index 0x0A)")
}

// wireWitnessCosigner builds the HeadSync requester (witness cosigner)
// when LEDGER_WITNESS_ENDPOINTS is set; nil otherwise. The returned
// *witnessclient.HeadSync satisfies builder.WitnessCosigner and is fed into
// the BuilderLoop.
func wireWitnessCosigner(cfg Config, d *deps.AppDeps) (*witnessclient.HeadSync, error) {
	if len(cfg.WitnessEndpoints) == 0 {
		d.Logger.Info("witness cosigner: disabled (LEDGER_WITNESS_ENDPOINTS unset)")
		return nil, nil
	}
	var pub witnessclient.CosignedHeadPublisher
	if d.GossipPublisher != nil {
		pub = d.GossipPublisher
	}
	hs, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  cfg.WitnessEndpoints,
		QuorumK:           cfg.WitnessQuorumK,
		PerWitnessTimeout: 30 * time.Second,
		NetworkID:         cfg.NetworkID,
		GossipPublisher:   pub,
	}, d.TreeHeadStore, d.Logger)
	if err != nil {
		return nil, err
	}
	d.Logger.Info("witness cosigner: HeadSync requester enabled",
		"endpoints", cfg.WitnessEndpoints,
		"quorum_k", cfg.WitnessQuorumK,
		"gossip_publisher", d.GossipPublisher != nil,
	)
	return hs, nil
}

// wireEscrowOverride builds the /v1/escrow-override handler when both
// the witness cosigner and gossip bundle are wired. nil otherwise.
func wireEscrowOverride(cfg Config, cosigner *witnessclient.HeadSync, d *deps.AppDeps) http.HandlerFunc {
	if cosigner == nil || d.GossipBundle == nil || d.GossipPublisher == nil {
		return nil
	}
	if cosigner.Collector() == nil {
		d.Logger.Warn("escrow override: skipped (cosigner has no Collector exposure)")
		return nil
	}
	svc, err := gossipnet.NewEscrowOverrideService(gossipnet.EscrowOverrideServiceConfig{
		Collector:  cosigner.Collector(),
		Store:      d.GossipStore,
		Sink:       d.GossipBundle.Sink,
		Signer:     cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
		NetworkID:  cfg.NetworkID,
		Originator: cfg.LedgerDID,
		Logger:     d.Logger,
	})
	if err != nil {
		d.Logger.Error("escrow override service", "error", err)
		return nil
	}
	d.Logger.Info("escrow override endpoint mounted at POST /v1/escrow-override")
	return api.EscrowOverrideHandler(svc, d.Logger)
}
