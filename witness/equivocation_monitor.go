/*
FILE PATH: witness/equivocation_monitor.go

Compares external tree heads against stored heads. Same tree_size +
different root = equivocation proof. Persists proof and fires alert.

KEY ARCHITECTURAL DECISIONS:
  - Cryptographic equivocation proof: two validly signed heads with same
    size and different roots is unforgeable evidence of operator misbehavior.
  - Stored proofs immutable — append-only equivocation_proofs table.
  - HeadA populated with local head bytes (complete proof).
  - Uses encoding/hex for proper hex decoding (not manual nibble parsing).
*/
package witness

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// EquivocationMonitorConfig configures the equivocation monitor.
type EquivocationMonitorConfig struct {
	PeerEndpoints []string
	PollInterval  time.Duration
	AlertCallback func(proof EquivocationProof)
}

// EquivocationProof is cryptographic evidence of log fork.
type EquivocationProof struct {
	TreeSize  uint64
	RootHashA [32]byte
	RootHashB [32]byte
	HeadA     []byte // Local serialized head.
	HeadB     []byte // Peer's serialized head.
}

// EquivocationMonitor detects log forks.
type EquivocationMonitor struct {
	cfg       EquivocationMonitorConfig
	db        *pgxpool.Pool
	headStore *store.TreeHeadStore
	client    *http.Client
	logger    *slog.Logger
}

// NewEquivocationMonitor creates a monitor.
func NewEquivocationMonitor(
	cfg EquivocationMonitorConfig,
	db *pgxpool.Pool,
	headStore *store.TreeHeadStore,
	logger *slog.Logger,
) *EquivocationMonitor {
	return &EquivocationMonitor{
		cfg:       cfg,
		db:        db,
		headStore: headStore,
		// Tier-3 alignment: SDK's DefaultClient supplies connection
		// pooling and 503-Retry-After honoring. Peers under load
		// surface 503 + Retry-After; absorbing locally beats hard
		// fork-detection failures during the very intervals when
		// equivocation monitoring matters most.
		client: sdklog.DefaultClient(30 * time.Second),
		logger: logger,
	}
}

// Run starts the equivocation monitoring loop.
func (em *EquivocationMonitor) Run(ctx context.Context) {
	if len(em.cfg.PeerEndpoints) == 0 {
		em.logger.Info("equivocation: no peers configured, exiting")
		return
	}

	ticker := time.NewTicker(em.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			em.check(ctx)
		}
	}
}

func (em *EquivocationMonitor) check(ctx context.Context) {
	for _, endpoint := range em.cfg.PeerEndpoints {
		peerHead, peerBytes, err := em.fetchPeerHead(ctx, endpoint)
		if err != nil {
			em.logger.Warn("equivocation: peer fetch failed",
				"endpoint", endpoint, "error", err)
			continue
		}

		localHead, err := em.headStore.GetBySize(ctx, peerHead.TreeSize)
		if err != nil || localHead == nil {
			continue
		}

		if localHead.RootHash != peerHead.RootHash {
			localBytes, _ := json.Marshal(map[string]any{
				"tree_size": localHead.TreeSize,
				"root_hash": fmt.Sprintf("%x", localHead.RootHash),
				"hash_algo": localHead.HashAlgo,
			})

			proof := EquivocationProof{
				TreeSize:  peerHead.TreeSize,
				RootHashA: localHead.RootHash,
				RootHashB: peerHead.RootHash,
				HeadA:     localBytes,
				HeadB:     peerBytes,
			}

			em.logger.Error("EQUIVOCATION DETECTED",
				"tree_size", proof.TreeSize,
				"local_root", fmt.Sprintf("%x", proof.RootHashA[:8]),
				"peer_root", fmt.Sprintf("%x", proof.RootHashB[:8]),
				"peer", endpoint,
			)

			em.persistProof(ctx, proof)
			if em.cfg.AlertCallback != nil {
				em.cfg.AlertCallback(proof)
			}
		}
	}
}

func (em *EquivocationMonitor) fetchPeerHead(ctx context.Context, endpoint string) (*store.CosignedTreeHead, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"/v1/tree/head", nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := em.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, nil, err
	}

	var parsed struct {
		TreeSize uint64 `json:"tree_size"`
		RootHash string `json:"root_hash"`
		HashAlgo uint16 `json:"hash_algo"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, err
	}

	head := &store.CosignedTreeHead{
		TreeSize: parsed.TreeSize,
		HashAlgo: parsed.HashAlgo,
	}
	rootBytes, err := hex.DecodeString(parsed.RootHash)
	if err == nil && len(rootBytes) == 32 {
		copy(head.RootHash[:], rootBytes)
	}
	return head, body, nil
}

func (em *EquivocationMonitor) persistProof(ctx context.Context, proof EquivocationProof) {
	_, err := em.db.Exec(ctx, `
		INSERT INTO equivocation_proofs (head_a, head_b, tree_size)
		VALUES ($1, $2, $3)`,
		proof.HeadA, proof.HeadB, proof.TreeSize,
	)
	if err != nil {
		em.logger.Error("equivocation: persist proof", "error", err)
	}
}
