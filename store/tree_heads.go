/*
FILE PATH: store/tree_heads.go

Cosigned tree head persistence. Normalized into two tables:
  tree_heads:     "at this size, the root was X (computed with hash_algo Y)"
  tree_head_sigs: "I (signer) vouch for this root (signed with sig_algo Z)"

DESIGN RULE: One row per attestation. Witnesses, operator seals, and
rehash attestations are all rows in tree_head_sigs. Append-only.

30-YEAR EXTENSIBILITY:
  - New hash algorithm: new hash_algo value, new tree_heads row at same tree_size.
  - New signature algorithm: new sig_algo value, new tree_head_sigs row.
  - Seal: operator signs existing root with stronger key. One INSERT.
  - Rehash seal: compute new root with new hash, INSERT head + sig.
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

// CosignedTreeHead and TreeHeadSignature live in apitypes/ so
// api/ can consume them without importing store/ (PT-7 — Pure
// CQRS). Re-exported as type aliases here for backwards
// compatibility with existing in-package call sites.
type (
	CosignedTreeHead   = apitypes.CosignedTreeHead
	TreeHeadSignature  = apitypes.TreeHeadSignature
)

// ─────────────────────────────────────────────────────────────────────────────
// Store
// ─────────────────────────────────────────────────────────────────────────────

// TreeHeadStore manages tree head and signature persistence.
type TreeHeadStore struct {
	db     *pgxpool.Pool
	mu     sync.RWMutex
	cached *CosignedTreeHead
}

// NewTreeHeadStore creates a tree head store.
func NewTreeHeadStore(db *pgxpool.Pool) *TreeHeadStore {
	return &TreeHeadStore{db: db}
}

// InsertHead stores a new tree head fact. Idempotent — ignores conflict
// if the same (tree_size, hash_algo) already exists.
func (s *TreeHeadStore) InsertHead(ctx context.Context, treeSize uint64, rootHash [32]byte, hashAlgo uint16) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO tree_heads (tree_size, root_hash, hash_algo)
		VALUES ($1, $2, $3)
		ON CONFLICT (tree_size, hash_algo) DO NOTHING`,
		treeSize, rootHash[:], int16(hashAlgo),
	)
	if err != nil {
		return fmt.Errorf("store/tree_heads: insert head size=%d: %w", treeSize, err)
	}
	return nil
}

// InsertSig stores a single attestation signature. Idempotent.
// Invalidates the latest cache if the sig's tree_size >= cached tree_size.
func (s *TreeHeadStore) InsertSig(ctx context.Context, treeSize uint64, hashAlgo uint16, signer string, sigAlgo uint16, signature []byte) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO tree_head_sigs (tree_size, hash_algo, signer, sig_algo, signature)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tree_size, hash_algo, signer, sig_algo) DO NOTHING`,
		treeSize, int16(hashAlgo), signer, int16(sigAlgo), signature,
	)
	if err != nil {
		return fmt.Errorf("store/tree_heads: insert sig size=%d signer=%s: %w", treeSize, signer, err)
	}

	// Invalidate cache if this sig might affect the latest head.
	s.mu.RLock()
	cached := s.cached
	s.mu.RUnlock()
	if cached == nil || treeSize >= cached.TreeSize {
		s.Invalidate()
	}
	return nil
}

// Invalidate clears the in-memory cache. Called by builder after commit
// and by HeadSync after receiving a cosignature.
func (s *TreeHeadStore) Invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}

// ─────────────────────────────────────────────────────────────────────────────
// Queries
// ─────────────────────────────────────────────────────────────────────────────

// Latest returns the most recent tree head with all its signatures.
// Returns nil if no tree heads exist. Cached in memory.
func (s *TreeHeadStore) Latest(ctx context.Context) (*CosignedTreeHead, error) {
	s.mu.RLock()
	cached := s.cached
	s.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	head, err := s.fetchLatest(ctx)
	if err != nil {
		return nil, err
	}
	if head != nil {
		s.mu.Lock()
		s.cached = head
		s.mu.Unlock()
	}
	return head, nil
}

// LatestCosigned returns the largest tree_size with at least minSigs
// distinct signers. Used for quorum-aware queries.
func (s *TreeHeadStore) LatestCosigned(ctx context.Context, minSigs int) (*CosignedTreeHead, error) {
	row := s.db.QueryRow(ctx, `
		SELECT h.tree_size, h.root_hash, h.hash_algo, h.created_at
		FROM tree_heads h
		WHERE (
			SELECT COUNT(DISTINCT signer)
			FROM tree_head_sigs s
			WHERE s.tree_size = h.tree_size AND s.hash_algo = h.hash_algo
		) >= $1
		ORDER BY h.tree_size DESC, h.hash_algo DESC
		LIMIT 1`, minSigs)

	var head CosignedTreeHead
	var rootHash []byte
	err := row.Scan(&head.TreeSize, &rootHash, &head.HashAlgo, &head.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/tree_heads: latest cosigned: %w", err)
	}
	if len(rootHash) == 32 {
		copy(head.RootHash[:], rootHash)
	}

	sigs, err := s.fetchSigs(ctx, head.TreeSize, head.HashAlgo)
	if err != nil {
		return nil, err
	}
	head.Signatures = sigs
	return &head, nil
}

// GetBySize returns the tree head at a specific size (lowest hash_algo).
// Used by equivocation monitor to compare roots.
func (s *TreeHeadStore) GetBySize(ctx context.Context, size uint64) (*CosignedTreeHead, error) {
	var head CosignedTreeHead
	var rootHash []byte
	err := s.db.QueryRow(ctx, `
		SELECT tree_size, root_hash, hash_algo, created_at
		FROM tree_heads
		WHERE tree_size = $1
		ORDER BY hash_algo ASC
		LIMIT 1`, size,
	).Scan(&head.TreeSize, &rootHash, &head.HashAlgo, &head.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/tree_heads: get size=%d: %w", size, err)
	}
	if len(rootHash) == 32 {
		copy(head.RootHash[:], rootHash)
	}

	sigs, err := s.fetchSigs(ctx, head.TreeSize, head.HashAlgo)
	if err != nil {
		return nil, err
	}
	head.Signatures = sigs
	return &head, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal
// ─────────────────────────────────────────────────────────────────────────────

func (s *TreeHeadStore) fetchLatest(ctx context.Context) (*CosignedTreeHead, error) {
	var head CosignedTreeHead
	var rootHash []byte
	err := s.db.QueryRow(ctx, `
		SELECT tree_size, root_hash, hash_algo, created_at
		FROM tree_heads
		ORDER BY tree_size DESC, hash_algo DESC
		LIMIT 1`,
	).Scan(&head.TreeSize, &rootHash, &head.HashAlgo, &head.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/tree_heads: latest: %w", err)
	}
	if len(rootHash) == 32 {
		copy(head.RootHash[:], rootHash)
	}

	sigs, err := s.fetchSigs(ctx, head.TreeSize, head.HashAlgo)
	if err != nil {
		return nil, err
	}
	head.Signatures = sigs
	return &head, nil
}

func (s *TreeHeadStore) fetchSigs(ctx context.Context, treeSize uint64, hashAlgo uint16) ([]TreeHeadSignature, error) {
	rows, err := s.db.Query(ctx, `
		SELECT signer, sig_algo, signature, created_at
		FROM tree_head_sigs
		WHERE tree_size = $1 AND hash_algo = $2
		ORDER BY sig_algo DESC, signer`,
		treeSize, int16(hashAlgo))
	if err != nil {
		return nil, fmt.Errorf("store/tree_heads: fetch sigs size=%d: %w", treeSize, err)
	}
	defer rows.Close()

	var sigs []TreeHeadSignature
	for rows.Next() {
		var sig TreeHeadSignature
		if err := rows.Scan(&sig.Signer, &sig.SigAlgo, &sig.Signature, &sig.CreatedAt); err != nil {
			return nil, fmt.Errorf("store/tree_heads: scan sig: %w", err)
		}
		sigs = append(sigs, sig)
	}
	return sigs, rows.Err()
}
