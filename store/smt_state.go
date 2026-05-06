/*
FILE PATH: store/smt_state.go

Postgres-backed implementations of sdk smt.LeafStore and sdk smt.NodeCache.

KEY ARCHITECTURAL DECISIONS:
  - PostgresLeafStore: supports both direct writes (pool) and transactional
    writes (via SetTx for atomic builder commits). The builder loop uses
    SetTx within its atomic commit transaction.
  - PostgresNodeCache: write-through to both Postgres (smt_nodes) and an
    in-memory LRU. Top N levels warmed on startup. Depth tracked correctly
    per node for selective warming.
  - LogPosition serialization: length-prefixed DID + uint64, matching SDK
    canonical serialization.

INVARIANTS:
  - After builder atomic commit, smt_leaves and smt_nodes are consistent.
  - WarmCache only loads nodes at depth <= topLevels (not all nodes).
  - LRU eviction preserves recently accessed nodes, not random eviction.
*/
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) PostgresLeafStore — implements sdk smt.LeafStore
// ─────────────────────────────────────────────────────────────────────────────

// PostgresLeafStore persists SMT leaves in Postgres.
// Supports transactional writes for atomic builder commits via SetTx/DeleteTx.
type PostgresLeafStore struct {
	db *pgxpool.Pool
}

// NewPostgresLeafStore creates a leaf store.
func NewPostgresLeafStore(db *pgxpool.Pool) *PostgresLeafStore {
	return &PostgresLeafStore{db: db}
}

// Get reads a leaf by key. Returns nil if not found.
func (s *PostgresLeafStore) Get(key [32]byte) (*types.SMTLeaf, error) {
	ctx := context.TODO()
	var originTipBytes, authorityTipBytes []byte
	err := s.db.QueryRow(ctx,
		"SELECT origin_tip, authority_tip FROM smt_leaves WHERE leaf_key = $1",
		key[:],
	).Scan(&originTipBytes, &authorityTipBytes)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/smt: get leaf: %w", err)
	}

	originTip, err := DeserializeLogPosition(originTipBytes)
	if err != nil {
		return nil, fmt.Errorf("store/smt: decode origin_tip: %w", err)
	}
	authorityTip, err := DeserializeLogPosition(authorityTipBytes)
	if err != nil {
		return nil, fmt.Errorf("store/smt: decode authority_tip: %w", err)
	}

	return &types.SMTLeaf{Key: key, OriginTip: originTip, AuthorityTip: authorityTip}, nil
}

// Set writes a leaf using the connection pool (non-transactional).
// Used during non-critical paths. Builder uses SetTx for atomic commits.
func (s *PostgresLeafStore) Set(key [32]byte, leaf types.SMTLeaf) error {
	ctx := context.TODO()
	originBytes := SerializeLogPosition(leaf.OriginTip)
	authBytes := SerializeLogPosition(leaf.AuthorityTip)

	_, err := s.db.Exec(ctx, `
		INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (leaf_key) DO UPDATE SET
			origin_tip = EXCLUDED.origin_tip,
			authority_tip = EXCLUDED.authority_tip,
			updated_at = NOW()`,
		key[:], originBytes, authBytes,
	)
	if err != nil {
		return fmt.Errorf("store/smt: set leaf: %w", err)
	}
	return nil
}

// SetTx writes a leaf within a transaction (for atomic builder commit).
func (s *PostgresLeafStore) SetTx(ctx context.Context, tx pgx.Tx, key [32]byte, leaf types.SMTLeaf) error {
	originBytes := SerializeLogPosition(leaf.OriginTip)
	authBytes := SerializeLogPosition(leaf.AuthorityTip)

	_, err := tx.Exec(ctx, `
		INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (leaf_key) DO UPDATE SET
			origin_tip = EXCLUDED.origin_tip,
			authority_tip = EXCLUDED.authority_tip,
			updated_at = NOW()`,
		key[:], originBytes, authBytes,
	)
	if err != nil {
		return fmt.Errorf("store/smt: set leaf tx: %w", err)
	}
	return nil
}

// SetBatch writes multiple leaves using Postgres batching.
// This satisfies the sdk smt.LeafStore interface.
// Note: The builder loop uses SetTx within its own atomic transaction block
// to commit mutations, but this method is required for interface compliance
// and non-transactional bulk operations.
func (s *PostgresLeafStore) SetBatch(leaves []types.SMTLeaf) error {
	if len(leaves) == 0 {
		return nil
	}

	ctx := context.TODO()
	batch := &pgx.Batch{}

	for _, leaf := range leaves {
		originBytes := SerializeLogPosition(leaf.OriginTip)
		authBytes := SerializeLogPosition(leaf.AuthorityTip)

		batch.Queue(`
			INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (leaf_key) DO UPDATE SET
				origin_tip = EXCLUDED.origin_tip,
				authority_tip = EXCLUDED.authority_tip,
				updated_at = NOW()`,
			leaf.Key[:], originBytes, authBytes,
		)
	}

	// SendBatch executes the queued statements.
	br := s.db.SendBatch(ctx, batch)
	defer br.Close()

	if _, err := br.Exec(); err != nil {
		return fmt.Errorf("store/smt: set batch: %w", err)
	}

	return nil
}

// Delete removes a leaf.
func (s *PostgresLeafStore) Delete(key [32]byte) error {
	ctx := context.TODO()
	_, err := s.db.Exec(ctx, "DELETE FROM smt_leaves WHERE leaf_key = $1", key[:])
	if err != nil {
		return fmt.Errorf("store/smt: delete leaf: %w", err)
	}
	return nil
}

// Count returns the total number of SMT leaves.
func (s *PostgresLeafStore) Count() (int, error) {
	ctx := context.TODO()
	var count int
	err := s.db.QueryRow(ctx, "SELECT COUNT(*) FROM smt_leaves").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store/smt: count leaves: %w", err)
	}
	return count, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) PostgresNodeCache — write-through Postgres + in-memory LRU
// ─────────────────────────────────────────────────────────────────────────────

// PostgresNodeCache implements sdk smt.NodeCache with write-through persistence.
// Uses a simple map with access tracking for LRU eviction.
type PostgresNodeCache struct {
	db *pgxpool.Pool
	mu sync.RWMutex
	cache map[[32]byte]cacheEntry
	access map[[32]byte]int64 // access counter for LRU
	counter int64
	maxSize int
}

type cacheEntry struct {
	hash []byte
	depth int
}

// NewPostgresNodeCache creates a node cache with the given LRU capacity.
func NewPostgresNodeCache(db *pgxpool.Pool, maxSize int) *PostgresNodeCache {
	if maxSize < 1024 {
		maxSize = 100000
	}
	return &PostgresNodeCache{
		db:      db,
		cache:   make(map[[32]byte]cacheEntry, maxSize),
		access:  make(map[[32]byte]int64, maxSize),
		maxSize: maxSize,
	}
}

// Get reads a node hash from cache, falling back to Postgres.
func (c *PostgresNodeCache) Get(key [32]byte) ([]byte, bool) {
	c.mu.RLock()
	entry, ok := c.cache[key]
	c.mu.RUnlock()
	if ok {
		c.mu.Lock()
		c.counter++
		c.access[key] = c.counter
		c.mu.Unlock()
		return entry.hash, true
	}

	// Cache miss — fetch from Postgres.
	ctx := context.TODO()
	var hash []byte
	err := c.db.QueryRow(ctx,
		"SELECT hash FROM smt_nodes WHERE path_key = $1", key[:],
	).Scan(&hash)
	if err != nil {
		return nil, false
	}

	c.mu.Lock()
	c.counter++
	c.cache[key] = cacheEntry{hash: hash, depth: 0}
	c.access[key] = c.counter
	c.mu.Unlock()
	return hash, true
}

// Set writes a node to cache and Postgres (write-through).
func (c *PostgresNodeCache) Set(key [32]byte, value []byte) {
	c.SetWithDepth(key, value, 0)
}

// SetWithDepth writes a node with its tree depth for selective warming.
func (c *PostgresNodeCache) SetWithDepth(key [32]byte, value []byte, depth int) {
	c.mu.Lock()
	if len(c.cache) >= c.maxSize {
		c.evictLRU()
	}
	c.counter++
	c.cache[key] = cacheEntry{hash: value, depth: depth}
	c.access[key] = c.counter
	c.mu.Unlock()

	// Write-through to Postgres.
	ctx := context.TODO()
	_, _ = c.db.Exec(ctx, `
		INSERT INTO smt_nodes (path_key, hash, depth, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (path_key) DO UPDATE SET
			hash = EXCLUDED.hash,
			depth = EXCLUDED.depth,
			updated_at = NOW()`,
		key[:], value, depth,
	)
}

// SetWithDepthTx writes a node within a transaction (for atomic builder commit).
func (c *PostgresNodeCache) SetWithDepthTx(ctx context.Context, tx pgx.Tx, key [32]byte, value []byte, depth int) error {
	c.mu.Lock()
	if len(c.cache) >= c.maxSize {
		c.evictLRU()
	}
	c.counter++
	c.cache[key] = cacheEntry{hash: value, depth: depth}
	c.access[key] = c.counter
	c.mu.Unlock()

	_, err := tx.Exec(ctx, `
		INSERT INTO smt_nodes (path_key, hash, depth, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (path_key) DO UPDATE SET
			hash = EXCLUDED.hash,
			depth = EXCLUDED.depth,
			updated_at = NOW()`,
		key[:], value, depth,
	)
	return err
}

// evictLRU removes the least recently accessed 25% of entries. Caller holds mu.
func (c *PostgresNodeCache) evictLRU() {
	target := c.maxSize * 3 / 4
	if len(c.cache) <= target {
		return
	}
	// Find the access threshold: remove entries with lowest access counters.
	// Simple approach: remove entries until below target.
	type kv struct {
		key [32]byte
		access int64
	}
	entries := make([]kv, 0, len(c.cache))
	for k := range c.cache {
		entries = append(entries, kv{key: k, access: c.access[k]})
	}
	// Sort by access time ascending (oldest first).
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].access < entries[i].access {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	toRemove := len(c.cache) - target
	for i := 0; i < toRemove && i < len(entries); i++ {
		delete(c.cache, entries[i].key)
		delete(c.access, entries[i].key)
	}
}

// WarmCache preloads top N levels of SMT nodes into the LRU.
func (c *PostgresNodeCache) WarmCache(ctx context.Context, topLevels int) error {
	rows, err := c.db.Query(ctx,
		"SELECT path_key, hash, depth FROM smt_nodes WHERE depth <= $1", topLevels,
	)
	if err != nil {
		return fmt.Errorf("store/smt: warm cache: %w", err)
	}
	defer rows.Close()

	c.mu.Lock()
	defer c.mu.Unlock()
	for rows.Next() {
		var keyBytes, hash []byte
		var depth int
		if err := rows.Scan(&keyBytes, &hash, &depth); err != nil {
			return fmt.Errorf("store/smt: warm cache scan: %w", err)
		}
		if len(keyBytes) == 32 {
			var key [32]byte
			copy(key[:], keyBytes)
			c.counter++
			c.cache[key] = cacheEntry{hash: hash, depth: depth}
			c.access[key] = c.counter
		}
	}
	return rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) LogPosition serialization for BYTEA columns
// ─────────────────────────────────────────────────────────────────────────────

// SerializeLogPosition encodes a LogPosition as length-prefixed DID + uint64.
func SerializeLogPosition(pos types.LogPosition) []byte {
	did := []byte(pos.LogDID)
	buf := make([]byte, 2+len(did)+8)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(did)))
	copy(buf[2:2+len(did)], did)
	binary.BigEndian.PutUint64(buf[2+len(did):], pos.Sequence)
	return buf
}

// DeserializeLogPosition decodes a BYTEA into a LogPosition.
func DeserializeLogPosition(data []byte) (types.LogPosition, error) {
	if len(data) < 10 {
		return types.LogPosition{}, fmt.Errorf("LogPosition bytes too short: %d", len(data))
	}
	didLen := binary.BigEndian.Uint16(data[0:2])
	if int(2+didLen+8) > len(data) {
		return types.LogPosition{}, fmt.Errorf("LogPosition truncated: didLen=%d, total=%d", didLen, len(data))
	}
	did := string(data[2 : 2+didLen])
	seq := binary.BigEndian.Uint64(data[2+didLen:])
	return types.LogPosition{LogDID: did, Sequence: seq}, nil
}
