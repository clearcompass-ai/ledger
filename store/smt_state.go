/*
FILE PATH: store/smt_state.go

Postgres-backed implementations of the v0.3.0 SDK's smt.LeafStore and
smt.NodeStore interfaces.

# KEY ARCHITECTURAL DECISIONS

  - PostgresLeafStore: every interface method takes ctx (Tier 1.3 of
    the v0.2.0 SDK migration, preserved in v0.3.0). SetTx remains for
    atomic builder commits.

  - PostgresNodeStore: content-addressed persistence for Jellyfish
    nodes. The SDK's smt.NodeStore interface is ctx-free by design
    (proof replay must never block on a remote cache lookup — per
    the upstream comment). Postgres reads inside Get still need a
    context for shutdown cancellation; we keep a process-lifetime
    ctx field on the store, set at construction.

  - Generously-sized in-memory LRU on top of Postgres. The LRU is
    load-bearing for the N+1-query read path, not optional: tree
    traversal heavily skews to the top nodes, and a hot LRU absorbs
    those reads so the connection pool is not saturated. Default
    capacity is 1M nodes (~50 MB at ~50 B / node).

  - LogPosition serialization: length-prefixed DID + uint64, matching
    the SDK's canonical serialization.

# INVARIANTS

  - After builder atomic commit, smt_leaves and jellyfish_nodes are
    consistent: every node referenced by smt_root_state.current_root
    is present in jellyfish_nodes; every leaf reachable from the root
    is present in smt_leaves.

  - LRU eviction is true LRU (oldest-accessed first), not random.

# GC

  jellyfish_nodes is content-addressed and structurally immortal. No
  time-based eviction; the table has no created_at column. If pruning
  is ever needed it MUST be a mark-and-sweep walk rooted at the live
  tree heads, never a time predicate. See migrations/0003 for the
  rationale.
*/
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) PostgresLeafStore — implements sdk smt.LeafStore
// ─────────────────────────────────────────────────────────────────────────────

// PostgresLeafStore persists SMT leaves in Postgres.
// Supports transactional writes for atomic builder commits via SetTx.
type PostgresLeafStore struct {
	db *pgxpool.Pool
}

// NewPostgresLeafStore creates a leaf store. Per-call ctx is supplied
// via the SDK's smt.LeafStore interface methods.
func NewPostgresLeafStore(db *pgxpool.Pool) *PostgresLeafStore {
	return &PostgresLeafStore{db: db}
}

// Get reads a leaf by key. Returns nil if not found.
func (s *PostgresLeafStore) Get(ctx context.Context, key [32]byte) (*types.SMTLeaf, error) {
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
func (s *PostgresLeafStore) Set(ctx context.Context, key [32]byte, leaf types.SMTLeaf) error {
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
func (s *PostgresLeafStore) SetBatch(ctx context.Context, leaves []types.SMTLeaf) error {
	if len(leaves) == 0 {
		return nil
	}

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

	br := s.db.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()

	if _, err := br.Exec(); err != nil {
		return fmt.Errorf("store/smt: set batch: %w", err)
	}
	return nil
}

// Delete removes a leaf.
func (s *PostgresLeafStore) Delete(ctx context.Context, key [32]byte) error {
	_, err := s.db.Exec(ctx, "DELETE FROM smt_leaves WHERE leaf_key = $1", key[:])
	if err != nil {
		return fmt.Errorf("store/smt: delete leaf: %w", err)
	}
	return nil
}

// Count returns the total number of SMT leaves.
func (s *PostgresLeafStore) Count(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, "SELECT COUNT(*) FROM smt_leaves").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store/smt: count leaves: %w", err)
	}
	return count, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) PostgresNodeStore — implements sdk smt.NodeStore
// ─────────────────────────────────────────────────────────────────────────────

// PostgresNodeStoreDefaultLRUSize is the default in-memory LRU
// capacity used when the caller doesn't supply one. 1 048 576 entries
// at ~50 B/node ≈ 50 MB of resident set.
//
// Tree traversal heavily skews to the top nodes, so a hot LRU of this
// size absorbs effectively all read traffic for the top 20 levels
// (2^20 ≈ 1M nodes), dropping per-request PG queries from ~depth to
// the handful of deep-node misses. The LRU is the physical circuit
// breaker for the connection pool — sizing it generously is
// load-bearing, not an optimisation.
const PostgresNodeStoreDefaultLRUSize = 1_048_576

// PostgresNodeStore implements the v0.3.0 SDK's smt.NodeStore over
// Postgres + an in-memory LRU. The store is content-addressed: Put
// inserts by hash (INSERT ON CONFLICT DO NOTHING — no UPSERTs, no
// write amplification beyond the single row), Get reads by hash.
//
// The SDK's smt.NodeStore interface is intentionally ctx-free: proof
// replay must never block on a remote cache lookup. The store still
// needs a context for Postgres I/O on a cache miss; we hold a
// process-lifetime ctx field set at construction. SIGTERM cancels
// in-flight queries.
type PostgresNodeStore struct {
	db *pgxpool.Pool

	mu      sync.RWMutex
	cache   map[[32]byte]smt.Node
	access  map[[32]byte]int64
	counter int64
	maxSize int

	// ctx is bound at construction. The smt.NodeStore interface
	// methods are ctx-free; the only consumer of this field is the
	// Postgres read inside Get on cache miss.
	ctx context.Context
}

// NewPostgresNodeStore creates a content-addressed node store with the
// given LRU capacity. If maxSize <= 0 the default (1M entries) is
// used. ctx is the process-lifetime context for in-flight Postgres
// reads on cache miss.
func NewPostgresNodeStore(ctx context.Context, db *pgxpool.Pool, maxSize int) *PostgresNodeStore {
	if maxSize <= 0 {
		maxSize = PostgresNodeStoreDefaultLRUSize
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &PostgresNodeStore{
		db:      db,
		cache:   make(map[[32]byte]smt.Node, 1024),
		access:  make(map[[32]byte]int64, 1024),
		maxSize: maxSize,
		ctx:     ctx,
	}
}

// Get returns the node at hash, or (nil, nil) for misses and for the
// canonical EmptyHash. Reads consult the LRU first; on miss, a
// Postgres SELECT loads the payload and the LRU is populated for
// future hits.
//
// The returned smt.Node is the stored instance — callers must not
// mutate fields. The Jellyfish nodes returned by DecodeNode are
// already immutable from the SDK's perspective (cryptographically
// content-addressed), but defensive coders should treat them as
// read-only regardless.
func (s *PostgresNodeStore) Get(hash [32]byte) (smt.Node, error) {
	if hash == smt.EmptyHash {
		return nil, nil
	}

	// Fast path: LRU hit.
	s.mu.RLock()
	cached, ok := s.cache[hash]
	s.mu.RUnlock()
	if ok {
		s.mu.Lock()
		s.counter++
		s.access[hash] = s.counter
		s.mu.Unlock()
		return cached, nil
	}

	// Slow path: Postgres read.
	var payload []byte
	err := s.db.QueryRow(s.ctx,
		"SELECT payload FROM jellyfish_nodes WHERE node_hash = $1",
		hash[:],
	).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/smt: get node %x: %w", hash[:8], err)
	}

	node, err := smt.DecodeNode(payload)
	if err != nil {
		return nil, fmt.Errorf("store/smt: decode node %x: %w", hash[:8], err)
	}

	s.mu.Lock()
	s.cachePutLocked(hash, node)
	s.mu.Unlock()
	return node, nil
}

// Put stores a node. The hash is computed from the node's content
// (smt.HashNode); duplicate Puts (same hash) are no-ops — exactly
// what content-addressing requires.
//
// Put writes through to Postgres via INSERT ON CONFLICT DO NOTHING.
// Use PutTx inside the builder's atomic commit; this non-transactional
// Put is for non-critical paths (e.g., ledger-reader warmup).
func (s *PostgresNodeStore) Put(node smt.Node) ([32]byte, error) {
	if node == nil {
		return [32]byte{}, errors.New("store/smt: cannot store nil node")
	}
	hash := smt.HashNode(node)

	// Promote to LRU regardless of whether PG already had it.
	s.mu.Lock()
	s.cachePutLocked(hash, node)
	s.mu.Unlock()

	_, err := s.db.Exec(s.ctx, `
		INSERT INTO jellyfish_nodes (node_hash, payload)
		VALUES ($1, $2)
		ON CONFLICT (node_hash) DO NOTHING`,
		hash[:], node.Serialize(),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("store/smt: put node %x: %w", hash[:8], err)
	}
	return hash, nil
}

// PutTx stores a node inside the supplied transaction. The builder
// loop uses this to atomically commit all dirty nodes from a batch
// alongside the leaves, the cursor, and the SMT root.
//
// Returns the canonical hash so the caller can reference the node
// from a parent without re-hashing.
func (s *PostgresNodeStore) PutTx(ctx context.Context, tx pgx.Tx, node smt.Node) ([32]byte, error) {
	if node == nil {
		return [32]byte{}, errors.New("store/smt: cannot store nil node")
	}
	hash := smt.HashNode(node)

	s.mu.Lock()
	s.cachePutLocked(hash, node)
	s.mu.Unlock()

	_, err := tx.Exec(ctx, `
		INSERT INTO jellyfish_nodes (node_hash, payload)
		VALUES ($1, $2)
		ON CONFLICT (node_hash) DO NOTHING`,
		hash[:], node.Serialize(),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("store/smt: put node tx %x: %w", hash[:8], err)
	}
	return hash, nil
}

// cachePutLocked inserts/updates the LRU. Caller MUST hold s.mu.
func (s *PostgresNodeStore) cachePutLocked(hash [32]byte, node smt.Node) {
	if _, present := s.cache[hash]; !present && len(s.cache) >= s.maxSize {
		s.evictLRULocked()
	}
	s.counter++
	s.cache[hash] = node
	s.access[hash] = s.counter
}

// evictLRULocked drops the least-recently-accessed 25% of entries
// when the cache hits its capacity. Caller MUST hold s.mu.
//
// The eviction sweep is O(N log N) due to the sort, but only happens
// when the cache is full; amortised over (maxSize/4) Puts the cost
// is sub-microsecond per Put even at maxSize = 1M.
func (s *PostgresNodeStore) evictLRULocked() {
	target := s.maxSize * 3 / 4
	if len(s.cache) <= target {
		return
	}
	type kv struct {
		key    [32]byte
		access int64
	}
	entries := make([]kv, 0, len(s.cache))
	for k := range s.cache {
		entries = append(entries, kv{key: k, access: s.access[k]})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].access < entries[j].access
	})
	toRemove := len(s.cache) - target
	for i := 0; i < toRemove && i < len(entries); i++ {
		delete(s.cache, entries[i].key)
		delete(s.access, entries[i].key)
	}
}

// Len returns the current LRU occupancy. Diagnostic/test use only.
func (s *PostgresNodeStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cache)
}

// WarmFromRecent preloads the LRU with up to N recently-inserted
// nodes from the table. Called on builder startup so the first batch
// after restart doesn't pay a full cold-cache penalty on every Get.
//
// "Recent" is approximated by inserting order in the absence of a
// created_at column (a deliberate omission — see migrations/0003 on
// why time-based metadata cannot live on jellyfish_nodes). The query
// reads the first N rows by ctid (physical row order), which is a
// reasonable approximation of recency on an append-mostly table.
//
// This is best-effort: failures are logged by the caller; the SDK's
// NodeStore.Get path always falls back to a Postgres miss read.
func (s *PostgresNodeStore) WarmFromRecent(ctx context.Context, limit int) error {
	if limit <= 0 {
		return nil
	}
	rows, err := s.db.Query(ctx,
		"SELECT node_hash, payload FROM jellyfish_nodes ORDER BY ctid DESC LIMIT $1",
		limit,
	)
	if err != nil {
		return fmt.Errorf("store/smt: warm cache: %w", err)
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var keyBytes, payload []byte
		if err := rows.Scan(&keyBytes, &payload); err != nil {
			return fmt.Errorf("store/smt: warm cache scan: %w", err)
		}
		if len(keyBytes) != 32 {
			continue
		}
		node, err := smt.DecodeNode(payload)
		if err != nil {
			continue
		}
		var hash [32]byte
		copy(hash[:], keyBytes)
		s.cachePutLocked(hash, node)
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
