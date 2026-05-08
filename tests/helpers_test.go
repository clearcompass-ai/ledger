/*
FILE PATH: tests/helpers_test.go

Shared test infrastructure for the ledger integration suite.

Provides:
  - In-memory SDK harness (testHarness) that wraps the SDK builder with
    convenience methods for SMT state inspection.
  - Mock fetcher and schema resolver implementing the SDK builder contracts.
  - Postgres connection/migration helpers gated by ATTESTA_TEST_DSN.
  - Bulk entry generation for determinism and scale tests.
  - SDK v0.1.0 admission helpers — buildStampParams, verifyStampForTest —
    that wrap the post-Wave-1.5 GenerateStamp(StampParams) and
    VerifyStamp(8-arg) APIs so test code stays readable.
*/
package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/admission"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/types"

	opbytestore "github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const testLogDID = "did:attesta:test:integration"

// testEpochWindowSeconds is the epoch length used by HTTP integration tests.
// 1 hour matches the production default (ATTESTA_EPOCH_WINDOW_SECONDS=3600)
// and is wired into testserver_test.go's SubmissionDeps.Admission.
const testEpochWindowSeconds = 3600

// testEpochAcceptanceWindow matches the ledger-side default. window=1
// accepts stamps from [current-1, current+1], tolerating clock skew.
const testEpochAcceptanceWindow = 1

// testEntryBytes is the package-level InMemoryEntryStore shared by all
// Postgres-backed query tests. Reset in cleanTables. This is the ONLY
// source of entry bytes in the test suite (Postgres stores index only).
var testEntryBytes = opbytestore.NewMemory()

// ─────────────────────────────────────────────────────────────────────────────
// Position helpers
// ─────────────────────────────────────────────────────────────────────────────

func pos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: testLogDID, Sequence: seq}
}

func foreignPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:attesta:foreign", Sequence: seq}
}

func ptrTo[T any](v T) *T { return &v }

// ─────────────────────────────────────────────────────────────────────────────
// Authority path helpers
// ─────────────────────────────────────────────────────────────────────────────

func sameSigner() *envelope.AuthorityPath {
	v := envelope.AuthoritySameSigner
	return &v
}

func delegation() *envelope.AuthorityPath {
	v := envelope.AuthorityDelegation
	return &v
}

func scopeAuth() *envelope.AuthorityPath {
	v := envelope.AuthorityScopeAuthority
	return &v
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry construction helpers
// ─────────────────────────────────────────────────────────────────────────────

// synSigner is a deterministic test keypair: a freshly-generated
// secp256k1 keypair plus its did:key:z... identifier. The two are
// always paired so signatures verify cryptographically against the
// admission resolver.
type synSigner struct {
	priv *ecdsa.PrivateKey
	did  string
}

// resolveSyntheticSigner returns a stable keypair for a test label.
// First call for a label generates a fresh did:key; subsequent calls
// return the same keypair. Tests that historically passed
// 'did:example:alice' as a SignerDID get a stable did:key:z... for
// 'alice' that distinguishes them from other labels — fanout
// queries continue to work — and the matching private key is used
// to sign so the signature verifies under the ledger's
// did.NewECDSAKeyResolver (SDK).
//
// The label is used as the cache key verbatim. Tests don't need to
// know whether a label has been seen before; idempotency is
// guaranteed by the cache.
//
// Process-wide cache. Cleared between processes (no test in this
// suite relies on cross-process determinism). Concurrent-safe.
var (
	synSignersMu sync.Mutex
	synSigners   = make(map[string]synSigner)
)

func resolveSyntheticSigner(label string) synSigner {
	synSignersMu.Lock()
	defer synSignersMu.Unlock()
	if s, ok := synSigners[label]; ok {
		return s
	}
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		// Boot-time helper failure — there's no test context to
		// route through; panic here is the only honest signal.
		panic(fmt.Errorf("test/helpers: GenerateDIDKeySecp256k1 for label %q: %w", label, err))
	}
	s := synSigner{priv: kp.PrivateKey, did: kp.DID}
	synSigners[label] = s
	return s
}

// sharedSyntheticSigner returns the keypair backing the empty-label
// bucket. Tests that need an explicit (priv, did) pair for code
// paths that bypass makeEntry (Mode B PoW stamp construction in
// http_integration_test.go, manual entry construction in
// destination_binding_test.go) use this directly.
func sharedSyntheticSigner(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	s := resolveSyntheticSigner("")
	return s.priv, s.did
}

// sharedTestPriv is a backwards-compatibility shim for callers that
// only need the private key. New code should prefer
// sharedSyntheticSigner so the matching did:key is also in scope.
func sharedTestPriv(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, _ := sharedSyntheticSigner(t)
	return priv
}

// makeEntry builds a signed *envelope.Entry suitable for SDK
// builder / SMT / Postgres tests. The signature is structurally
// well-formed (Validate passes; Serialize / EntryIdentity safe)
// but is NOT cryptographically tied to h.SignerDID — the same
// shared keypair signs every entry. Tests that exercise the
// builder's authority-chain logic depend on string comparisons
// over DIDs, so makeEntry preserves h.SignerDID verbatim.
//
// Tests that POST through admission (which DOES verify signatures
// against did:key resolvers) use makeAdmissibleEntry, which
// rewrites h.SignerDID into a real did:key and signs with the
// matching private key.
//
// Defaults:
//
//   - h.Destination defaults to testLogDID when empty.
//   - Signature is produced by sharedSyntheticSigner against the
//     entry's SigningPayload, then assigned to entry.Signatures so
//     Serialize and EntryIdentity become safe to call.
func makeEntry(t *testing.T, h envelope.ControlHeader, payload []byte) *envelope.Entry {
	t.Helper()
	if h.Destination == "" {
		h.Destination = testLogDID
	}
	// EventTime is microseconds since Unix epoch — matches the SDK's
	// exchange/policy.CheckFreshness unit. A zero EventTime causes
	// the ledger to reject the entry as 56-years-stale (Unix epoch).
	if h.EventTime == 0 {
		h.EventTime = time.Now().UTC().UnixMicro()
	}
	entry, err := envelope.NewUnsignedEntry(h, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, sharedTestPriv(t))
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: h.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
	return entry
}

// makeAdmissibleEntry builds a signed entry whose Signatures[0]
// verifies against the ledger's admission DIDResolver. Use this
// for tests that POST through HTTP — `buildWireEntry` and
// destination-binding fixtures.
//
// Behaviour vs makeEntry:
//
//   - h.SignerDID is treated as a label. resolveSyntheticSigner
//     deterministically maps the label to a did:key:z... and a
//     matching keypair. h.SignerDID is rewritten and the signature
//     is produced with the matching key, so admission's
//     ECDSAKeyResolver (from SDK did/) returns the verifying public key.
//   - Tests that distinguish 'alice' from 'bob' continue to do so
//     — different labels yield different did:keys.
func makeAdmissibleEntry(t *testing.T, h envelope.ControlHeader, payload []byte) *envelope.Entry {
	t.Helper()
	if h.Destination == "" {
		h.Destination = testLogDID
	}
	if h.EventTime == 0 {
		h.EventTime = time.Now().UTC().UnixMicro()
	}
	signer := resolveSyntheticSigner(h.SignerDID)
	h.SignerDID = signer.did
	entry, err := envelope.NewUnsignedEntry(h, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, signer.priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: signer.did,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
	return entry
}

func canonicalHashBytes(entry *envelope.Entry) [32]byte {
	id, err := envelope.EntryIdentity(entry)
	if err != nil {
		// helpers_test fixtures construct via NewUnsignedEntry +
		// Validate, so EntryIdentity should never fail here. Panic
		// rather than silently returning the zero hash — a bad
		// fixture must surface loudly during test development.
		panic("canonicalHashBytes: EntryIdentity: " + err.Error())
	}
	return id
}

// mustSerialize is a test-only helper: serialize the entry and
// panic on error. Helpers that construct entries via the
// NewUnsignedEntry → Sign → Validate path can never trigger a
// real Serialize error; treating the error as fatal here keeps
// the existing helper signatures intact.
func mustSerialize(entry *envelope.Entry) []byte {
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		panic("tests: mustSerialize: " + err.Error())
	}
	return canonical
}

// mustEntryIdentity mirrors mustSerialize for EntryIdentity.
func mustEntryIdentity(entry *envelope.Entry) [32]byte {
	id, err := envelope.EntryIdentity(entry)
	if err != nil {
		panic("tests: mustEntryIdentity: " + err.Error())
	}
	return id
}

// ─────────────────────────────────────────────────────────────────────────────
// SDK admission helpers (post-Wave-1.5 API)
// ─────────────────────────────────────────────────────────────────────────────

// currentTestEpoch returns the epoch index the ledger's verifier will
// compute for "now" given testEpochWindowSeconds. Test fixtures must use
// this exact value, otherwise VerifyStamp rejects the stamp as out-of-window.
func currentTestEpoch() uint64 {
	return uint64(time.Now().UTC().Unix() / int64(testEpochWindowSeconds))
}

// buildStampParams constructs the StampParams struct that GenerateStamp
// expects. Keeps test call sites readable instead of repeating six fields.
//
// Caller is responsible for the entry hash, log DID, and difficulty.
// Hash function defaults to SHA-256 (ledger default) and Argon2id params
// to nil. Submitter commit is left absent (Mode B without rate-limit binding).
func buildStampParams(entryHash [32]byte, logDID string, difficulty uint32) admission.StampParams {
	return admission.StampParams{
		EntryHash:  entryHash,
		LogDID:     logDID,
		Difficulty: difficulty,
		HashFunc:   admission.HashSHA256,
		Epoch:      currentTestEpoch(),
	}
}

// verifyStampForTest constructs a types.AdmissionProof from the StampParams
// + nonce and runs VerifyStamp with the test epoch and acceptance window.
// Returns the verification error (or nil on success).
//
// This is the canonical test-side equivalent of the ledger's Step 5
// admission verification — uses ProofFromWire's API form, the same hash
// function, and the same epoch/window the ledger uses at runtime.
func verifyStampForTest(p admission.StampParams, nonce uint64, expectedLog string, minDifficulty uint32) error {
	apiProof := &types.AdmissionProof{
		Mode:            types.AdmissionModeB,
		Nonce:           nonce,
		TargetLog:       p.LogDID,
		Difficulty:      p.Difficulty,
		Epoch:           p.Epoch,
		SubmitterCommit: p.SubmitterCommit,
	}
	return admission.VerifyStamp(
		apiProof,
		p.EntryHash,
		expectedLog,
		minDifficulty,
		p.HashFunc,
		p.Argon2idParams,
		currentTestEpoch(),
		uint64(testEpochAcceptanceWindow),
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// String helpers
// ─────────────────────────────────────────────────────────────────────────────

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func didForUser(i int) string {
	return "did:example:user" + itoa(i)
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock fetcher
// ─────────────────────────────────────────────────────────────────────────────

type mockFetcher struct {
	mu      sync.RWMutex
	entries map[types.LogPosition]*types.EntryWithMetadata
}

func newMockFetcher() *mockFetcher {
	return &mockFetcher{entries: make(map[types.LogPosition]*types.EntryWithMetadata)}
}

func (f *mockFetcher) Fetch(p types.LogPosition) (*types.EntryWithMetadata, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.entries[p], nil
}

func (f *mockFetcher) storeEntry(p types.LogPosition, entry *envelope.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[p] = &types.EntryWithMetadata{
		CanonicalBytes: mustSerialize(entry),
		LogTime:        time.Now(),
		Position:       p,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock schema resolver
// ─────────────────────────────────────────────────────────────────────────────

type mockSchemaResolver struct {
	commutative bool
}

func (r *mockSchemaResolver) Resolve(ref types.LogPosition, fetcher types.EntryFetcher) (*builder.SchemaResolution, error) {
	return &builder.SchemaResolution{
		IsCommutative:   r.commutative,
		DeltaWindowSize: 10,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory test harness (wraps SDK builder with convenience methods)
// ─────────────────────────────────────────────────────────────────────────────

type testHarness struct {
	tree    *smt.Tree
	fetcher *mockFetcher
	schema  builder.SchemaResolver
	buffer  *builder.DeltaWindowBuffer
}

func newHarness() *testHarness {
	return &testHarness{
		tree:    smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache()),
		fetcher: newMockFetcher(),
		buffer:  builder.NewDeltaWindowBuffer(10),
	}
}

// addRootEntity creates a root entity leaf in the SMT and stores the entry.
func (h *testHarness) addRootEntity(t *testing.T, p types.LogPosition, signerDID string) *envelope.Entry {
	t.Helper()
	entry := makeEntry(t, envelope.ControlHeader{
		SignerDID:     signerDID,
		AuthorityPath: sameSigner(),
	}, nil)
	h.fetcher.storeEntry(p, entry)
	key := smt.DeriveKey(p)
	leaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	if err := h.tree.SetLeaf(key, leaf); err != nil {
		t.Fatal(err)
	}
	return entry
}

// addDelegation creates a delegation entry and leaf.
func (h *testHarness) addDelegation(t *testing.T, delegPos types.LogPosition, signerDID, delegateDID string) *envelope.Entry {
	t.Helper()
	entry := makeEntry(t, envelope.ControlHeader{
		SignerDID:     signerDID,
		AuthorityPath: sameSigner(),
		DelegateDID:   &delegateDID,
	}, nil)
	h.fetcher.storeEntry(delegPos, entry)
	key := smt.DeriveKey(delegPos)
	_ = h.tree.SetLeaf(key, types.SMTLeaf{Key: key, OriginTip: delegPos, AuthorityTip: delegPos})
	return entry
}

// addScopeEntity creates a scope entity with an authority set.
func (h *testHarness) addScopeEntity(t *testing.T, p types.LogPosition, signerDID string, authSet map[string]struct{}) *envelope.Entry {
	t.Helper()
	entry := makeEntry(t, envelope.ControlHeader{
		SignerDID:     signerDID,
		AuthorityPath: sameSigner(),
		AuthoritySet:  authSet,
	}, nil)
	h.fetcher.storeEntry(p, entry)
	key := smt.DeriveKey(p)
	_ = h.tree.SetLeaf(key, types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p})
	return entry
}

// process runs a single entry through ProcessBatch.
func (h *testHarness) process(t *testing.T, entry *envelope.Entry, p types.LogPosition) *builder.BatchResult {
	t.Helper()
	h.fetcher.storeEntry(p, entry)
	result, err := builder.ProcessBatch(
		h.tree, []*envelope.Entry{entry}, []types.LogPosition{p},
		h.fetcher, h.schema, testLogDID, h.buffer,
	)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	return result
}

// processBatch runs multiple entries through ProcessBatch.
func (h *testHarness) processBatch(t *testing.T, entries []*envelope.Entry, positions []types.LogPosition) *builder.BatchResult {
	t.Helper()
	for i, entry := range entries {
		h.fetcher.storeEntry(positions[i], entry)
	}
	result, err := builder.ProcessBatch(
		h.tree, entries, positions,
		h.fetcher, h.schema, testLogDID, h.buffer,
	)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	return result
}

func (h *testHarness) leafOriginTip(t *testing.T, p types.LogPosition) types.LogPosition {
	t.Helper()
	leaf, err := h.tree.GetLeaf(smt.DeriveKey(p))
	if err != nil || leaf == nil {
		t.Fatalf("leaf not found for %s", p)
	}
	return leaf.OriginTip
}

func (h *testHarness) leafAuthorityTip(t *testing.T, p types.LogPosition) types.LogPosition {
	t.Helper()
	leaf, err := h.tree.GetLeaf(smt.DeriveKey(p))
	if err != nil || leaf == nil {
		t.Fatalf("leaf not found for %s", p)
	}
	return leaf.AuthorityTip
}

func (h *testHarness) leafExists(t *testing.T, p types.LogPosition) bool {
	t.Helper()
	leaf, err := h.tree.GetLeaf(smt.DeriveKey(p))
	return err == nil && leaf != nil
}

func (h *testHarness) root(t *testing.T) [32]byte {
	t.Helper()
	r, err := h.tree.Root()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ─────────────────────────────────────────────────────────────────────────────
// Bulk entry generation
// ─────────────────────────────────────────────────────────────────────────────

// generateEntries builds n bulk-test entries via makeEntry so each one
// satisfies the Serialize-safety invariant. Takes *testing.T so
// the underlying SignEntry / Validate failures fail the test loudly
// instead of dropping a nil entry into the slice.
func generateEntries(t *testing.T, n int) ([]*envelope.Entry, []types.LogPosition) {
	t.Helper()
	entries := make([]*envelope.Entry, n)
	positions := make([]types.LogPosition, n)
	for i := 0; i < n; i++ {
		var ap *envelope.AuthorityPath
		if i%5 == 0 {
			v := envelope.AuthoritySameSigner
			ap = &v
		}
		entries[i] = makeEntry(t, envelope.ControlHeader{
			SignerDID:     didForUser(i / 10),
			AuthorityPath: ap,
		}, []byte{byte(i)})
		positions[i] = pos(uint64(i + 1))
	}
	return entries, positions
}

// runSDKBuilder runs ProcessBatch against a fresh in-memory tree.
func runSDKBuilder(t *testing.T, entries []*envelope.Entry, positions []types.LogPosition) *builder.BatchResult {
	t.Helper()
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	f := newMockFetcher()
	for i, e := range entries {
		f.storeEntry(positions[i], e)
	}
	result, err := builder.ProcessBatch(tree, entries, positions, f, nil, testLogDID, builder.NewDeltaWindowBuffer(10))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Postgres helpers (for integration tests requiring a real database)
// ─────────────────────────────────────────────────────────────────────────────

// skipIfNoPostgres checks for ATTESTA_TEST_DSN. Returns a pool or skips the test.
// Cleans all tables for isolation.
func skipIfNoPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := connectPostgres(t)
	cleanTables(t, pool)
	t.Cleanup(func() {
		cleanTables(t, pool)
		pool.Close()
	})
	return pool
}

// connectPostgres returns a pool WITHOUT cleaning tables.
// Use for tests that depend on data from a prior test (e.g., QueryIndex after BulkInsert).
func connectPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN not set — skipping Postgres integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping test database: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("run migrations: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func cleanTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	tables := []string{
		"tree_head_sigs", "entry_index", "smt_leaves", "smt_nodes",
		"credits", "tree_heads", "delta_window_buffers",
		"witness_sets", "equivocation_proofs", "sessions",
	}
	for _, table := range tables {
		if _, err := pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			// Table might not exist yet; ignore.
		}
	}
	// Reset sequence.
	// entry_sequence SEQUENCE was dropped in commit 10 (WAL-first
	// admission; Tessera owns sequence allocation now). Tests that
	// seed entries supply seq numbers explicitly via insertTestEntry.

	// Reset package-level entry byte store.
	testEntryBytes = opbytestore.NewMemory()
}

// insertTestEntry directly inserts an entry into Postgres for query testing.
func insertTestEntry(t *testing.T, pool *pgxpool.Pool, seq uint64, entry *envelope.Entry, logDID string) {
	t.Helper()
	ctx := context.Background()
	hash := mustEntryIdentity(entry)
	canonical := mustSerialize(entry)
	logTime := time.Now().UTC()

	var targetRoot, cosigOf, schemaRef []byte
	if entry.Header.TargetRoot != nil {
		targetRoot = store.SerializeLogPosition(*entry.Header.TargetRoot)
	}
	if entry.Header.CosignatureOf != nil {
		cosigOf = store.SerializeLogPosition(*entry.Header.CosignatureOf)
	}
	if entry.Header.SchemaRef != nil {
		schemaRef = store.SerializeLogPosition(*entry.Header.SchemaRef)
	}

	// Index in Postgres (no bytes).
	_, err := pool.Exec(ctx, `
		INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		seq, hash[:], logTime,
		entry.Header.SignerDID,
		targetRoot, cosigOf, schemaRef,
	)
	if err != nil {
		t.Fatalf("insert test entry seq=%d: %v", seq, err)
	}

	// Wire bytes in testEntryBytes (the ONLY source of entry bytes).
	// Wire bytes ARE the canonical bytes under (signatures
	// section embedded inside the canonical form by envelope.Serialize).
	if err := testEntryBytes.WriteEntry(ctx, seq, hash, canonical); err != nil {
		t.Fatalf("write entry bytes seq=%d: %v", seq, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON payload helpers
// ─────────────────────────────────────────────────────────────────────────────

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Suppress unused import warnings
// ─────────────────────────────────────────────────────────────────────────────

var _ = fmt.Sprintf

// ─────────────────────────────────────────────────────────────────────────────
// Real-GCS gating for integration tests
// ─────────────────────────────────────────────────────────────────────────────

// requireRealGCS returns a real-GCS-backed bytestore.Backend for
// integration tests that exercise the full byte-storage path. The
// integration suite is REAL-GCS-ONLY — fake-gcs-server is rejected.
//
// Resolution chain (matches bytestore.NewGCS production path):
//
//  1. ATTESTA_TEST_GCS_BUCKET — required. Skip the test if unset.
//  2. ATTESTA_TEST_GCS_ENDPOINT — must be EMPTY. The integration
//     suite refuses fake-gcs to keep production behavior pinned
//     (presigned URLs, V4 signing, ADC chain). Set the variable
//     to fail the test loudly.
//  3. ADC chain (in priority order):
//     a. GOOGLE_APPLICATION_CREDENTIALS — service-account key file
//     b. gcloud application-default login (developer workstation)
//     c. Workload Identity (GKE / Cloud Run / GCE metadata server)
//
// The bucket must grant the test identity:
//
//   - storage.objects.create
//   - storage.objects.get
//   - storage.objects.list
//   - storage.objects.delete
//
// On any wiring failure, the test fails (NOT skips) so a broken
// CI configuration doesn't silently turn into a green build.
func requireRealGCS(t *testing.T) opbytestore.Backend {
	t.Helper()

	bucket := os.Getenv("ATTESTA_TEST_GCS_BUCKET")
	if bucket == "" {
		t.Skip("ATTESTA_TEST_GCS_BUCKET unset; integration suite skipped")
	}

	if endpoint := os.Getenv("ATTESTA_TEST_GCS_ENDPOINT"); endpoint != "" {
		t.Fatalf(
			"integration suite refuses fake-gcs (ATTESTA_TEST_GCS_ENDPOINT=%q). "+
				"Real-GCS only — point ATTESTA_TEST_GCS_BUCKET at a real bucket "+
				"and rely on ADC / Workload Identity for credentials.", endpoint,
		)
	}

	store, err := opbytestore.NewFromConfig(context.Background(), opbytestore.Config{
		Backend: "gcs",
		Bucket:  bucket,
		// No GCSEndpoint, no GCSAnonymous → ADC default chain.
	})
	if err != nil {
		t.Fatalf("requireRealGCS: bytestore.NewFromConfig: %v "+
			"(ADC credentials unavailable? ensure GOOGLE_APPLICATION_CREDENTIALS, "+
			"gcloud application-default login, or Workload Identity is configured)", err)
	}
	// Backend impls handle their own connection lifetime; no Close
	// method exists on the interface.
	return store
}
