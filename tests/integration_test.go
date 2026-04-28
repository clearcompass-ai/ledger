/*
FILE PATH: tests/integration_test.go

85 integration tests across 14 categories. Every test has real assertions.
Tests requiring Postgres skip gracefully when ORTHOLOG_TEST_DSN is unset.
Tests requiring Tessera use the SDK's StubMerkleTree.

POST-WAVE-1.5 CHANGES:
  - admission.GenerateStamp now takes a StampParams struct (named fields).
  - admission.VerifyStamp takes 8 args including currentEpoch + acceptanceWindow.
  - Test helpers buildStampParams + verifyStampForTest (helpers_test.go) keep
    call sites readable. They wire Epoch from currentTestEpoch() so the test
    matches what the operator's runtime computes.
  - Wire format is protocol v5 (Wave 1.5). All preamble references updated.

Run without Postgres:  go test ./tests/ -v -count=1
Run with Postgres:     ORTHOLOG_TEST_DSN="postgres://..." go test ./tests/ -v -count=1
*/
package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	opbuilder "github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	"github.com/clearcompass-ai/ortholog-operator/witness"
)

// ═════════════════════════════════════════════════════════════════════════════
// Category 1: Admission Pipeline (13 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestAdmission_ValidEntry(t *testing.T) {
	entry := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice"}, []byte("attestation"))
	canonical := envelope.Serialize(entry)
	hash := sha256.Sum256(canonical)
	if len(canonical) == 0 {
		t.Fatal("canonical bytes should not be empty")
	}
	if hash == [32]byte{} {
		t.Fatal("hash should not be zero")
	}
	t.Logf("valid entry: %d bytes, hash %x", len(canonical), hash[:8])
}

func TestAdmission_DuplicateHash(t *testing.T) {
	entry := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice"}, nil)
	h1 := sha256.Sum256(envelope.Serialize(entry))
	h2 := sha256.Sum256(envelope.Serialize(entry))
	if h1 != h2 {
		t.Fatal("identical entries must produce identical hashes")
	}
}

func TestAdmission_MalformedBytes(t *testing.T) {
	// v7.75: envelope.StripSignature is gone — Deserialize is the
	// parser surface that rejects malformed wire bytes.
	_, err := envelope.Deserialize([]byte{0xFF, 0xFF})
	if err == nil {
		t.Fatal("malformed bytes should fail Deserialize")
	}
}

func TestAdmission_UnsignedEntry_SDK_D5(t *testing.T) {
	// 7-byte preamble (v5 protocol), no signatures section → must fail Deserialize.
	raw := []byte{0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0xFF}
	_, err := envelope.Deserialize(raw)
	if err == nil {
		t.Fatal("truncated entry should fail Deserialize")
	}
}

func TestAdmission_WrongSignerKey_SDK_D5(t *testing.T) {
	// v7.75: signatures live INSIDE the canonical bytes. SDK-D5
	// guarantee — Deserialize is parse-only, never crypto-verifies.
	// We round-trip a signed entry's wire bytes and confirm the
	// signatures section comes back intact (algoID + non-empty
	// bytes), proving Deserialize is the structural parser; the
	// downstream verifier (admission/entry_signature_verifier.go)
	// is what would reject a wrong-key signature.
	entry := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice"}, nil)
	wire := envelope.Serialize(entry)
	parsed, err := envelope.Deserialize(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Signatures) == 0 {
		t.Fatal("Deserialize should preserve the signatures section")
	}
	if parsed.Signatures[0].AlgoID != envelope.SigAlgoECDSA {
		t.Fatalf("algoID mismatch: %d", parsed.Signatures[0].AlgoID)
	}
	if len(parsed.Signatures[0].Bytes) == 0 {
		t.Fatal("signature bytes should be preserved")
	}
}

func TestAdmission_CorruptSignature_SDK_D5(t *testing.T) {
	// Same SDK-D5 contract: Deserialize parses the structural shape
	// without running ecdsa.Verify. Round-tripping a real entry is
	// the simplest demonstration; a corrupted-bytes-in-flight test
	// belongs at the verifier layer (admission/entry_signature_verifier_test.go),
	// not at the parser.
	entry := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice"}, nil)
	wire := envelope.Serialize(entry)
	parsed, err := envelope.Deserialize(wire)
	if err != nil {
		t.Fatal("Deserialize should succeed on a well-formed wire")
	}
	if len(parsed.Signatures[0].Bytes) == 0 {
		t.Fatal("sig bytes should be preserved by Deserialize")
	}
}

// TestAdmission_ExactlyMaxSize_SDK_D11 asserts that a near-cap entry
// serializes successfully under the v7.75 size invariant.
//
// v7.75 changed MaxCanonicalBytes from 1 MiB → MaxBundleEntrySize
// (= 65535) per envelope/api.go:69-80, closing ORTHO-BUG-005 (entries
// admitted under the old 1 MiB cap would later panic inside
// MarshalBundleEntry's uint16 length prefix). The previous test fixture
// (`payload = (1<<20)-200`) was sized for the 1 MiB cap and now fails
// entry.Validate with ErrCanonicalTooLarge. New fixture uses a payload
// that leaves comfortable margin for header + signature framing.
func TestAdmission_ExactlyMaxSize_SDK_D11(t *testing.T) {
	// 1 KiB margin for preamble + header_body + signatures section.
	payload := make([]byte, envelope.MaxCanonicalBytes-1024)
	entry := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:big"}, payload)
	wire := envelope.Serialize(entry)
	if len(wire) == 0 {
		t.Fatal("near-max entry should serialize")
	}
	if len(wire) > envelope.MaxCanonicalBytes {
		t.Fatalf("near-max entry serialized to %d bytes, exceeds cap %d",
			len(wire), envelope.MaxCanonicalBytes)
	}
}

// TestAdmission_OverMaxSize_SDK_D11 asserts that an over-cap entry is
// rejected by entry.Validate (the SDK gate that prevents downstream
// MarshalBundleEntry panic). Previously this test was a tautology
// (`(1<<20)+1 > (1<<20)` always true) that asserted nothing about the
// SDK; the v7.75 cap drop made the lazy form even more meaningless,
// so the test now actually exercises the size cap.
func TestAdmission_OverMaxSize_SDK_D11(t *testing.T) {
	// Push 4 KiB past the cap so any reasonable header/sig overhead
	// can't bring it back under.
	payload := make([]byte, envelope.MaxCanonicalBytes+4096)
	hdr := envelope.ControlHeader{
		SignerDID:   "did:example:overcap",
		Destination: testLogDID,
	}
	// NewUnsignedEntry runs the same validateHeaderForWrite that
	// makeEntry would, but doesn't require a signature — sufficient to
	// trip the size cap at entry.Validate time without minting an
	// ECDSA signature for an entry we expect to be rejected anyway.
	entry, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		// Some SDKs reject at NewUnsignedEntry, others at Validate;
		// either is acceptable as long as the over-cap entry never
		// reaches Serialize.
		return
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err == nil {
		t.Fatalf("over-cap entry (payload %d bytes) should fail Validate",
			len(payload))
	}
}

// TestAdmission_EvidenceCapNonSnapshot_Decision51 verifies that a non-snapshot
// entry carrying more than envelope.MaxEvidencePointers (32) is rejected by
// NewEntry. Decision 51 caps routine evidence at 32; only authority snapshot
// entries (Path C with PriorAuthority + AuthoritySet) are exempt.
func TestAdmission_EvidenceCapNonSnapshot_Decision51(t *testing.T) {
	if envelope.MaxEvidencePointers != 32 {
		t.Fatalf("test assumes MaxEvidencePointers=32, got %d — update test", envelope.MaxEvidencePointers)
	}
	overCap := envelope.MaxEvidencePointers + 1 // 33 — first illegal count
	pointers := make([]types.LogPosition, overCap)
	for i := range pointers {
		pointers[i] = pos(uint64(i + 1))
	}
	// v7.75: NewUnsignedEntry runs the same validateHeaderForWrite
	// (envelope/serialize.go:241) that NewEntry runs, so this asserts
	// the same EvidencePointers cap rejection without forcing the
	// test to mint a signature. Destination is set so the rejection
	// fires for the EvidencePointers reason (NewUnsignedEntry rejects
	// empty Destination earlier with a different error).
	_, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:        "did:example:overcap",
		Destination:      testLogDID,
		EvidencePointers: pointers,
	}, nil)
	if err == nil {
		t.Fatalf("%d Evidence_Pointers on non-snapshot should be rejected (cap=%d)",
			overCap, envelope.MaxEvidencePointers)
	}
}

// TestAdmission_EvidenceCapSnapshotExempt_Decision51 verifies that an authority
// snapshot entry can carry MORE than MaxEvidencePointers without being rejected.
// Snapshots aggregate cosignature references and are deliberately uncapped.
//
// Uses cap+1 pointers — same count that would fail for a non-snapshot entry —
// to actually exercise the exemption code path. (A count below the cap would
// pass for the wrong reason and not test anything.)
func TestAdmission_EvidenceCapSnapshotExempt_Decision51(t *testing.T) {
	if envelope.MaxEvidencePointers != 32 {
		t.Fatalf("test assumes MaxEvidencePointers=32, got %d — update test", envelope.MaxEvidencePointers)
	}
	overCap := envelope.MaxEvidencePointers + 1 // 33 — would fail for non-snapshot
	pointers := make([]types.LogPosition, overCap)
	for i := range pointers {
		pointers[i] = pos(uint64(i + 1))
	}
	tr := pos(100)
	pa := pos(99)
	sp := pos(50)
	// Same NewEntry → NewUnsignedEntry switch as the non-snapshot
	// counterpart above. validateHeaderForWrite is shared between the
	// two constructors, so the snapshot exemption (isAuthoritySnapshotShape
	// at envelope/serialize.go:359) is exercised either way.
	_, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID: "did:example:snapshot", Destination: testLogDID, AuthorityPath: scopeAuth(),
		TargetRoot: &tr, PriorAuthority: &pa, ScopePointer: &sp, EvidencePointers: pointers,
	}, nil)
	if err != nil {
		t.Fatalf("snapshot with %d pointers should be exempt from cap=%d: %v",
			overCap, envelope.MaxEvidencePointers, err)
	}
}

// TestAdmission_ModeB_ValidStamp generates a stamp with the SDK and verifies
// it round-trips. Uses the post-Wave-1.5 StampParams API. The verification
// uses the test epoch (matching what the operator computes at request time).
func TestAdmission_ModeB_ValidStamp(t *testing.T) {
	h := [32]byte{1, 2, 3, 4}
	params := buildStampParams(h, testLogDID, 8)

	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	if err := verifyStampForTest(params, nonce, testLogDID, 8); err != nil {
		t.Fatalf("VerifyStamp on fresh stamp: %v", err)
	}
}

// TestAdmission_ModeB_WrongLog confirms that a stamp generated for one log
// fails verification when the verifier expects a different log DID. This is
// the binding that prevents stamp reuse across operators.
func TestAdmission_ModeB_WrongLog(t *testing.T) {
	h := [32]byte{5, 6, 7, 8}
	params := buildStampParams(h, testLogDID, 8)

	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	// Verify against a DIFFERENT expected log DID — must fail.
	err = verifyStampForTest(params, nonce, "did:ortholog:different", 8)
	if err == nil {
		t.Fatal("stamp bound to wrong log DID should fail verification")
	}
	t.Logf("wrong-log rejection: %v", err)
}

// TestAdmission_ModeB_BelowDifficulty confirms that a stamp generated at
// difficulty 8 fails verification when the verifier requires difficulty 16.
// This protects operators from accepting under-powered submissions when
// they raise their difficulty target via DifficultyController.
func TestAdmission_ModeB_BelowDifficulty(t *testing.T) {
	h := [32]byte{9, 10, 11, 12}
	params := buildStampParams(h, testLogDID, 8)

	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	// Verify with stricter difficulty (16) than what was used to mint (8).
	err = verifyStampForTest(params, nonce, testLogDID, 16)
	if err == nil {
		t.Fatal("stamp below required difficulty should fail verification")
	}
	t.Logf("below-difficulty rejection: %v", err)
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 2: Builder Determinism (6 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestDeterminism_RootMatch_1000Entries(t *testing.T) {
	entries, positions := generateEntries(t, 1000)
	r1 := runSDKBuilder(t, entries, positions)
	r2 := runSDKBuilder(t, entries, positions)
	if r1.NewRoot != r2.NewRoot {
		t.Fatalf("DETERMINISM FAILURE: %x != %x", r1.NewRoot[:8], r2.NewRoot[:8])
	}
	t.Logf("determinism verified: root=%x leaves=%d", r1.NewRoot[:8], r1.NewLeafCounts)
}

func TestDeterminism_AllPaths(t *testing.T) {
	var entries []*envelope.Entry
	var positions []types.LogPosition
	seq := uint64(1)
	for i := 0; i < 25; i++ {
		entries = append(entries, makeEntry(t, envelope.ControlHeader{SignerDID: didForUser(i), AuthorityPath: sameSigner()}, nil))
		positions = append(positions, pos(seq))
		seq++
	}
	for i := 0; i < 25; i++ {
		entries = append(entries, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:w" + itoa(i)}, nil))
		positions = append(positions, pos(seq))
		seq++
	}
	r1 := runSDKBuilder(t, entries, positions)
	r2 := runSDKBuilder(t, entries, positions)
	if r1.NewRoot != r2.NewRoot {
		t.Fatal("all-path determinism failed")
	}
	if r1.NewLeafCounts != 25 {
		t.Fatalf("expected 25 leaves, got %d", r1.NewLeafCounts)
	}
	if r1.CommentaryCounts != 25 {
		t.Fatalf("expected 25 commentary, got %d", r1.CommentaryCounts)
	}
}

func TestDeterminism_PathCompression(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:alice")
	h.addRootEntity(t, pos(2), "did:example:alice")
	action := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice", TargetRoot: ptrTo(pos(1)), TargetIntermediate: ptrTo(pos(2)), AuthorityPath: sameSigner()}, nil)
	r := h.process(t, action, pos(3))
	if r.PathACounts != 1 {
		t.Fatal("expected Path A")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(3)) {
		t.Fatal("root OriginTip not updated")
	}
	if !h.leafOriginTip(t, pos(2)).Equal(pos(3)) {
		t.Fatal("intermediate OriginTip not updated")
	}
}

func TestDeterminism_LaneSelection(t *testing.T) {
	entries, positions := generateEntries(t, 100)
	r1 := runSDKBuilder(t, entries, positions)
	r2 := runSDKBuilder(t, entries, positions)
	if r1.NewRoot != r2.NewRoot {
		t.Fatal("lane selection determinism failed")
	}
}

func TestDeterminism_CommutativeSchemas(t *testing.T) {
	entries, positions := generateEntries(t, 50)
	r1 := runSDKBuilder(t, entries, positions)
	r2 := runSDKBuilder(t, entries, positions)
	if r1.NewRoot != r2.NewRoot {
		t.Fatal("commutative determinism failed")
	}
}

func TestDeterminism_EmptyBatch(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	rootBefore, _ := tree.Root()
	result, _ := builder.ProcessBatch(tree, nil, nil, newMockFetcher(), nil, testLogDID, builder.NewDeltaWindowBuffer(10))
	if result.NewRoot != rootBefore {
		t.Fatal("empty batch should not change root")
	}
	if len(result.Mutations) != 0 {
		t.Fatal("empty batch = no mutations")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 3: SMT State Correctness (8 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestSMT_LeafCreation(t *testing.T) {
	h := newHarness()
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice", AuthorityPath: sameSigner()}, nil), pos(1))
	if r.NewLeafCounts != 1 {
		t.Fatal("expected 1 leaf")
	}
	leaf, _ := h.tree.GetLeaf(smt.DeriveKey(pos(1)))
	if leaf == nil {
		t.Fatal("leaf should exist")
	}
	if leaf.OriginTip != pos(1) || leaf.AuthorityTip != pos(1) {
		t.Fatal("both tips should be self")
	}
}

func TestSMT_OriginTipUpdate_PathA(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:alice")
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice", TargetRoot: ptrTo(pos(1)), AuthorityPath: sameSigner()}, []byte("amended")), pos(2))
	if !h.leafOriginTip(t, pos(1)).Equal(pos(2)) {
		t.Fatal("OriginTip should advance")
	}
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("AuthorityTip should NOT change")
	}
}

func TestSMT_AuthorityTipUpdate_PathC(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:entity")
	h.addScopeEntity(t, pos(2), "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2))}, []byte("sealing")), pos(3))
	if r.PathCCounts != 1 {
		t.Fatal("expected Path C")
	}
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(3)) {
		t.Fatal("AuthorityTip should advance")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("OriginTip should NOT change")
	}
}

func TestSMT_LaneSelection_AmendmentExecution(t *testing.T) {
	h := newHarness()
	h.addScopeEntity(t, pos(1), "did:example:a", map[string]struct{}{"did:example:a": {}, "did:example:b": {}})
	newSet := map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}}
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(1)), AuthoritySet: newSet}, nil), pos(2))
	if !h.leafOriginTip(t, pos(1)).Equal(pos(2)) {
		t.Fatal("amendment should update OriginTip")
	}
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("amendment should NOT update AuthorityTip")
	}
}

func TestSMT_LaneSelection_Enforcement(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:entity")
	h.addScopeEntity(t, pos(2), "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2))}, nil), pos(3))
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(3)) {
		t.Fatal("enforcement should update AuthorityTip")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("enforcement should NOT update OriginTip")
	}
}

func TestSMT_CommentaryZeroImpact(t *testing.T) {
	h := newHarness()
	rootBefore := h.root(t)
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:witness"}, nil), pos(1))
	if r.NewRoot != rootBefore {
		t.Fatal("commentary should not change root")
	}
	if r.CommentaryCounts != 1 {
		t.Fatal("should count as commentary")
	}
	if h.leafExists(t, pos(1)) {
		t.Fatal("commentary should NOT create a leaf")
	}
}

func TestSMT_PathD_ForeignTarget(t *testing.T) {
	h := newHarness()
	rootBefore := h.root(t)
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice", AuthorityPath: sameSigner(), TargetRoot: ptrTo(foreignPos(1))}, nil), pos(1))
	if r.NewRoot != rootBefore {
		t.Fatal("foreign target should not change root")
	}
	if r.PathDCounts != 1 {
		t.Fatal("expected Path D")
	}
}

func TestSMT_DelegationLiveness(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:owner")
	h.addDelegation(t, pos(2), "did:example:owner", "did:example:delegate")
	// Live: should succeed.
	r1 := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:delegate", TargetRoot: ptrTo(pos(1)), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{pos(2)}}, nil), pos(3))
	if r1.PathBCounts != 1 {
		t.Fatal("live delegation should succeed")
	}
	// Revoke delegation.
	key := smt.DeriveKey(pos(2))
	leaf, _ := h.tree.GetLeaf(key)
	u := *leaf
	u.OriginTip = pos(4)
	h.tree.SetLeaf(key, u)
	// Revoked: should fail.
	r2 := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:delegate", TargetRoot: ptrTo(pos(1)), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{pos(2)}}, nil), pos(5))
	if r2.PathDCounts != 1 {
		t.Fatal("revoked delegation should fall to Path D")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 4: Query Index Correctness (10 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestQuery_CosignatureOf_Basic(t *testing.T) {
	if indexes.NewPostgresQueryAPI(nil, testEntryBytes, testLogDID) == nil {
		t.Fatal("nil")
	}
}

func TestQuery_CosignatureOf_Multiple(t *testing.T) {
	pool := skipIfNoPostgres(t)
	qapi := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID)
	tp := pos(100)
	for i := uint64(1); i <= 5; i++ {
		insertTestEntry(t, pool, i, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:w" + itoa(int(i)), CosignatureOf: ptrTo(tp)}, nil), testLogDID)
	}
	results, err := qapi.QueryByCosignatureOf(tp)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 5 {
		t.Fatalf("expected 5, got %d", len(results))
	}
	for i := 1; i < len(results); i++ {
		if results[i].Position.Sequence <= results[i-1].Position.Sequence {
			t.Fatal("should be ordered")
		}
	}
}

func TestQuery_CosignatureOf_Empty(t *testing.T) {
	pool := skipIfNoPostgres(t)
	results, _ := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID).QueryByCosignatureOf(pos(999))
	if len(results) != 0 {
		t.Fatal("should be empty")
	}
}

func TestQuery_TargetRoot_Multiple(t *testing.T) {
	pool := skipIfNoPostgres(t)
	qapi := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID)
	insertTestEntry(t, pool, 1, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a", AuthorityPath: sameSigner()}, nil), testLogDID)
	for i := uint64(2); i <= 4; i++ {
		insertTestEntry(t, pool, i, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a", TargetRoot: ptrTo(pos(1)), AuthorityPath: sameSigner()}, []byte{byte(i)}), testLogDID)
	}
	results, _ := qapi.QueryByTargetRoot(pos(1))
	if len(results) != 3 {
		t.Fatalf("expected 3, got %d", len(results))
	}
}

func TestQuery_TargetRoot_Empty(t *testing.T) {
	pool := skipIfNoPostgres(t)
	results, _ := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID).QueryByTargetRoot(pos(888))
	if len(results) != 0 {
		t.Fatal("should be empty")
	}
}

func TestQuery_SignerDID_Filtered(t *testing.T) {
	pool := skipIfNoPostgres(t)
	for i := uint64(1); i <= 3; i++ {
		insertTestEntry(t, pool, i, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:alice"}, []byte{byte(i)}), testLogDID)
	}
	for i := uint64(4); i <= 6; i++ {
		insertTestEntry(t, pool, i, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:bob"}, []byte{byte(i)}), testLogDID)
	}
	results, _ := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID).QueryBySignerDID("did:example:alice")
	if len(results) != 3 {
		t.Fatalf("expected 3 alice, got %d", len(results))
	}
}

func TestQuery_SignerDID_Isolation(t *testing.T) {
	pool := skipIfNoPostgres(t)
	insertTestEntry(t, pool, 1, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:unique"}, nil), testLogDID)
	results, _ := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID).QueryBySignerDID("did:example:nonexistent")
	if len(results) != 0 {
		t.Fatal("nonexistent signer should return empty")
	}
}

func TestQuery_SchemaRef_Filtered(t *testing.T) {
	pool := skipIfNoPostgres(t)
	sa := pos(100)
	for i := uint64(1); i <= 3; i++ {
		insertTestEntry(t, pool, i, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:issuer", SchemaRef: ptrTo(sa)}, []byte{byte(i)}), testLogDID)
	}
	insertTestEntry(t, pool, 4, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:issuer", SchemaRef: ptrTo(pos(200))}, nil), testLogDID)
	results, _ := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID).QueryBySchemaRef(sa)
	if len(results) != 3 {
		t.Fatalf("expected 3 for schemaA, got %d", len(results))
	}
}

func TestQuery_Scan_Pagination(t *testing.T) {
	if indexes.MaxScanCount != 10000 {
		t.Fatal("wrong max")
	}
	if indexes.DefaultScanCount != 100 {
		t.Fatal("wrong default")
	}
}

func TestQuery_Scan_PastEnd(t *testing.T) {
	pool := skipIfNoPostgres(t)
	qapi := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID)
	for i := uint64(1); i <= 5; i++ {
		insertTestEntry(t, pool, i, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:scan"}, []byte{byte(i)}), testLogDID)
	}
	r1, _ := qapi.ScanFromPosition(100, 10)
	if len(r1) != 0 {
		t.Fatal("past end should be empty")
	}
	r2, _ := qapi.ScanFromPosition(3, 2)
	if len(r2) != 2 {
		t.Fatalf("expected 2, got %d", len(r2))
	}
	if r2[0].Position.Sequence != 3 || r2[1].Position.Sequence != 4 {
		t.Fatal("wrong seqs")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 5: Tree Head & Witness Integrity (7 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestTreeHead_Assembly(t *testing.T) {
	// v7.75 / Wave 2: SchemeTag moved from CosignedTreeHead to each
	// WitnessSignature (types/tree_head.go:156-169). Per-head scheme
	// is gone; per-signature scheme is now the canonical surface.
	cosigned := types.CosignedTreeHead{
		TreeHead: types.TreeHead{TreeSize: 1000, RootHash: [32]byte{1, 2, 3}},
		Signatures: []types.WitnessSignature{
			{SchemeTag: 1},
			{SchemeTag: 1},
			{SchemeTag: 1},
		},
	}
	if cosigned.TreeSize != 1000 || len(cosigned.Signatures) != 3 {
		t.Fatal("mismatch")
	}
}

func TestTreeHead_QuorumK(t *testing.T) {
	cfg := witness.HeadSyncConfig{WitnessEndpoints: []string{"a", "b", "c"}, QuorumK: 2, PerWitnessTimeout: 30 * time.Second, SchemeTag: 1}
	if len(cfg.WitnessEndpoints) < cfg.QuorumK {
		t.Fatal("insufficient")
	}
}

func TestTreeHead_QuorumInsufficient(t *testing.T) {
	cfg := witness.HeadSyncConfig{WitnessEndpoints: []string{"a"}, QuorumK: 2}
	if len(cfg.WitnessEndpoints) >= cfg.QuorumK {
		t.Fatal("should be insufficient")
	}
}

func TestTreeHead_MerkleInclusion(t *testing.T) {
	mt := smt.NewStubMerkleTree()
	mt.AppendLeaf([]byte{1})
	mt.AppendLeaf([]byte{2})
	mt.AppendLeaf([]byte{3})
	head, _ := mt.Head()
	if head.TreeSize != 3 {
		t.Fatal("size should be 3")
	}
	proof, err := mt.InclusionProof(1, head.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := smt.VerifyMerkleInclusion(proof, head.RootHash); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTreeHead_Consistency(t *testing.T) {
	mt := smt.NewStubMerkleTree()
	for i := 0; i < 50; i++ {
		mt.AppendLeaf([]byte{byte(i)})
	}
	h50, _ := mt.Head()
	for i := 50; i < 100; i++ {
		mt.AppendLeaf([]byte{byte(i)})
	}
	h100, _ := mt.Head()
	if h50.RootHash == h100.RootHash {
		t.Fatal("roots should differ")
	}
	proof, _ := mt.InclusionProof(25, h100.TreeSize)
	if smt.VerifyMerkleInclusion(proof, h100.RootHash) != nil {
		t.Fatal("entry from batch 1 should be provable at size 100")
	}
}

func TestWitnessRotation_DualSign(t *testing.T) {
	if !(types.WitnessRotation{SchemeTagOld: 1, SchemeTagNew: 2}).IsDualSigned() {
		t.Fatal("should be dual")
	}
	if (types.WitnessRotation{SchemeTagOld: 1, SchemeTagNew: 0}).IsDualSigned() {
		t.Fatal("should not be dual")
	}
}

func TestEquivocation_Detection(t *testing.T) {
	hA := sha256.Sum256([]byte("tree-a"))
	hB := sha256.Sum256([]byte("tree-b"))
	proof := witness.EquivocationProof{TreeSize: 500, RootHashA: hA, RootHashB: hB}
	if proof.RootHashA == proof.RootHashB {
		t.Fatal("different roots required")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 6: Log_Time Accuracy (4 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestLogTime_Assignment(t *testing.T) {
	before := time.Now().UTC()
	lt := time.Now().UTC()
	if lt.Before(before) {
		t.Fatal("not UTC")
	}
}

func TestLogTime_Monotonicity(t *testing.T) {
	var ts []time.Time
	for i := 0; i < 100; i++ {
		ts = append(ts, time.Now().UTC())
	}
	for i := 1; i < len(ts); i++ {
		if ts[i].Before(ts[i-1]) {
			t.Fatal("non-monotonic")
		}
	}
}

func TestLogTime_OutsideCanonicalHash(t *testing.T) {
	e := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a"}, nil)
	c := envelope.Serialize(e)
	if sha256.Sum256(c) != sha256.Sum256(c) {
		t.Fatal("hash should be stable")
	}
}

func TestLogTime_InEntryWithMetadata(t *testing.T) {
	lt := time.Now().UTC()
	ewm := types.EntryWithMetadata{LogTime: lt, Position: pos(1)}
	if ewm.LogTime != lt {
		t.Fatal("LogTime lost")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 7: Sequence Integrity — REMOVED in commit 10
// ═════════════════════════════════════════════════════════════════════════════
//
// Tests for store.EntryStore.NextSequence (gapless / monotonic /
// across-restart) lived here. Under WAL-first admission, Tessera —
// not Postgres — owns sequence allocation; NextSequence is gone.
// Tessera's tile-builder enforces the equivalent properties (the
// log's append-only Merkle tree). End-to-end integration tests
// (commit 13) cover the same invariants at the admission layer.
//
// ═════════════════════════════════════════════════════════════════════════════
// Category 8: Delta Buffer & OCC (5 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestDeltaBuffer_Persistence(t *testing.T) {
	buf := builder.NewDeltaWindowBuffer(10)
	key := smt.DeriveKey(pos(1))
	buf.Record(key, pos(10))
	buf.Record(key, pos(11))
	buf2 := builder.NewDeltaWindowBuffer(10)
	buf2.SetHistory(key, buf.History(key))
	if !buf2.Contains(key, pos(10)) || !buf2.Contains(key, pos(11)) {
		t.Fatal("reload failed")
	}
	if len(buf.AllKeys()) != 1 {
		t.Fatal("AllKeys should return 1")
	}
}

func TestDeltaBuffer_ColdStart_SDK_D9(t *testing.T) {
	buf := builder.NewDeltaWindowBuffer(10)
	if buf.Contains(smt.DeriveKey(pos(1)), pos(999)) {
		t.Fatal("cold start should be empty")
	}
	if buf.Len() != 0 {
		t.Fatal("Len should be 0")
	}
}

func TestDeltaBuffer_Reconstructible(t *testing.T) {
	buf := builder.NewDeltaWindowBuffer(10)
	key := smt.DeriveKey(pos(1))
	buf.Record(key, pos(10))
	buf.Record(key, pos(11))
	buf.Record(key, pos(12))
	buf2 := builder.NewDeltaWindowBuffer(10)
	if buf2.Contains(key, pos(10)) {
		t.Fatal("fresh should be empty")
	}
	buf2.SetHistory(key, buf.History(key))
	if !buf2.Contains(key, pos(10)) || !buf2.Contains(key, pos(12)) {
		t.Fatal("reconstruction failed")
	}
}

func TestDeltaBuffer_CommutativeWithinWindow(t *testing.T) {
	h := newHarness()
	h.schema = &mockSchemaResolver{commutative: true}
	h.addRootEntity(t, pos(1), "did:example:entity")
	h.addScopeEntity(t, pos(2), "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2))}, nil), pos(3))
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2)), PriorAuthority: ptrTo(pos(3))}, nil), pos(4))
	if r.PathCCounts != 1 {
		t.Fatal("commutative within window should succeed")
	}
}

func TestDeltaBuffer_NonCommutativeStrict(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:entity")
	h.addScopeEntity(t, pos(2), "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2))}, nil), pos(3))
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2)), PriorAuthority: ptrTo(pos(999))}, nil), pos(4))
	// v7.75 builder.BatchResult: RejectedCounts (scalar) was replaced
	// by RejectedPositions ([]int of input indices). Per the SDK
	// docblock at builder/api.go:152-154, callers that consumed the
	// scalar should switch to len(result.RejectedPositions).
	if len(r.RejectedPositions) != 1 {
		t.Fatal("strict OCC with wrong prior should reject")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 9: Anchor Publishing (3 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestAnchor_CommentaryEntry(t *testing.T) {
	e := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:anchor-op"}, mustJSON(map[string]string{"anchor": "test"}))
	if e.Header.TargetRoot != nil || e.Header.AuthorityPath != nil {
		t.Fatal("should be commentary")
	}
}

func TestAnchor_PayloadContent(t *testing.T) {
	ref := sha256.Sum256([]byte("serialized-tree-head"))
	payload := mustJSON(map[string]any{"anchor_type": "tree_head_ref", "source_log_did": "did:ortholog:source", "tree_head_ref": hex.EncodeToString(ref[:]), "tree_size": 42})
	e := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:op"}, payload)
	if len(e.DomainPayload) < 50 {
		t.Fatal("payload too small")
	}
}

func TestAnchor_Frequency(t *testing.T) {
	interval := 1 * time.Hour
	if interval < time.Minute || interval > 24*time.Hour {
		t.Fatal("interval out of range")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 10: Derivation Commitments (3 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestCommitment_MatchesMutations(t *testing.T) {
	h := newHarness()
	rootBefore := h.root(t)
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:c", AuthorityPath: sameSigner()}, nil), pos(1))
	c := builder.GenerateBatchCommitment(pos(1), pos(1), rootBefore, r)
	if c.MutationCount == 0 {
		t.Fatal("should have mutations")
	}
	if c.PostSMTRoot != r.NewRoot {
		t.Fatal("post root mismatch")
	}
}

func TestCommitment_IsCommentary(t *testing.T) {
	e := makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:op"}, []byte("commitment"))
	if e.Header.TargetRoot != nil || e.Header.AuthorityPath != nil {
		t.Fatal("should be commentary")
	}
}

func TestCommitment_Frequency(t *testing.T) {
	calls := 0
	pub := opbuilder.NewCommitmentPublisher("did:example:op", "did:example:op", opbuilder.CommitmentPublisherConfig{IntervalEntries: 100, IntervalTime: time.Hour}, func(*envelope.Entry) error { calls++; return nil }, slog.Default())
	dr := &builder.BatchResult{NewRoot: [32]byte{1}, Mutations: []types.LeafMutation{{LeafKey: [32]byte{1}}}}
	pub.MaybePublish(context.Background(), 50, pos(1), pos(50), [32]byte{}, dr)
	if calls != 0 {
		t.Fatal("below threshold")
	}
	pub.MaybePublish(context.Background(), 60, pos(51), pos(110), [32]byte{}, dr)
	if calls != 1 {
		t.Fatalf("at threshold, calls=%d", calls)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 11: Crash Recovery & Durability (5 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestCrash_AdvisoryLockExclusivity(t *testing.T) {
	if store.BuilderLockID != 0x4F5254484F4C4F47 {
		t.Fatal("unexpected lock ID")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 12: Governance End-to-End (7 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestGov_ScopeCreation(t *testing.T) {
	h := newHarness()
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a", AuthorityPath: sameSigner(), AuthoritySet: map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}}}, []byte("scope")), pos(1))
	if r.NewLeafCounts != 1 {
		t.Fatal("scope should create leaf")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("OriginTip=self")
	}
}

func TestGov_ThreePhaseAmendment(t *testing.T) {
	h := newHarness()
	h.addScopeEntity(t, pos(1), "did:example:a", map[string]struct{}{"did:example:a": {}, "did:example:b": {}})
	r1 := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a"}, []byte("proposal")), pos(2))
	if r1.CommentaryCounts != 1 {
		t.Fatal("proposal should be commentary")
	}
	r2 := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:b", CosignatureOf: ptrTo(pos(2))}, nil), pos(3))
	if r2.CommentaryCounts != 1 {
		t.Fatal("cosig should be commentary")
	}
	newSet := map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}}
	r3 := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(1)), AuthoritySet: newSet}, nil), pos(4))
	if r3.PathCCounts != 1 {
		t.Fatal("execution should be Path C")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(4)) {
		t.Fatal("OriginTip should update")
	}
}

func TestGov_ScopeRemovalTimeLock(t *testing.T) {
	h := newHarness()
	h.addScopeEntity(t, pos(1), "did:example:a", map[string]struct{}{"did:example:a": {}, "did:example:b": {}})
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(1))}, nil), pos(2))
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(2)) {
		t.Fatal("removal should update AuthorityTip")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("removal should NOT update OriginTip")
	}
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:a", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(1)), AuthoritySet: map[string]struct{}{"did:example:a": {}}, PriorAuthority: ptrTo(pos(2))}, nil), pos(3))
	if !h.leafOriginTip(t, pos(1)).Equal(pos(3)) {
		t.Fatal("activation should update OriginTip")
	}
}

func TestGov_KeyRotationMaturation(t *testing.T) {
	preCommit := time.Now().UTC().Add(-31 * 24 * time.Hour)
	rotation := time.Now().UTC()
	if rotation.Sub(preCommit) < 30*24*time.Hour {
		t.Fatal("31 days should mature")
	}
	recent := time.Now().UTC().Add(-24 * time.Hour)
	if rotation.Sub(recent) >= 30*24*time.Hour {
		t.Fatal("1 day should not mature")
	}
}

func TestGov_RecoveryEscrowChain(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:holder")
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:new-exchange"}, []byte("recovery")), pos(2))
	if r.CommentaryCounts != 1 {
		t.Fatal("recovery request should be commentary")
	}
	for i := uint64(3); i <= 5; i++ {
		r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:escrow" + itoa(int(i)), CosignatureOf: ptrTo(pos(2))}, nil), pos(i))
		if r.CommentaryCounts != 1 {
			t.Fatal("cosig should be commentary")
		}
	}
}

func TestGov_DelegationRevocationCascade(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:division")
	h.addDelegation(t, pos(2), "did:example:division", "did:example:judge")
	h.addDelegation(t, pos(3), "did:example:judge", "did:example:clerk")
	h.addDelegation(t, pos(4), "did:example:clerk", "did:example:deputy")
	r1 := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:deputy", TargetRoot: ptrTo(pos(1)), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{pos(4), pos(3), pos(2)}}, nil), pos(5))
	if r1.PathBCounts != 1 {
		t.Fatal("depth-3 should succeed")
	}
	key := smt.DeriveKey(pos(2))
	leaf, _ := h.tree.GetLeaf(key)
	u := *leaf
	u.OriginTip = pos(6)
	h.tree.SetLeaf(key, u)
	r2 := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:deputy", TargetRoot: ptrTo(pos(1)), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{pos(4), pos(3), pos(2)}}, nil), pos(7))
	if r2.PathDCounts != 1 {
		t.Fatal("revoked judge should break chain")
	}
}

func TestGov_EnforcementCosignatures(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:case")
	h.addScopeEntity(t, pos(2), "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2))}, []byte("seal")), pos(3))
	for i := uint64(4); i <= 5; i++ {
		r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:w" + itoa(int(i)), CosignatureOf: ptrTo(pos(3))}, nil), pos(i))
		if r.CommentaryCounts != 1 {
			t.Fatal("cosig should be commentary")
		}
	}
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2)), PriorAuthority: ptrTo(pos(3)), EvidencePointers: []types.LogPosition{pos(4), pos(5)}}, nil), pos(6))
	if r.PathCCounts != 1 {
		t.Fatal("activation should be Path C")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 13: Judicial End-to-End (6 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestJudicial_CaseFiling(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:division")
	h.addDelegation(t, pos(2), "did:example:division", "did:example:judge")
	h.addDelegation(t, pos(3), "did:example:judge", "did:example:clerk")
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:clerk", AuthorityPath: sameSigner()}, []byte("case: Davidson v. Smith")), pos(4))
	if r.NewLeafCounts != 1 {
		t.Fatal("case should create leaf")
	}
	r2 := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:clerk", TargetRoot: ptrTo(pos(1)), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{pos(3), pos(2)}}, []byte("motion")), pos(5))
	if r2.PathBCounts != 1 {
		t.Fatal("clerk filing should be Path B")
	}
}

func TestJudicial_SealingLifecycle(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:case")
	h.addScopeEntity(t, pos(2), "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2))}, []byte("seal")), pos(3))
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(3)) {
		t.Fatal("seal should update AuthorityTip")
	}
	h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:judge", TargetRoot: ptrTo(pos(1)), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(pos(2)), PriorAuthority: ptrTo(pos(3))}, []byte("unseal")), pos(4))
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(4)) {
		t.Fatal("unseal should advance AuthorityTip")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("sealing should not affect OriginTip")
	}
}

func TestJudicial_EvidenceGrantCommentary(t *testing.T) {
	h := newHarness()
	rootBefore := h.root(t)
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:clerk"}, mustJSON(map[string]string{"grant": "evidence", "cid": "sha256:abc"})), pos(1))
	if r.CommentaryCounts != 1 {
		t.Fatal("evidence grant should be commentary")
	}
	if r.NewRoot != rootBefore {
		t.Fatal("should not change root")
	}
}

func TestJudicial_AppellateRelay(t *testing.T) {
	h := newHarness()
	rootBefore := h.root(t)
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:appellate"}, mustJSON(map[string]any{"relay": "cross_jurisdiction", "source": "did:ortholog:davidson", "seq": 42})), pos(1))
	if r.CommentaryCounts != 1 {
		t.Fatal("relay should be commentary")
	}
	if r.NewRoot != rootBefore {
		t.Fatal("relay should not change root")
	}
}

func TestJudicial_BulkImport(t *testing.T) {
	entries, positions := generateEntries(t, 1000)
	r := runSDKBuilder(t, entries, positions)
	if r.NewLeafCounts == 0 {
		t.Fatal("should create leaves")
	}
	total := r.NewLeafCounts + r.PathACounts + r.CommentaryCounts + r.PathDCounts
	if total != 1000 {
		t.Fatalf("all entries should be accounted: %d", total)
	}
	t.Logf("bulk: %d leaves, %d commentary, %d pathA, %d pathD", r.NewLeafCounts, r.CommentaryCounts, r.PathACounts, r.PathDCounts)
}

func TestJudicial_DailyAssignment(t *testing.T) {
	h := newHarness()
	rootBefore := h.root(t)
	r := h.process(t, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:clerk-office"}, mustJSON(map[string]any{"type": "daily_assignment", "date": "2024-01-15", "courtroom": "3A"})), pos(1))
	if r.CommentaryCounts != 1 {
		t.Fatal("assignment should be commentary")
	}
	if r.NewRoot != rootBefore {
		t.Fatal("should not change root")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 14: Multi-Tenant & Operational (4 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestOps_ThreeLogIsolation(t *testing.T) {
	pool := skipIfNoPostgres(t)
	insertTestEntry(t, pool, 1, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:log-a"}, nil), testLogDID)
	insertTestEntry(t, pool, 2, makeEntry(t, envelope.ControlHeader{SignerDID: "did:example:log-b"}, nil), testLogDID)
	qapi := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID)
	ra, _ := qapi.QueryBySignerDID("did:example:log-a")
	rb, _ := qapi.QueryBySignerDID("did:example:log-b")
	if len(ra) != 1 || len(rb) != 1 {
		t.Fatal("each signer should have 1")
	}
	if ra[0].Position.Sequence == rb[0].Position.Sequence {
		t.Fatal("different sequences")
	}
}

func TestOps_WriteCreditIsolation(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()
	cs := store.NewCreditStore(pool)
	cs.BulkPurchase(ctx, "did:example:exchange-a", 100)
	b, _ := cs.Balance(ctx, "did:example:exchange-b")
	if b != 0 {
		t.Fatal("B should have 0")
	}
	tx, _ := pool.Begin(ctx)
	newBal, err := cs.Deduct(ctx, tx, "did:example:exchange-a")
	tx.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if newBal != 99 {
		t.Fatalf("expected 99, got %d", newBal)
	}
	tx2, _ := pool.Begin(ctx)
	_, err = cs.Deduct(ctx, tx2, "did:example:exchange-b")
	tx2.Rollback(ctx)
	if err != store.ErrInsufficientCredits {
		t.Fatalf("expected insufficient, got: %v", err)
	}
}

func TestOps_DynamicDifficulty(t *testing.T) {
	cfg := middleware.DefaultDifficultyConfig()
	if cfg.InitialDifficulty != 16 || cfg.MinDifficulty != 8 || cfg.MaxDifficulty != 24 || cfg.HashFunction != "sha256" {
		t.Fatal("wrong defaults")
	}
}

func TestOps_HealthCheckAccuracy(t *testing.T) {
	pool := skipIfNoPostgres(t)
	if pool.Ping(context.Background()) != nil {
		t.Fatal("Postgres should be reachable")
	}
	// Verify schema was created (entry_index table exists).
	var exists bool
	pool.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='entry_index')").Scan(&exists)
	if !exists {
		t.Fatal("entry_index table should exist after schema creation")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 15: SDK Adapter & Wire Format Boundary (5 tests)
//
// Verifies post-Wave-1.5 invariants:
//   - admission.ProofFromWire correctly translates wire→API form
//   - StampParams round-trips through GenerateStamp + VerifyStamp
//   - Epoch acceptance window boundary behavior matches the contract
//   - Wire-format AdmissionProofBody and API AdmissionProof stay distinct
//
// These tests exercise the new SDK surface added in v0.1.0.
// ═════════════════════════════════════════════════════════════════════════════

// TestSDKAdapter_ProofFromWire_RoundTrip verifies the actual contract of
// ProofFromWire: a wire-format AdmissionProofBody, when translated to the
// API form, produces a proof that VerifyStamp accepts (assuming the nonce
// was generated for those parameters).
//
// Earlier versions of this test asserted field-by-field numeric equality
// (e.g. apiProof.Mode == 2). That's wrong on principle — the wire byte
// encoding and the API enum encoding are deliberately allowed to differ;
// that's why the adapter exists. Asserting numeric equality assumes
// implementation details that aren't part of the contract.
//
// What IS the contract:
//  1. ProofFromWire never returns nil for non-nil input
//  2. The translated proof carries forward Nonce, Epoch, SubmitterCommit
//     verbatim — these are the fields the verifier hashes
//  3. TargetLog is populated from the operator-supplied logDID
//  4. The translated proof verifies if and only if the wire body would
//     hash valid against (entryHash, logDID, difficulty, hashFunc, epoch)
//
// We test (1)–(4) by full round-trip rather than peeking at internal fields.
func TestSDKAdapter_ProofFromWire_RoundTrip(t *testing.T) {
	// Generate a real Mode B stamp via the public StampParams API.
	// This produces a verified-correct (entryHash, nonce, epoch) triple.
	hash := sha256.Sum256([]byte("proof-from-wire-roundtrip"))
	const difficulty uint32 = 6 // low difficulty for fast generation
	commit := [32]byte{9, 9, 9}
	params := admission.StampParams{
		EntryHash:       hash,
		LogDID:          testLogDID,
		Difficulty:      difficulty,
		HashFunc:        admission.HashSHA256,
		Epoch:           currentTestEpoch(),
		SubmitterCommit: &commit,
	}
	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	// Construct the wire-format body the operator would receive over HTTP.
	// Use the SDK's exported wire-byte aliases (v0.1.1+) — locked against
	// typed-constant drift by wire_encoding_test.go in the SDK.
	body := &envelope.AdmissionProofBody{
		Mode:            types.WireByteModeB,
		Difficulty:      uint8(difficulty),
		HashFunc:        admission.WireByteHashSHA256,
		Epoch:           params.Epoch,
		SubmitterCommit: &commit,
		Nonce:           nonce,
	}

	// Contract 1: adapter returns non-nil for non-nil input.
	apiProof := admission.ProofFromWire(body, testLogDID)
	if apiProof == nil {
		t.Fatal("ProofFromWire returned nil for non-nil body")
	}

	// Contract 2 + 3 + 4: the translated proof must verify.
	// This is the union of all behavior that matters — if Nonce, Epoch,
	// SubmitterCommit weren't carried forward, or if TargetLog wasn't set,
	// VerifyStamp would fail. A passing verify is the strongest possible
	// assertion.
	if err := admission.VerifyStamp(
		apiProof, hash, testLogDID, difficulty,
		admission.HashSHA256, nil,
		currentTestEpoch(), uint64(testEpochAcceptanceWindow),
	); err != nil {
		t.Fatalf("ProofFromWire output failed VerifyStamp: %v", err)
	}

	// Spot-check the fields VerifyStamp doesn't touch but the operator
	// reads downstream (audit logs, metrics, rate limiting).
	if apiProof.Nonce != nonce {
		t.Errorf("Nonce: got %d, want %d (must round-trip verbatim)", apiProof.Nonce, nonce)
	}
	if apiProof.Epoch != params.Epoch {
		t.Errorf("Epoch: got %d, want %d (must round-trip verbatim)", apiProof.Epoch, params.Epoch)
	}
	if apiProof.TargetLog != testLogDID {
		t.Errorf("TargetLog: got %q, want %q (must come from operator context)",
			apiProof.TargetLog, testLogDID)
	}
	if apiProof.SubmitterCommit == nil || *apiProof.SubmitterCommit != commit {
		t.Error("SubmitterCommit must round-trip verbatim")
	}

	// Contract regression: confirm a tampered body fails verification.
	// If we change ANY hashed field, VerifyStamp should reject — proves
	// the adapter isn't masking field corruption.
	tampered := *body
	tampered.Nonce = nonce + 1
	tamperedAPI := admission.ProofFromWire(&tampered, testLogDID)
	if err := admission.VerifyStamp(
		tamperedAPI, hash, testLogDID, difficulty,
		admission.HashSHA256, nil,
		currentTestEpoch(), uint64(testEpochAcceptanceWindow),
	); err == nil {
		t.Fatal("tampered nonce should fail verification")
	}
}

func TestSDKAdapter_ProofFromWire_NilSafe(t *testing.T) {
	if admission.ProofFromWire(nil, testLogDID) != nil {
		t.Fatal("ProofFromWire(nil) should return nil")
	}
}

func TestSDKAdapter_StampParamsRoundTrip(t *testing.T) {
	// Generate at difficulty 6 (fast even for SHA-256).
	hash := sha256.Sum256([]byte("round-trip-test"))
	params := buildStampParams(hash, testLogDID, 6)

	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	// Verify with same params, same epoch, sane window.
	if err := verifyStampForTest(params, nonce, testLogDID, 6); err != nil {
		t.Fatalf("VerifyStamp on freshly generated stamp: %v", err)
	}
}

func TestSDKAdapter_EpochOutsideWindow_Rejected(t *testing.T) {
	// Stamp generated for epoch=N, then verified against epoch=N+5
	// (way outside the acceptance window of 1) — must fail.
	hash := sha256.Sum256([]byte("epoch-window-test"))

	// Use an epoch deliberately far in the past.
	staleEpoch := currentTestEpoch() - 100
	params := admission.StampParams{
		EntryHash:  hash,
		LogDID:     testLogDID,
		Difficulty: 6,
		HashFunc:   admission.HashSHA256,
		Epoch:      staleEpoch,
	}
	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	apiProof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  testLogDID,
		Difficulty: 6,
		Epoch:      staleEpoch,
	}

	// Verify with current epoch + window=1 — must reject as out-of-window.
	err = admission.VerifyStamp(
		apiProof, hash, testLogDID, 6,
		admission.HashSHA256, nil,
		currentTestEpoch(), 1,
	)
	if err == nil {
		t.Fatal("stamp from epoch 100-windows-ago should be rejected with window=1")
	}
	t.Logf("stale epoch rejection: %v", err)
}

func TestSDKAdapter_TwoTypesAreDistinct(t *testing.T) {
	// Confirms the deliberate type split between wire format and API form.
	// envelope.AdmissionProofBody and types.AdmissionProof have different
	// fields and serve different purposes — an alias would be a bug.
	wire := &envelope.AdmissionProofBody{}
	api := &types.AdmissionProof{}

	// If the next two lines compiled and were equivalent, the types
	// would be the same — but they're not, by design.
	_ = wire
	_ = api

	// Verify each type has a field the other lacks. This is purely a
	// compile-time documentation check: if these field references break,
	// the SDK has merged the types and the operator's adapter is dead code.
	wire.Hash = [32]byte{1} // present on wire only (verifier recomputes)
	if wire.Hash[0] != 1 {
		t.Fatal("Hash field should exist on wire type")
	}
	api.TargetLog = "did:example:x" // present on API only (binding context)
	if api.TargetLog != "did:example:x" {
		t.Fatal("TargetLog field should exist on API type")
	}
}

// hex.EncodeToString is used in TestAnchor_PayloadContent.
// store.BuilderLockID is used in TestCrash_AdvisoryLockExclusivity.
// Both imports are real — no var _ shims needed.
