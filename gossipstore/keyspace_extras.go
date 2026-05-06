/*
FILE PATH: gossipstore/keyspace_extras.go

Key encoders/decoders + on-disk shapes for the projection sub-prefixes:

	0x09 binding inverted index (Filter.Binding O(1) lookup)
	0x0A splitid index (EquivocationScanner subscribes here)
	0x0B equivocation projection (read-side cache for /by-split-id)

Split from keyspace.go to keep both files under the 300-LOC budget.
*/
package gossipstore

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// MaxSchemaIDLen caps the schema_id stored in the splitid index.
// 256 bytes is generous for -style identifiers
// ("attesta.network/schema/pre-grant-commitment/v1").
const MaxSchemaIDLen = 256

// ─────────────────────────────────────────────────────────────────────
// 0x09 — binding inverted index
// ─────────────────────────────────────────────────────────────────────

// bindingIndexKey builds a key under the binding inverted index.
// Composite (binding || eventID) so multiple events at the same
// binding produce distinct keys.
func bindingIndexKey(binding [32]byte, eventID [32]byte) []byte {
	k := make([]byte, 2+32+32)
	k[0] = prefixGossipRoot
	k[1] = subBindingIndex
	copy(k[2:34], binding[:])
	copy(k[34:], eventID[:])
	return k
}

// bindingIndexPrefix scans every event matching one binding hash.
// Prefix-equality lookup → O(log N) on Badger LSM with bloom-filter
// fast-path; effectively O(1) at scale.
func bindingIndexPrefix(binding [32]byte) []byte {
	k := make([]byte, 2+32)
	k[0] = prefixGossipRoot
	k[1] = subBindingIndex
	copy(k[2:], binding[:])
	return k
}

// eventIDFromBindingIndexKey extracts the suffix eventID from a
// binding-index key.
func eventIDFromBindingIndexKey(k []byte) ([32]byte, error) {
	var id [32]byte
	if len(k) != 2+32+32 || k[0] != prefixGossipRoot || k[1] != subBindingIndex {
		return id, fmt.Errorf("gossipstore: not a binding index key")
	}
	copy(id[:], k[34:])
	return id, nil
}

// ─────────────────────────────────────────────────────────────────────
// 0x0A — splitid index (ledger-local detection trigger)
// ─────────────────────────────────────────────────────────────────────

// SplitIDIndexEntry is the value stored under the splitid index.
// Carries everything the EquivocationScanner needs to construct an
// EntryCommitmentEquivocationFinding without re-reading the WAL.
type SplitIDIndexEntry struct {
	// EquivocatorDID is the ledger DID that signed this entry.
	// Today every entry is signed by THIS ledger, so all index
	// values share one DID; the field is explicit so a future
	// multi-tenant ledger (one binary serving multiple log DIDs)
	// can still be detected.
	EquivocatorDID string `json:"equivocator_did"`

	// CanonicalHash is the SHA-256 of the entry's canonical
	// wire bytes — the same value that keys entry_index in
	// Postgres. Different canonical hashes at the same
	// (schema_id, split_id) are the equivocation signature.
	CanonicalHash [32]byte `json:"canonical_hash"`

	// SigBytes is the ledger's entry-signature over
	// CanonicalHash. The scanner copies this into the gossip
	// event's per-side payload so consumers verify without
	// fetching the entry.
	SigBytes []byte `json:"sig_bytes"`
}

// splitIDIndexKey builds a key under the splitid index. The
// 8-byte big-endian seq suffix orders entries within one
// (schema_id, split_id) so a prefix scan returns them in
// admission order.
func splitIDIndexKey(schemaID string, splitID [32]byte, seq uint64) []byte {
	if len(schemaID) > MaxSchemaIDLen {
		schemaID = schemaID[:MaxSchemaIDLen]
	}
	k := make([]byte, 2+2+len(schemaID)+32+8)
	k[0] = prefixGossipRoot
	k[1] = subSplitIDIndex
	binary.BigEndian.PutUint16(k[2:4], uint16(len(schemaID)))
	off := 4 + len(schemaID)
	copy(k[4:off], schemaID)
	copy(k[off:off+32], splitID[:])
	off += 32
	binary.BigEndian.PutUint64(k[off:off+8], seq)
	return k
}

// splitIDIndexPrefix returns the prefix matching every entry at
// one (schema_id, split_id) tuple. The scanner uses this to count
// collisions: prefix scan returning ≥ 2 keys is an equivocation.
func splitIDIndexPrefix(schemaID string, splitID [32]byte) []byte {
	if len(schemaID) > MaxSchemaIDLen {
		schemaID = schemaID[:MaxSchemaIDLen]
	}
	k := make([]byte, 2+2+len(schemaID)+32)
	k[0] = prefixGossipRoot
	k[1] = subSplitIDIndex
	binary.BigEndian.PutUint16(k[2:4], uint16(len(schemaID)))
	off := 4 + len(schemaID)
	copy(k[4:off], schemaID)
	copy(k[off:off+32], splitID[:])
	return k
}

// allSplitIDIndexPrefix is the watch prefix for db.Subscribe.
func allSplitIDIndexPrefix() []byte {
	return []byte{prefixGossipRoot, subSplitIDIndex}
}

// SplitIDIndexEntryFromKey decodes the trailing seq from a key
// for diagnostic / collision-investigation use.
func SplitIDIndexEntryFromKey(k []byte) (schemaID string, splitID [32]byte, seq uint64, err error) {
	if len(k) < 4 || k[0] != prefixGossipRoot || k[1] != subSplitIDIndex {
		err = fmt.Errorf("gossipstore: not a splitid index key")
		return
	}
	slen := int(binary.BigEndian.Uint16(k[2:4]))
	if len(k) != 4+slen+32+8 {
		err = fmt.Errorf("gossipstore: splitid key length mismatch")
		return
	}
	schemaID = string(k[4 : 4+slen])
	copy(splitID[:], k[4+slen:4+slen+32])
	seq = binary.BigEndian.Uint64(k[4+slen+32:])
	return
}

// EncodeSplitIDIndexEntry serializes the value side of the splitid
// index. Defensive: the scanner reads + decodes; corruption here
// would silently break detection.
func EncodeSplitIDIndexEntry(e SplitIDIndexEntry) ([]byte, error) {
	if e.EquivocatorDID == "" {
		return nil, fmt.Errorf("gossipstore: SplitIDIndexEntry: empty EquivocatorDID")
	}
	if e.CanonicalHash == ([32]byte{}) {
		return nil, fmt.Errorf("gossipstore: SplitIDIndexEntry: zero CanonicalHash")
	}
	if len(e.SigBytes) == 0 {
		return nil, fmt.Errorf("gossipstore: SplitIDIndexEntry: empty SigBytes")
	}
	return json.Marshal(e)
}

// DecodeSplitIDIndexEntry parses a value back. Used by the
// EquivocationScanner.
func DecodeSplitIDIndexEntry(raw []byte) (SplitIDIndexEntry, error) {
	var out SplitIDIndexEntry
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("gossipstore: decode splitid entry: %w", err)
	}
	if out.EquivocatorDID == "" {
		return out, fmt.Errorf("gossipstore: decoded splitid entry has empty DID")
	}
	if len(out.SigBytes) == 0 {
		return out, fmt.Errorf("gossipstore: decoded splitid entry has empty SigBytes")
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────
// 0x0B — equivocation projection (O(1) read for /by-split-id)
// ─────────────────────────────────────────────────────────────────────

// equivProjKey builds a key under the equivocation projection.
// Keyed by content-derived binding so the read endpoint computes
// it identically and serves a point lookup.
func equivProjKey(binding [32]byte) []byte {
	k := make([]byte, 2+32)
	k[0] = prefixGossipRoot
	k[1] = subEquivProj
	copy(k[2:], binding[:])
	return k
}

// ─────────────────────────────────────────────────────────────────────
// 0x0C — entry lookup projection (CQRS read-side for /by-split-id)
// ─────────────────────────────────────────────────────────────────────

// EntryLookupIndexEntry is the value stored under 0x0C. Carries
// every field the /v1/commitments/by-split-id JSON response needs
// to construct one CommitmentLookupEntry without touching Postgres.
//
// CanonicalBytes is the full canonical wire encoding of the entry
// (the SDK consumer feeds this back into envelope.ParseEntry to
// reconstruct domain payloads). LogTimeMicros is unix-micros so
// the read handler reconstructs the time.Time deterministically;
// LogDID is the ledger's log DID (constant per ledger binary
// but stored per-row so a future multi-tenant ledger can serve
// rows from multiple log DIDs without ambiguity).
type EntryLookupIndexEntry struct {
	CanonicalBytes []byte `json:"canonical_bytes"`
	LogTimeMicros int64 `json:"log_time_micros"`
	LogDID string `json:"log_did"`
}

// entryLookupKey builds a key under 0x0C. Sort order is
// (schema_id, split_id, seq ASC). The 8-byte big-endian seq suffix
// ensures a prefix scan returns admissions in chronological order
// at the same (schema, split_id) tuple — the JSON response
// preserves that order verbatim.
func entryLookupKey(schemaID string, splitID [32]byte, seq uint64) []byte {
	if len(schemaID) > MaxSchemaIDLen {
		schemaID = schemaID[:MaxSchemaIDLen]
	}
	k := make([]byte, 2+2+len(schemaID)+32+8)
	k[0] = prefixGossipRoot
	k[1] = subEntryLookup
	binary.BigEndian.PutUint16(k[2:4], uint16(len(schemaID)))
	off := 4 + len(schemaID)
	copy(k[4:off], schemaID)
	copy(k[off:off+32], splitID[:])
	off += 32
	binary.BigEndian.PutUint64(k[off:off+8], seq)
	return k
}

// entryLookupPrefix returns the prefix matching every entry at one
// (schema_id, split_id) tuple under 0x0C. Used by the read handler
// to scan all rows for the lookup; the CommitmentFetcher
// implementation iterates this prefix once per request.
func entryLookupPrefix(schemaID string, splitID [32]byte) []byte {
	if len(schemaID) > MaxSchemaIDLen {
		schemaID = schemaID[:MaxSchemaIDLen]
	}
	k := make([]byte, 2+2+len(schemaID)+32)
	k[0] = prefixGossipRoot
	k[1] = subEntryLookup
	binary.BigEndian.PutUint16(k[2:4], uint16(len(schemaID)))
	off := 4 + len(schemaID)
	copy(k[4:off], schemaID)
	copy(k[off:off+32], splitID[:])
	return k
}

// entryLookupKeyParts decodes the (schema_id, split_id, seq) tuple
// from an 0x0C key. Symmetric with entryLookupKey — the read
// handler relies on this to surface seq in the lookup response.
func entryLookupKeyParts(k []byte) (schemaID string, splitID [32]byte, seq uint64, err error) {
	if len(k) < 4 || k[0] != prefixGossipRoot || k[1] != subEntryLookup {
		err = fmt.Errorf("gossipstore: not an entry lookup key")
		return
	}
	slen := int(binary.BigEndian.Uint16(k[2:4]))
	if len(k) != 4+slen+32+8 {
		err = fmt.Errorf("gossipstore: entry lookup key length mismatch")
		return
	}
	schemaID = string(k[4 : 4+slen])
	copy(splitID[:], k[4+slen:4+slen+32])
	seq = binary.BigEndian.Uint64(k[4+slen+32:])
	return
}

// EncodeEntryLookupIndexEntry serializes the value side. Empty
// CanonicalBytes is rejected — admission stage 1 already enforces
// non-empty canonical bytes; an empty value here would be a
// sequencer bug worth catching at write time.
func EncodeEntryLookupIndexEntry(e EntryLookupIndexEntry) ([]byte, error) {
	if len(e.CanonicalBytes) == 0 {
		return nil, fmt.Errorf("gossipstore: EntryLookupIndexEntry: empty CanonicalBytes")
	}
	if e.LogDID == "" {
		return nil, fmt.Errorf("gossipstore: EntryLookupIndexEntry: empty LogDID")
	}
	return json.Marshal(e)
}

// DecodeEntryLookupIndexEntry parses a 0x0C value back. Used by
// the BadgerCommitmentFetcher.
func DecodeEntryLookupIndexEntry(raw []byte) (EntryLookupIndexEntry, error) {
	var out EntryLookupIndexEntry
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("gossipstore: decode entry lookup entry: %w", err)
	}
	if len(out.CanonicalBytes) == 0 {
		return out, fmt.Errorf("gossipstore: decoded entry lookup entry has empty CanonicalBytes")
	}
	if out.LogDID == "" {
		return out, fmt.Errorf("gossipstore: decoded entry lookup entry has empty LogDID")
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────
// 0x0D — splitid replay HWM (singleton)
// ─────────────────────────────────────────────────────────────────────

// splitIDReplayHWMKey returns the singleton key for the
// replay-on-restart high-water-mark.
func splitIDReplayHWMKey() []byte {
	return []byte{prefixGossipRoot, subSplitIDReplayHWM}
}
