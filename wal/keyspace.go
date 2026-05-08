/*
FILE PATH: wal/keyspace.go

BadgerDB keyspace layout for the WAL.

	entry:<hash:32>          → wire bytes (immutable, write-once)
	meta:<hash:32>            → meta record (state, seq, attempts)
	seq_index:<seq:8>         → hash:32 (after sequencing)
	inflight:<hash:32>        → ts:8 (unix-nano)  (breadcrumb across Add)
	hwm → seq:8 (high-water mark for shipped)
	tessera_dedup:<id:32>     → seq:8 (Tessera Deduplicator backing)

State machine on meta:

	pending — written by Submit, before tessera.Add
	sequenced — written by Sequence (after tessera.Add returned a seq)
	shipped — written by MarkShipped (after bytestore upload completed)
	manual — written by Shipper after N retry-exhausted attempts
	            (ledger-side metric only — bytes stay in WAL)

INVARIANTS:
  - entry:<hash> is set ONCE per (hash) and never deleted while the
    entry is live. The Shipper's "advance HWM and GC" path is the
    only deletion site, and it only removes entries below
    HWM-RetentionBuffer.
  - meta:<hash> always coexists with entry:<hash>. They're written
    in the same Badger txn so this is atomic.
  - seq_index:<seq> appears only after Sequence has run. The Shipper
    iterates seq_index in ascending order to find the next entry
    to ship.
  - inflight:<hash> exists only between Submit and Sequence. The
    Reconciler scans this on boot to catch entries that were Add'd
    to Tessera but never Sequence'd locally (ledger crashed in
    the window).
  - tessera_dedup is a separate keyspace prefix because Tessera's
    Deduplicator owns it; we never read or write under that prefix
    from any path other than the dedup adapter (wal/dedup.go).
*/
package wal

import (
	"encoding/binary"
)

// Keyspace prefixes. Single-byte tags chosen so the BadgerDB sort
// order groups related keys (e.g., all `entry:` keys are contiguous).
const (
	prefixEntry        byte = 0x01
	prefixMeta         byte = 0x02
	prefixSeqIndex     byte = 0x03
	prefixInflight     byte = 0x04
	prefixHWM          byte = 0x05
	prefixTesseraDedup byte = 0x06
)

// entryKey builds the storage key for an entry's wire bytes.
func entryKey(hash [32]byte) []byte {
	k := make([]byte, 1+32)
	k[0] = prefixEntry
	copy(k[1:], hash[:])
	return k
}

// metaKey builds the storage key for an entry's metadata record.
func metaKey(hash [32]byte) []byte {
	k := make([]byte, 1+32)
	k[0] = prefixMeta
	copy(k[1:], hash[:])
	return k
}

// seqIndexKey builds the storage key mapping sequence → hash.
// Big-endian seq encoding so the BadgerDB sort order matches numeric
// order (lets the Shipper iterate sequenced entries in seq ASC).
func seqIndexKey(seq uint64) []byte {
	k := make([]byte, 1+8)
	k[0] = prefixSeqIndex
	binary.BigEndian.PutUint64(k[1:], seq)
	return k
}

// seqFromIndexKey reverses seqIndexKey for iteration.
func seqFromIndexKey(k []byte) uint64 {
	return binary.BigEndian.Uint64(k[1:])
}

// inflightKey builds the storage key for the breadcrumb covering the
// Tessera-Add window.
func inflightKey(hash [32]byte) []byte {
	k := make([]byte, 1+32)
	k[0] = prefixInflight
	copy(k[1:], hash[:])
	return k
}

// hashFromInflightKey reverses inflightKey for iteration.
func hashFromInflightKey(k []byte) [32]byte {
	var h [32]byte
	copy(h[:], k[1:])
	return h
}

// hwmKey is the singleton HWM record key.
func hwmKey() []byte {
	return []byte{prefixHWM}
}

// tesseraDedupKey wraps the Tessera Deduplicator backing.
// identity is the entry's content hash (envelope.EntryIdentity).
func tesseraDedupKey(identity []byte) []byte {
	k := make([]byte, 1+len(identity))
	k[0] = prefixTesseraDedup
	copy(k[1:], identity)
	return k
}
