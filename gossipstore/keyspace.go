/*
FILE PATH: gossipstore/keyspace.go

BadgerDB keyspace layout for the operator-side gossip Store.

# DESIGN

All keys live under a single root prefix byte (prefixGossipRoot = 0x07).
The second byte is a sub-prefix tag identifying the index. This
co-tenants gossip data with the existing WAL keyspace (prefixes
0x01..0x06 reserved by wal/keyspace.go) without colliding.

  0x07 0x01 <eventID:32>                              → SignedEvent JSON
  0x07 0x02 <olen:2><orig><lamport:8>                 → eventID:32
  0x07 0x03 <klen:2><kind><lamport:8><olen:2><orig>   → eventID:32
  0x07 0x04 <olen:2><orig>                            → headRecord (40 bytes)
  0x07 0x05 <olen:2><orig><lamport:8>                 → eventID:32
  0x07 0x06                                           → statsCounter (16 bytes)
  0x07 0x07 <olen:2><orig>                            → empty (existence marker)

# SCALE NOTES

  - 0x01 byID: Get is O(log N) via direct point read. Hot path for
    event-by-id endpoint.
  - 0x02 chain: per-originator ordered scan. Big-endian lamport
    encoding makes Badger's natural sort order match numeric order.
    Iterate(Originator=X), Head(X) → fast prefix scan.
  - 0x03 kindIndex: per-kind global ordered scan. Iterate(Kind=K)
    or IterSince(Kind=K, no Originator) → fast prefix scan.
    Includes orig in suffix for stable ordering across originators
    publishing to the same kind.
  - 0x04 head: per-originator chain head. O(1) read for Append's
    chain-discipline check; avoids scanning 0x02 to find the last
    entry.
  - 0x05 sthIndex: per-originator KindCosignedTreeHead reverse
    index. LatestSTH(X) → seek-last on prefix scan, O(log N).
  - 0x06 stats: aggregate EventCount + OriginatorCount as a single
    fixed-size record. Incremented atomically inside Append's txn
    (so Stats is O(1) — required by the Store interface).
  - 0x07 origExists: existence marker for distinct-originator
    counting. Written once on the first event from a new originator;
    used to keep the stats counter accurate without scanning.

# WHY NOT BATCH MERGE

Badger's MergeOperator (atomic counter) was considered for stats.
Rejected because:
  - Stats is a low-frequency read (boot, observability scrape)
    and is fine being computed inside the same txn as Append.
  - MergeOperator has surprising recovery semantics on crash.
  - Single-byte read of a fixed-size record is simpler.

# ENDIANNESS

Big-endian throughout. Badger sorts keys lexicographically; for
numeric ranges (lamport) to match numeric sort order, the encoding
must be big-endian. The Lamport range [a, b] becomes a contiguous
byte range under the prefix, which makes IterSince a single ordered
scan.
*/
package gossipstore

import (
	"encoding/binary"
	"fmt"
)

// Single root prefix; co-tenant with WAL prefixes 0x01..0x06.
const prefixGossipRoot byte = 0x07

// Sub-prefix tags. Single bytes chosen so all of one index's keys
// are contiguous in Badger's sort order.
const (
	subEvent       byte = 0x01 // by-eventID
	subChain       byte = 0x02 // per-originator chain
	subKindIndex   byte = 0x03 // per-kind global
	subHead        byte = 0x04 // per-originator head pointer
	subSTHIndex    byte = 0x05 // per-originator STH reverse index
	subStats       byte = 0x06 // singleton stats record
	subOrigExists  byte = 0x07 // existence marker for originator count
)

// MaxOriginatorLen mirrors gossip.MaxOriginatorLen. Lengths are
// encoded as uint16 in keys to keep them ordered correctly even
// for very long DIDs.
const MaxOriginatorLen = 1024

// MaxKindLen mirrors gossip.MaxKindLen. Same rationale.
const MaxKindLen = 64

// eventKey builds the by-id key for a SignedEvent.
func eventKey(eventID [32]byte) []byte {
	k := make([]byte, 2+32)
	k[0] = prefixGossipRoot
	k[1] = subEvent
	copy(k[2:], eventID[:])
	return k
}

// chainKey builds the per-originator chain key. Sort order is
// (originator, lamport ASC). Lamport is big-endian uint64.
func chainKey(originator string, lamport uint64) []byte {
	if len(originator) > MaxOriginatorLen {
		// Defensive: callers should validate before reaching here.
		// We truncate so we never emit a malformed key. The store
		// rejects oversized originators upstream via Append's
		// validation, so this is belt-and-braces.
		originator = originator[:MaxOriginatorLen]
	}
	k := make([]byte, 2+2+len(originator)+8)
	k[0] = prefixGossipRoot
	k[1] = subChain
	binary.BigEndian.PutUint16(k[2:4], uint16(len(originator)))
	copy(k[4:4+len(originator)], originator)
	binary.BigEndian.PutUint64(k[4+len(originator):], lamport)
	return k
}

// chainPrefix returns the scan prefix matching all chain entries
// for one originator.
func chainPrefix(originator string) []byte {
	k := make([]byte, 2+2+len(originator))
	k[0] = prefixGossipRoot
	k[1] = subChain
	binary.BigEndian.PutUint16(k[2:4], uint16(len(originator)))
	copy(k[4:], originator)
	return k
}

// allChainsPrefix returns the scan prefix matching every chain
// entry across all originators. Used by Iterate when no
// originator filter is set.
func allChainsPrefix() []byte {
	return []byte{prefixGossipRoot, subChain}
}

// kindIndexKey builds the per-kind global index key. Sort order
// is (kind, lamport ASC, originator). Including originator in the
// suffix breaks ties so two events at the same lamport from
// different originators don't collide.
func kindIndexKey(kind string, lamport uint64, originator string) []byte {
	if len(kind) > MaxKindLen {
		kind = kind[:MaxKindLen]
	}
	if len(originator) > MaxOriginatorLen {
		originator = originator[:MaxOriginatorLen]
	}
	k := make([]byte, 2+2+len(kind)+8+2+len(originator))
	k[0] = prefixGossipRoot
	k[1] = subKindIndex
	binary.BigEndian.PutUint16(k[2:4], uint16(len(kind)))
	off := 4 + len(kind)
	copy(k[4:off], kind)
	binary.BigEndian.PutUint64(k[off:off+8], lamport)
	off += 8
	binary.BigEndian.PutUint16(k[off:off+2], uint16(len(originator)))
	off += 2
	copy(k[off:], originator)
	return k
}

// kindIndexPrefix returns the scan prefix matching all events of
// a single kind across all originators.
func kindIndexPrefix(kind string) []byte {
	k := make([]byte, 2+2+len(kind))
	k[0] = prefixGossipRoot
	k[1] = subKindIndex
	binary.BigEndian.PutUint16(k[2:4], uint16(len(kind)))
	copy(k[4:], kind)
	return k
}

// headKey builds the per-originator head pointer key. Stores a
// fixed-size headRecord (32 byte prevHash + 8 byte lamport).
func headKey(originator string) []byte {
	if len(originator) > MaxOriginatorLen {
		originator = originator[:MaxOriginatorLen]
	}
	k := make([]byte, 2+2+len(originator))
	k[0] = prefixGossipRoot
	k[1] = subHead
	binary.BigEndian.PutUint16(k[2:4], uint16(len(originator)))
	copy(k[4:], originator)
	return k
}

// sthIndexKey builds the per-originator STH index key. Sort
// order is (originator, lamport ASC); LatestSTH seeks the last
// entry under the originator prefix.
func sthIndexKey(originator string, lamport uint64) []byte {
	if len(originator) > MaxOriginatorLen {
		originator = originator[:MaxOriginatorLen]
	}
	k := make([]byte, 2+2+len(originator)+8)
	k[0] = prefixGossipRoot
	k[1] = subSTHIndex
	binary.BigEndian.PutUint16(k[2:4], uint16(len(originator)))
	copy(k[4:4+len(originator)], originator)
	binary.BigEndian.PutUint64(k[4+len(originator):], lamport)
	return k
}

// sthIndexPrefix returns the scan prefix for a single originator's
// STH entries.
func sthIndexPrefix(originator string) []byte {
	k := make([]byte, 2+2+len(originator))
	k[0] = prefixGossipRoot
	k[1] = subSTHIndex
	binary.BigEndian.PutUint16(k[2:4], uint16(len(originator)))
	copy(k[4:], originator)
	return k
}

// statsKey is the singleton stats record key. The value is a
// fixed-size pair of big-endian uint64 (EventCount, OriginatorCount).
func statsKey() []byte {
	return []byte{prefixGossipRoot, subStats}
}

// origExistsKey marks an originator as having at least one event.
// Written once (idempotent) so Append knows whether to bump the
// OriginatorCount stats counter.
func origExistsKey(originator string) []byte {
	if len(originator) > MaxOriginatorLen {
		originator = originator[:MaxOriginatorLen]
	}
	k := make([]byte, 2+2+len(originator))
	k[0] = prefixGossipRoot
	k[1] = subOrigExists
	binary.BigEndian.PutUint16(k[2:4], uint16(len(originator)))
	copy(k[4:], originator)
	return k
}

// allHeadsPrefix scans every head record (used by Stats to populate
// the Heads map).
func allHeadsPrefix() []byte {
	return []byte{prefixGossipRoot, subHead}
}

// headRecord is the on-disk encoding for the per-originator head
// pointer: 32 byte prevHash || 8 byte lamport (big-endian).
type headRecord struct {
	prevHash [32]byte
	lamport  uint64
}

func encodeHead(h headRecord) []byte {
	out := make([]byte, 40)
	copy(out[:32], h.prevHash[:])
	binary.BigEndian.PutUint64(out[32:], h.lamport)
	return out
}

func decodeHead(raw []byte) (headRecord, error) {
	if len(raw) != 40 {
		return headRecord{}, fmt.Errorf("gossipstore: head record length=%d, want 40", len(raw))
	}
	var h headRecord
	copy(h.prevHash[:], raw[:32])
	h.lamport = binary.BigEndian.Uint64(raw[32:])
	return h, nil
}

// statsRecord is the on-disk stats: EventCount + OriginatorCount.
type statsRecord struct {
	eventCount      uint64
	originatorCount uint64
}

func encodeStats(s statsRecord) []byte {
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out[:8], s.eventCount)
	binary.BigEndian.PutUint64(out[8:], s.originatorCount)
	return out
}

func decodeStats(raw []byte) (statsRecord, error) {
	if len(raw) != 16 {
		return statsRecord{}, fmt.Errorf("gossipstore: stats record length=%d, want 16", len(raw))
	}
	return statsRecord{
		eventCount:      binary.BigEndian.Uint64(raw[:8]),
		originatorCount: binary.BigEndian.Uint64(raw[8:]),
	}, nil
}

// originatorFromHeadKey extracts the originator from a 0x04 head
// key for use during Stats's heads map population.
func originatorFromHeadKey(k []byte) (string, error) {
	if len(k) < 4 || k[0] != prefixGossipRoot || k[1] != subHead {
		return "", fmt.Errorf("gossipstore: not a head key")
	}
	olen := binary.BigEndian.Uint16(k[2:4])
	if int(olen) != len(k)-4 {
		return "", fmt.Errorf("gossipstore: head key length mismatch")
	}
	return string(k[4 : 4+olen]), nil
}

// lamportFromChainKey extracts the lamport timestamp from a 0x02
// chain key. Used by IterSince when computing the next cursor.
func lamportFromChainKey(k []byte) (uint64, error) {
	if len(k) < 4 || k[0] != prefixGossipRoot || k[1] != subChain {
		return 0, fmt.Errorf("gossipstore: not a chain key")
	}
	olen := int(binary.BigEndian.Uint16(k[2:4]))
	if len(k) != 4+olen+8 {
		return 0, fmt.Errorf("gossipstore: chain key length mismatch")
	}
	return binary.BigEndian.Uint64(k[4+olen:]), nil
}
