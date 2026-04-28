/*
FILE PATH: wal/meta.go

Meta record encoding for entry state.

Wire format (binary, fixed-prefix):

  [1 byte state] [8 bytes seq big-endian] [4 bytes attempts] [8 bytes lastErrTs unix-nano]

Total: 21 bytes. Fixed-width so iterators can decode without bounds-
checking in the hot path. The format is internal — Badger keys + values
are not exposed outside the wal package.
*/
package wal

import (
	"encoding/binary"
	"fmt"
	"time"
)

// EntryState is the state-machine value stored in meta:<hash>.
type EntryState uint8

const (
	// StateUnknown is the zero value; never written to disk. Reading
	// state==StateUnknown indicates a decode bug or a corrupt record.
	StateUnknown EntryState = 0

	// StatePending: WAL has the bytes durably; tessera.Add not yet
	// confirmed. Inflight breadcrumb is set in this state.
	StatePending EntryState = 1

	// StateSequenced: tessera.Add returned a sequence; the entry is
	// committed to the log's order. Bytes still live in the WAL until
	// the Shipper migrates them.
	StateSequenced EntryState = 2

	// StateShipped: bytestore upload succeeded. The Shipper transitions
	// here AND advances HWM (when contiguous).
	StateShipped EntryState = 3

	// StateManual: Shipper has retried N times and given up; bytes
	// stay in the WAL pending operator intervention. Reads still
	// succeed via the WAL (no DLQ — the operator's manual-intervention
	// queue is metric-only).
	StateManual EntryState = 4
)

// String renders the state for logging.
func (s EntryState) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateSequenced:
		return "sequenced"
	case StateShipped:
		return "shipped"
	case StateManual:
		return "manual"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// Meta is the in-memory representation of meta:<hash>. The disk
// encoding is fixed-width binary (see metaEncodedSize).
type Meta struct {
	State      EntryState
	Sequence   uint64    // valid iff State >= StateSequenced
	Attempts   uint32    // shipper retry counter
	LastErrTs  time.Time // wall-clock of last error; zero on success
}

// metaEncodedSize is the on-disk size of a Meta record.
const metaEncodedSize = 1 + 8 + 4 + 8

// encodeMeta serializes Meta to fixed-width binary.
func encodeMeta(m Meta) []byte {
	buf := make([]byte, metaEncodedSize)
	buf[0] = byte(m.State)
	binary.BigEndian.PutUint64(buf[1:9], m.Sequence)
	binary.BigEndian.PutUint32(buf[9:13], m.Attempts)
	if m.LastErrTs.IsZero() {
		// Zero time → store as 0 nanos (vs. UnixNano() which would
		// be a large negative pre-1970 value for some clock states).
		binary.BigEndian.PutUint64(buf[13:21], 0)
	} else {
		binary.BigEndian.PutUint64(buf[13:21], uint64(m.LastErrTs.UnixNano()))
	}
	return buf
}

// decodeMeta parses a fixed-width meta record.
func decodeMeta(buf []byte) (Meta, error) {
	if len(buf) != metaEncodedSize {
		return Meta{}, fmt.Errorf("wal/meta: bad length %d, want %d", len(buf), metaEncodedSize)
	}
	m := Meta{
		State:    EntryState(buf[0]),
		Sequence: binary.BigEndian.Uint64(buf[1:9]),
		Attempts: binary.BigEndian.Uint32(buf[9:13]),
	}
	if ns := int64(binary.BigEndian.Uint64(buf[13:21])); ns != 0 {
		m.LastErrTs = time.Unix(0, ns).UTC()
	}
	return m, nil
}
