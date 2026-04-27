/*
FILE PATH: bytestore/bytestore.go

Package bytestore is the operator's wire-byte storage abstraction.

Tessera-alignment invariant: entries are opaque []byte blobs keyed
by sequence number — identical to the upstream Tessera library's
storage shape (driver.Add takes []byte, driver.ReadEntries returns
[]byte). The byte store has no knowledge of envelope structure;
whatever bytes are written are what reads return.

Under v7.75 the wire bytes ARE the canonical bytes (the multi-sig
section is appended INSIDE the canonical form by envelope.Serialize),
so a single blob carries everything a consumer needs; envelope
.Deserialize recovers the structure on the read path.

KEY ARCHITECTURAL DECISIONS:
  - Single-blob storage: no internal length-prefix codec.
  - Reader / Writer / Store split lets callers narrow the surface
    they depend on (admission only needs Writer; the read path
    only needs Reader; tests typically need Store).
  - Implementations live in their own files: gcs.go (production),
    memory.go (tests + local dev). The Memory impl is exported so
    tests across packages can construct one without an internal
    package; production code is forbidden from importing it (lint
    rule: bytestore.Memory is allowed only in *_test.go).

DEPENDENCIES:
  - api/submission.go: writes wire bytes via Writer.WriteEntry.
  - store/entries.go: reads wire bytes via Reader.ReadEntry.
  - store/indexes/query_api.go: batches reads via Reader.ReadEntryBatch.
  - cmd/operator/main.go: composition root wires GCS in production.
*/
package bytestore

// Reader returns wire bytes for an entry by sequence number.
type Reader interface {
	// ReadEntry returns the wire bytes for seq. Returns an error
	// wrapping a not-found sentinel when the entry is absent.
	ReadEntry(seq uint64) ([]byte, error)

	// ReadEntryBatch returns wire bytes for each seq in the same
	// order as the input slice. Any missing sequence is a fatal
	// error for the whole batch (callers don't get a silent short
	// slice).
	ReadEntryBatch(seqs []uint64) ([][]byte, error)
}

// Writer stores wire bytes for an entry. Called at admission time.
type Writer interface {
	WriteEntry(seq uint64, wireBytes []byte) error
}

// Store is the union: an implementation that can both read and write.
// Most production wiring uses Store; tests do too. Library callers
// that only need one side narrow to Reader or Writer.
type Store interface {
	Reader
	Writer
}
