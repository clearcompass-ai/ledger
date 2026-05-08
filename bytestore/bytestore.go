/*
FILE PATH: bytestore/bytestore.go

Package bytestore is the ledger's wire-byte storage abstraction.

HEXAGONAL DESIGN:

	The ledger depends only on the interfaces defined here. Adapters
	(gcs.go, s3.go, memory.go) live in this package but are
	interchangeable through the factory (factory.go). Production
	swaps backends via LEDGER_BYTE_STORE_BACKEND={gcs|s3} without
	touching admission, builder, or read code.

	Why both GCS and S3:
	  - GCS native: workload identity / ADC on GCE/GKE; integrates
	    with Google's IAM signed-URL primitive natively.
	  - S3 (AWS SDK v2): same wire as RustFS / Cloudflare R2 /
	    AWS S3. Local-dev gets a paved path via a RustFS container;
	    future cloud migrations don't require a code change.

TESSERA-ALIGNMENT INVARIANT:

	Entries are opaque []byte blobs keyed by (sequence, hash) — the
	same shape upstream Tessera consumes. The byte store has no
	knowledge of envelope structure; whatever bytes are written are
	what reads return.

	Under the wire bytes ARE the canonical bytes (the multi-sig
	section is appended INSIDE the canonical form by envelope.Serialize),
	so a single blob carries everything a consumer needs;
	envelope.Deserialize recovers the structure on the read path.

OBJECT KEY SHAPE:

	All adapters use the same path layout via layoutKey:

	  <prefix>/<seq:016x>/<hash_hex>

	Hash in the path is what makes the 302 redirect path safe: the
	consumer can verify statically that the URL points at the bytes
	the ledger promised, before fetching. Adapters MUST use
	layoutKey for the canonical name so a bucket written by one
	adapter is readable by any other (useful for migrations).

INTERFACE SURFACE:
  - Reader: ReadEntry, ReadEntryBatch — opaque byte fetch
  - Writer: WriteEntry — opaque byte write
  - PublicURLer: PublicURL — credential-free monitor URL
    (transparency-log convention; see publicurl.go)
  - Store = Reader + Writer (test/dev impls satisfy this)
  - Backend = Store + PublicURLer (production impls satisfy this)

DEPENDENCIES:
  - api/submission.go: writes via Writer.WriteEntry.
  - api/entries.go: 302 redirect to PublicURLer.PublicURL for
    shipped entries; inline serve via Reader for un-shipped.
  - store/entries.go + store/indexes/query_api.go: read via Reader.
  - shipper/: writes via Writer; reads via WAL (this package only
    sees the upload side).
*/
package bytestore

import (
	"context"
	"encoding/hex"
	"fmt"
)

// EntryRef pairs a sequence number with the entry's identity hash
// (envelope.EntryIdentity = SHA-256 of canonical bytes). Both are
// required to construct the storage key and to let consumers
// statically verify the URL points at the promised bytes before
// fetching.
type EntryRef struct {
	Seq  uint64
	Hash [32]byte
}

// Reader returns wire bytes for an entry by (seq, hash). Returns an
// error wrapping a not-found sentinel when the entry is absent at
// the constructed path.
//
// The reader is opaque w.r.t. envelope structure: it returns whatever
// bytes were written. Callers that need to inspect the entry
// (signatures, header fields, payload) call envelope.Deserialize on
// the result.
type Reader interface {
	ReadEntry(ctx context.Context, seq uint64, hash [32]byte) ([]byte, error)

	// ReadEntryBatch returns wire bytes for each ref in the same
	// order as the input slice. Any missing entry is a fatal error
	// for the whole batch.
	ReadEntryBatch(ctx context.Context, refs []EntryRef) ([][]byte, error)
}

// Writer stores wire bytes for an entry. Called by admission (one
// blob per entry) and by the shipper (when migrating from WAL).
type Writer interface {
	WriteEntry(ctx context.Context, seq uint64, hash [32]byte, wireBytes []byte) error
}

// Store is the union of Reader + Writer. Test/dev implementations
// satisfy this (Memory). Production implementations also satisfy
// Backend (Store + PublicURLer).
type Store interface {
	Reader
	Writer
}

// Backend is what production wiring depends on: full Store + a
// credential-free monitor URL composer for the read path's 302
// redirect.
//
// The 302 path serves a transparency-log architecture: tile and
// entry buckets are anonymous-read by design (RFC 9162,
// c2sp.org/tlog-tiles). Anyone — witness, auditor, third-party
// monitor — can fetch entries directly via the public URL.
// Presigning would be over-credentialed for public buckets and
// architecturally wrong for transparency mode.
//
// PublicURLer lives in publicurl.go.
type Backend interface {
	Store
	PublicURLer
}

// layoutKey returns the canonical object name for an entry. ALL
// adapters MUST use this function so a bucket written by one
// adapter is readable by any other.
//
// The shape is:
//
//	<prefix>/<seq:016x>/<hash_hex>
//
// Zero-padded hex sequence sorts lexically the same way it sorts
// numerically — useful for ad-hoc gsutil/aws ls inspection. The
// hash suffix is what makes the 302 redirect safe (consumers can
// statically verify the URL points at the promised hash).
func layoutKey(prefix string, seq uint64, hash [32]byte) string {
	return fmt.Sprintf("%s/%016x/%s", prefix, seq, hex.EncodeToString(hash[:]))
}

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrNotFound is wrapped by adapters when a requested entry isn't in
// the bucket. Callers test with errors.Is(err, ErrNotFound).
//
// GCS adapters wrap storage.ErrObjectNotExist; S3 adapters wrap the
// AWS SDK's NotFound error. Both forms also unwrap to ErrNotFound so
// caller code can stay backend-agnostic.
var ErrNotFound = fmt.Errorf("bytestore: entry not found")
