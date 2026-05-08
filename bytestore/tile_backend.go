/*
FILE PATH:

	bytestore/tile_backend.go

DESCRIPTION:

	The TileBackend interface — the storage-side contract behind
	the ledger's Static-CT tile-serving HTTP routes (api/
	tile_handler.go). Implementations:

	    *tessera.POSIXTileBackend    (POSIX directory)
	    *bytestore.GCSTiles          (GCS object store, this package)

	Auditors fetch tiles via the SDK's log/tessera_fetcher.go
	primitive at known c2sp.org/tlog-tiles paths. The HTTP layer
	consumes a TileBackend; the backend is opaque about whether
	the bytes come from disk, cloud, or memory.

KEY ARCHITECTURAL DECISIONS:
  - Defined in bytestore (not api) so the compile-time
    interface guard `var _ TileBackend = (*GCSTiles)(nil)` lives
    with the implementation. The api package consumes the
    interface; bytestore owns it.
  - Two methods only. Read-only. The ledger never writes tiles
    via this interface — Tessera owns tile writes (via its own
    storage driver). Reads are the exclusively-served surface
    for /checkpoint and /tile/{level}/{rest...}.
  - os.ErrNotExist verbatim signaling: the SDK's
    log/tessera_fetcher.fetchTesseraTile expects errors.Is(err,
    os.ErrNotExist) to drive the partial-then-full fallback.
    Implementations MUST translate their underlying "not found"
    sentinel (storage.ErrObjectNotExist for GCS, the kernel's
    ENOENT for POSIX) to os.ErrNotExist.

OVERVIEW:

	Used by api.NewCheckpointHandler and api.NewTileHandler to
	serve the c2sp.org/tlog-tiles HTTP routes. The interface is
	deliberately tiny — anything beyond reading a path or the
	canonical checkpoint belongs in a richer storage interface,
	not this one.

KEY DEPENDENCIES:
  - context.Context: bounded I/O timeout discipline.
  - os.ErrNotExist: canonical "tile absent" signal.
*/
package bytestore

import "context"

// -------------------------------------------------------------------------------------------------
// 1) TileBackend
// -------------------------------------------------------------------------------------------------

// TileBackend is the read-only contract behind the ledger's
// Static-CT tile-serving HTTP routes.
//
// Implementations:
//
//   - *tessera.POSIXTileBackend reads from a local POSIX
//     directory. Default for in-binary deployments.
//
//   - *bytestore.GCSTiles reads from a GCS bucket prefix.
//     Production deployments where Tessera writes tiles
//     directly to GCS (or where an external sync mirrors the
//     POSIX dir into GCS) use this.
//
// Both ReadTileByPath and ReadCheckpoint MUST translate their
// backend-specific "not found" sentinel to os.ErrNotExist so
// callers (the SDK's log/tessera_fetcher.go included) can drive
// the partial-then-full fallback via errors.Is(err, os.ErrNotExist).
type TileBackend interface {
	// ReadTileByPath returns the bytes of a c2sp.org/tlog-tiles
	// path (e.g., "tile/0/x001/067" or "tile/entries/x001/067").
	// Returns os.ErrNotExist when the tile is absent.
	ReadTileByPath(ctx context.Context, path string) ([]byte, error)

	// ReadCheckpoint returns the bytes of the canonical
	// c2sp.org/tlog-tiles signed checkpoint. Returns
	// os.ErrNotExist before the first checkpoint is published
	// (typical at fresh boot).
	ReadCheckpoint(ctx context.Context) ([]byte, error)
}
