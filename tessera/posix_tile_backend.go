/*
FILE PATH: tessera/posix_tile_backend.go

POSIXTileBackend — filesystem-backed TileBackend.

WHY THIS EXISTS:

	The ledger embeds the Tessera library in-process. When Tessera
	is configured with the POSIX storage driver, it writes tiles,
	entry bundles, and the checkpoint file into a directory tree
	following the c2sp.org/tlog-tiles layout EXACTLY:

	  <root>/checkpoint
	  <root>/tile/<level>/<index_groups>/<final>
	  <root>/tile/entries/<index_groups>/<final>

	The path scheme is identical to what the personality's
	http.FileServer used to expose. So the ledger can read the
	same files directly from the local filesystem, bypassing HTTP
	entirely. Same correctness, lower latency, no network failure
	modes.

INVARIANTS:
  - rootDir is the Tessera storage directory passed to
    posix.New(ctx, posix.Config{Path: rootDir}).
  - The path argument to ReadTileByPath is c2sp.org-encoded and
    interpreted as a relative path under rootDir. Path traversal
    (e.g., "../etc/passwd") is rejected by filepath.Clean +
    prefix-check before any file is opened.
  - Returns os.ErrNotExist for missing tiles. Callers (TileReader,
    proof computation) treat this as "not yet committed" and
    surface it to the user without crashing.

THREAD SAFETY:

	os.ReadFile is goroutine-safe. No state in *POSIXTileBackend.
	Multiple TileReader instances or concurrent reads from the
	same instance are safe.

ALTERNATIVES CONSIDERED:
  - Using upstream tessera.LogReader (returned from NewAppender)
    instead of reading files directly. LogReader provides
    ReadTile / ReadEntryBundle keyed by (level, index, p uint8)
    instead of paths. Bridging to the ledger's path-based
    TileBackend interface would require parsing the c2sp.org
    path back into the (level, index, p) tuple — a detour that
    adds no value while POSIX is the only Tessera backend. Once
    a remote Tessera storage driver (GCS / S3) is wired the
    ledger can switch to a LogReader-backed TileBackend without
    touching proof_adapter.go's call sites.
*/
package tessera

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// POSIXTileBackend reads tlog-tiles tiles, entry bundles, and the
// checkpoint from a local filesystem directory.
type POSIXTileBackend struct {
	rootDir string
}

// NewPOSIXTileBackend constructs a POSIX-backed tile reader for
// the supplied directory. The directory must be the same path
// the embedded Tessera POSIX driver writes to.
//
// Returns an error if rootDir is empty or does not exist —
// caller-facing fail-fast at startup beats a silent stream of
// "tile not found" errors at runtime.
func NewPOSIXTileBackend(rootDir string) (*POSIXTileBackend, error) {
	if rootDir == "" {
		return nil, fmt.Errorf("tessera: NewPOSIXTileBackend requires non-empty rootDir")
	}
	abs, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("tessera: rootDir abs: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("tessera: rootDir stat %q: %w", abs, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("tessera: rootDir %q is not a directory", abs)
	}
	return &POSIXTileBackend{rootDir: abs}, nil
}

// ReadTileByPath reads a tile file at <rootDir>/<path>.
//
// path is c2sp.org-encoded (e.g., "tile/0/x001/067" or
// "tile/entries/x001/067"). The leading "tile/" component is
// part of the path; this function does NOT prepend it.
//
// Path traversal protection: filepath.Clean reduces the path to
// canonical form, then we re-verify the result still falls under
// rootDir before opening any file. Without this check a path
// like "../../etc/passwd" would escape the storage directory.
//
// Returns os.ErrNotExist when the file is absent — the standard
// signal callers use to distinguish "not yet integrated" from
// "real I/O error."
func (b *POSIXTileBackend) ReadTileByPath(ctx context.Context, path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("tessera/posix: ReadTileByPath requires non-empty path")
	}

	clean := filepath.Clean(path)
	// Reject absolute paths and traversal upfront.
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return nil, fmt.Errorf("tessera/posix: rejected path traversal: %q", path)
	}

	full := filepath.Join(b.rootDir, clean)

	// Defense in depth: verify the joined path stays under rootDir
	// even after Join's normalization.
	if !strings.HasPrefix(full, b.rootDir+string(filepath.Separator)) && full != b.rootDir {
		return nil, fmt.Errorf("tessera/posix: rejected path traversal: %q", path)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(full)
	if err != nil {
		// Surface os.ErrNotExist verbatim so callers can
		// errors.Is(err, os.ErrNotExist) without unwrapping.
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("tessera/posix: read %q: %w", full, err)
	}
	return data, nil
}

// ReadCheckpoint returns the bytes of <rootDir>/checkpoint —
// the c2sp.org/tlog-tiles signed checkpoint Tessera writes after
// each integration cycle. Convenience wrapper around
// ReadTileByPath that callers can use without knowing the exact
// filename ("checkpoint", per the spec).
//
// Returns os.ErrNotExist before the first checkpoint is written
// — typical at fresh-boot before any entries have been admitted.
func (b *POSIXTileBackend) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	return b.ReadTileByPath(ctx, "checkpoint")
}

// RootDir returns the absolute path the backend was constructed
// with. Useful for logging at startup so the audit trail shows
// where tiles are landing on disk.
func (b *POSIXTileBackend) RootDir() string {
	return b.rootDir
}

// Compile-time pin: POSIXTileBackend satisfies the existing
// TileBackend contract used by TileReader. If the interface
// changes upstream, this fails at build time before TileReader's
// call site does.
var _ TileBackend = (*POSIXTileBackend)(nil)
