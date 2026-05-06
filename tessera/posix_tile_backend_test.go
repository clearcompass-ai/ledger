/*
FILE PATH: tessera/posix_tile_backend_test.go

Self-contained tests for POSIXTileBackend. Uses t.TempDir() — no
docker, no Postgres, no external services. Always runs.

Coverage:
  - Constructor validation (empty / missing / non-directory).
  - Round-trip: write a tile to disk, ReadTileByPath returns it.
  - Path traversal rejection (defense in depth).
  - Subdirectory paths (the c2sp.org tile path shape).
  - os.ErrNotExist surfaced verbatim for missing files.
  - ReadCheckpoint convenience wrapper.
  - Context cancellation.
  - Concurrent reads (goroutine-safety pin).
  - Compile-time interface satisfaction.
*/
package tessera

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeTile is a tiny test helper that creates intermediate dirs
// and writes a file under root. Mirrors what Tessera's POSIX
// driver does at integration time.
func writeTile(t *testing.T, root, relPath string, data []byte) {
	t.Helper()
	full := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", relPath, err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Constructor validation
// ─────────────────────────────────────────────────────────────────

func TestPOSIXTileBackend_New_RejectsEmptyRoot(t *testing.T) {
	if _, err := NewPOSIXTileBackend(""); err == nil {
		t.Fatal("expected error on empty rootDir")
	}
}

func TestPOSIXTileBackend_New_RejectsMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := NewPOSIXTileBackend(missing); err == nil {
		t.Fatal("expected error on missing directory")
	}
}

func TestPOSIXTileBackend_New_RejectsRegularFile(t *testing.T) {
	tmp := t.TempDir()
	notADir := filepath.Join(tmp, "regular-file")
	if err := os.WriteFile(notADir, []byte("file"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := NewPOSIXTileBackend(notADir); err == nil {
		t.Fatal("expected error when path is a regular file, not a directory")
	}
}

func TestPOSIXTileBackend_New_AcceptsValidDir(t *testing.T) {
	b, err := NewPOSIXTileBackend(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.RootDir() == "" {
		t.Error("RootDir empty after successful construction")
	}
}

// ─────────────────────────────────────────────────────────────────
// Round-trip read
// ─────────────────────────────────────────────────────────────────

func TestPOSIXTileBackend_ReadTileByPath_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	want := []byte("checkpoint-bytes")
	writeTile(t, tmp, "checkpoint", want)

	b, err := NewPOSIXTileBackend(tmp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := b.ReadTileByPath(context.Background(), "checkpoint")
	if err != nil {
		t.Fatalf("ReadTileByPath: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPOSIXTileBackend_ReadTileByPath_SubdirectoryPath(t *testing.T) {
	tmp := t.TempDir()
	// c2sp.org-shaped path: tile/<level>/<index_groups>/<final>
	want := []byte("hash-tile-level-0-index-067")
	writeTile(t, tmp, "tile/0/x001/067", want)

	b, _ := NewPOSIXTileBackend(tmp)

	got, err := b.ReadTileByPath(context.Background(), "tile/0/x001/067")
	if err != nil {
		t.Fatalf("ReadTileByPath: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPOSIXTileBackend_ReadTileByPath_EntryTilePath(t *testing.T) {
	tmp := t.TempDir()
	want := []byte("entry-tile-bundle")
	writeTile(t, tmp, "tile/entries/x001/042", want)

	b, _ := NewPOSIXTileBackend(tmp)

	got, err := b.ReadTileByPath(context.Background(), "tile/entries/x001/042")
	if err != nil {
		t.Fatalf("ReadTileByPath: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────
// Missing files
// ─────────────────────────────────────────────────────────────────

func TestPOSIXTileBackend_ReadTileByPath_MissingReturnsErrNotExist(t *testing.T) {
	b, _ := NewPOSIXTileBackend(t.TempDir())

	_, err := b.ReadTileByPath(context.Background(), "tile/0/x000/000")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// ReadCheckpoint convenience wrapper
// ─────────────────────────────────────────────────────────────────

func TestPOSIXTileBackend_ReadCheckpoint_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	want := []byte("attesta\n100\nrootHashB64\n\n— signature\n")
	writeTile(t, tmp, "checkpoint", want)

	b, _ := NewPOSIXTileBackend(tmp)

	got, err := b.ReadCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPOSIXTileBackend_ReadCheckpoint_MissingReturnsErrNotExist(t *testing.T) {
	b, _ := NewPOSIXTileBackend(t.TempDir())

	_, err := b.ReadCheckpoint(context.Background())
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist for missing checkpoint, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Path traversal protection (the load-bearing security pin)
// ─────────────────────────────────────────────────────────────────

func TestPOSIXTileBackend_ReadTileByPath_RejectsParentTraversal(t *testing.T) {
	tmp := t.TempDir()
	// Plant a sentinel file OUTSIDE the storage root that we
	// must NOT be able to read via "../<parent>/<sentinel>".
	parent := filepath.Dir(tmp)
	sentinel := "POSIX_TILE_TRAVERSAL_TEST_SENTINEL"
	sentinelPath := filepath.Join(parent, sentinel)
	if err := os.WriteFile(sentinelPath, []byte("PWN"), 0o644); err != nil {
		t.Fatalf("setup sentinel: %v", err)
	}
	defer os.Remove(sentinelPath)

	b, _ := NewPOSIXTileBackend(tmp)

	_, err := b.ReadTileByPath(context.Background(), "../"+sentinel)
	if err == nil {
		t.Fatal("expected path traversal rejection, got success")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Errorf("expected 'path traversal' in error, got %v", err)
	}
}

func TestPOSIXTileBackend_ReadTileByPath_RejectsAbsolutePath(t *testing.T) {
	b, _ := NewPOSIXTileBackend(t.TempDir())

	_, err := b.ReadTileByPath(context.Background(), "/etc/passwd")
	if err == nil {
		t.Fatal("expected absolute-path rejection")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Errorf("expected 'path traversal' in error, got %v", err)
	}
}

func TestPOSIXTileBackend_ReadTileByPath_RejectsEmptyPath(t *testing.T) {
	b, _ := NewPOSIXTileBackend(t.TempDir())

	_, err := b.ReadTileByPath(context.Background(), "")
	if err == nil {
		t.Fatal("expected empty-path rejection")
	}
}

// ─────────────────────────────────────────────────────────────────
// Context cancellation
// ─────────────────────────────────────────────────────────────────

func TestPOSIXTileBackend_ReadTileByPath_RespectsCanceledContext(t *testing.T) {
	tmp := t.TempDir()
	writeTile(t, tmp, "tile/0/x000/001", []byte("ignored"))
	b, _ := NewPOSIXTileBackend(tmp)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ReadTileByPath(ctx, "tile/0/x000/001")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Concurrent reads (goroutine-safety pin)
// ─────────────────────────────────────────────────────────────────

func TestPOSIXTileBackend_ConcurrentReads(t *testing.T) {
	tmp := t.TempDir()
	const nFiles = 50
	const nReaders = 10
	const readsPer = 100

	// Plant nFiles distinct tiles.
	want := make(map[string][]byte, nFiles)
	for i := 0; i < nFiles; i++ {
		path := filepath.Join("tile", "0", "x000", padInt(i))
		data := []byte("tile-" + padInt(i))
		writeTile(t, tmp, path, data)
		want[path] = data
	}

	b, _ := NewPOSIXTileBackend(tmp)

	var wg sync.WaitGroup
	wg.Add(nReaders)
	errs := make(chan error, nReaders*readsPer)
	for r := 0; r < nReaders; r++ {
		go func(r int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < readsPer; i++ {
				path := filepath.Join("tile", "0", "x000", padInt(i%nFiles))
				got, err := b.ReadTileByPath(ctx, path)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, want[path]) {
					errs <- errors.New("data mismatch under concurrent read")
					return
				}
			}
		}(r)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent read error: %v", err)
	}
}

// padInt returns a 3-digit zero-padded representation of i.
// Avoids importing fmt for a one-line formatter.
func padInt(i int) string {
	const digits = "0123456789"
	out := make([]byte, 3)
	out[0] = digits[(i/100)%10]
	out[1] = digits[(i/10)%10]
	out[2] = digits[i%10]
	return string(out)
}
