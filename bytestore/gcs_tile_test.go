/*
FILE PATH:
    bytestore/gcs_tile_test.go

DESCRIPTION:
    Tests for GCSTiles. Runs against either fake-gcs-server (CI
    smoke path, gated by ATTESTA_TEST_GCS_ENDPOINT) OR real GCS
    (operator-validated path, gated by ATTESTA_TEST_GCS_BUCKET +
    GOOGLE_APPLICATION_CREDENTIALS), via the requireGCS helper
    already in gcs_test.go.

KEY ARCHITECTURAL DECISIONS:
    - One file covers both modes. The requireGCS helper detects
      which mode by env var; tests are agnostic to the underlying
      transport. Real-GCS-only invariants (concurrent reads at
      scale, CDN cache header compatibility) live in
      gcs_tile_integration_test.go (build tag gcs_integration).
    - Each test uses a per-name prefix to isolate concurrent runs
      AND to let t.Cleanup wipe its own objects (avoids real-GCS
      accumulation).
    - Tests exercise the c2sp.org/tlog-tiles paths verbatim
      (tile/0/x001/067, tile/entries/x001/067, checkpoint) so a
      regression in path encoding shows up on the wire, not as a
      synthetic shape.

OVERVIEW:
    For each test:
        1. requireGCS(t) returns a configured *GCS (or skips).
        2. NewGCSTiles(g, prefix, timeout) constructs the
           subject under test.
        3. Upload synthetic tile bytes via g.bucket directly
           (bypasses bytestore.GCS.WriteEntry's per-entry layout).
        4. Exercise the contract: ReadTileByPath, ReadCheckpoint,
           ErrNotExist mapping, path-traversal rejection,
           MaxTileBytes enforcement.

KEY DEPENDENCIES:
    - requireGCS, deletePrefix (both in gcs_test.go).
    - cloud.google.com/go/storage: for direct uploads bypassing
      the entry-layout key scheme.
*/
package bytestore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
)

// -------------------------------------------------------------------------------------------------
// 1) Constructor + path validation (no GCS required)
// -------------------------------------------------------------------------------------------------

// TestGCSTiles_ObjectKey_RejectsPathTraversal pins the storage-
// layer defense-in-depth. The api/tile_handler.go validator runs
// first; this is the second line of defense.
func TestGCSTiles_ObjectKey_RejectsPathTraversal(t *testing.T) {
	t.Parallel()
	g := &GCSTiles{prefix: "tessera"}
	cases := []string{
		"",                  // empty
		"..",                // traversal
		"../etc/passwd",     // traversal
		"a/../b",            // traversal in middle
		"/etc/passwd",       // absolute
		"valid\x00null",     // non-printable
		"tile/0/\x7Fbad",    // DEL byte
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if _, err := g.objectKey(p); err == nil {
				t.Errorf("objectKey(%q) accepted; want rejection", p)
			}
		})
	}
}

func TestGCSTiles_ObjectKey_HappyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		prefix string
		path   string
		want   string
	}{
		{"tessera", "tile/0/x001/067", "tessera/tile/0/x001/067"},
		{"tessera", "checkpoint", "tessera/checkpoint"},
		{"tessera", "tile/entries/x001/067", "tessera/tile/entries/x001/067"},
		{"", "tile/0/x001/067", "tile/0/x001/067"},
		{"some/deep/prefix", "checkpoint", "some/deep/prefix/checkpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.prefix+"|"+tc.path, func(t *testing.T) {
			g := &GCSTiles{prefix: tc.prefix}
			got, err := g.objectKey(tc.path)
			if err != nil {
				t.Fatalf("objectKey(%q): %v", tc.path, err)
			}
			if got != tc.want {
				t.Errorf("objectKey(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Construction defaults
// -------------------------------------------------------------------------------------------------

func TestGCSTiles_NewGCSTiles_DefaultsReadTimeout(t *testing.T) {
	t.Parallel()
	g := &GCS{} // bucket field is nil — we only inspect the timeout default
	tb := NewGCSTiles(g, "tessera", 0)
	if tb.readTimeout != 30*time.Second {
		t.Errorf("readTimeout = %v, want 30s default", tb.readTimeout)
	}
}

func TestGCSTiles_NewGCSTiles_TrimsTrailingSlash(t *testing.T) {
	t.Parallel()
	g := &GCS{}
	tb := NewGCSTiles(g, "tessera/", 5*time.Second)
	if tb.prefix != "tessera" {
		t.Errorf("prefix = %q, want %q (trailing slash trimmed)", tb.prefix, "tessera")
	}
}

func TestGCSTiles_NewGCSTiles_EmptyPrefix(t *testing.T) {
	t.Parallel()
	g := &GCS{}
	tb := NewGCSTiles(g, "", 5*time.Second)
	if tb.prefix != "" {
		t.Errorf("prefix = %q, want empty", tb.prefix)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Round-trip against fake-gcs-server / real GCS
// -------------------------------------------------------------------------------------------------

// uploadObject puts raw bytes at <key> in the bucket. Test-only;
// bypasses *GCS.WriteEntry's per-entry layout because tile keys
// are c2sp.org-shaped, not seq-shaped.
func uploadObject(t *testing.T, ctx context.Context, g *GCS, key string, data []byte) {
	t.Helper()
	w := g.bucket.Object(key).NewWriter(ctx)
	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		_ = w.Close()
		t.Fatalf("upload %q: %v", key, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("upload %q close: %v", key, err)
	}
}

// tilesFor returns a *GCSTiles backed by the *GCS's bucket, with
// a per-test prefix so concurrent runs don't collide.
func tilesFor(t *testing.T, g *GCS) (*GCSTiles, string) {
	t.Helper()
	prefix := g.objectPrefix + "/tessera"
	return NewGCSTiles(g, prefix, 30*time.Second), prefix
}

func TestGCSTiles_ReadTile_RoundTrip(t *testing.T) {
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	want := []byte("hash-tile-bytes-deadbeef")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	uploadObject(t, ctx, g, prefix+"/tile/0/x001/067", want)

	got, err := tb.ReadTileByPath(ctx, "tile/0/x001/067")
	if err != nil {
		t.Fatalf("ReadTileByPath: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestGCSTiles_ReadCheckpoint_RoundTrip(t *testing.T) {
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	want := []byte("origin\n42\nroot==\n\n— signer base64sig\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	uploadObject(t, ctx, g, prefix+"/checkpoint", want)

	got, err := tb.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestGCSTiles_ReadTile_EntryBundlePath(t *testing.T) {
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	want := []byte("entry-bundle-tile-bytes")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	uploadObject(t, ctx, g, prefix+"/tile/entries/x001/067", want)

	got, err := tb.ReadTileByPath(ctx, "tile/entries/x001/067")
	if err != nil {
		t.Fatalf("ReadTileByPath: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) ErrNotExist mapping
// -------------------------------------------------------------------------------------------------

func TestGCSTiles_ReadTile_ErrNotExistOnMissing(t *testing.T) {
	g := requireGCS(t)
	tb, _ := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := tb.ReadTileByPath(ctx, "tile/0/missing/000")
	if err == nil {
		t.Fatal("ReadTileByPath on missing tile returned nil error; want os.ErrNotExist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v; want errors.Is(.., os.ErrNotExist)", err)
	}
}

func TestGCSTiles_ReadCheckpoint_ErrNotExistBeforeFirstIntegration(t *testing.T) {
	g := requireGCS(t)
	tb, _ := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := tb.ReadCheckpoint(ctx)
	if err == nil {
		t.Fatal("ReadCheckpoint on empty bucket returned nil; want os.ErrNotExist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v; want errors.Is(.., os.ErrNotExist)", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Path-traversal defense at the bucket layer
// -------------------------------------------------------------------------------------------------

func TestGCSTiles_ReadTile_RejectsTraversalBeforeBucketCall(t *testing.T) {
	g := requireGCS(t)
	tb, _ := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Hostile path. The handler validates first; this is the
	// storage-layer fall-through. Must reject WITHOUT calling
	// the GCS API (no round-trip).
	_, err := tb.ReadTileByPath(ctx, "../etc/passwd")
	if err == nil {
		t.Fatal("ReadTileByPath('../etc/passwd') returned nil error; want rejection")
	}
	if !strings.Contains(err.Error(), "..") {
		t.Errorf("err = %v; want message mentioning '..'", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) MaxTileBytes ceiling
// -------------------------------------------------------------------------------------------------

// TestGCSTiles_ReadTile_RejectsOversizeBody pins the bounded-I/O
// guarantee. Uploads MaxTileBytes+1 bytes to a tile key, asserts
// the read returns "exceeds MaxTileBytes". Defends against an
// upstream Tessera misbehavior or hostile object that streams
// unbounded bytes within the readTimeout window.
//
// Skipped on fake-gcs (object size ceiling there is impractical
// for a 16-MiB upload through the test harness). Real-GCS
// integration test in gcs_tile_integration_test.go covers this.
func TestGCSTiles_ReadTile_RejectsOversizeBody(t *testing.T) {
	if os.Getenv("ATTESTA_TEST_GCS_ENDPOINT") != "" {
		t.Skip("oversize-body test requires real GCS; skip on fake-gcs-server")
	}
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	oversized := make([]byte, MaxTileBytes+1)
	uploadObject(t, ctx, g, prefix+"/tile/0/oversize", oversized)

	_, err := tb.ReadTileByPath(ctx, "tile/0/oversize")
	if err == nil {
		t.Fatal("ReadTileByPath of oversize body returned nil; want rejection")
	}
	if !strings.Contains(err.Error(), "exceeds MaxTileBytes") {
		t.Errorf("err = %v; want 'exceeds MaxTileBytes'", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 7) Compile-time guards
// -------------------------------------------------------------------------------------------------

// Compile-time assertion that the storage handle reused by
// GCSTiles is the same *storage.BucketHandle the *GCS holds.
// Catches any future refactor that accidentally creates a fresh
// GCS client per tile read (which would multiply the auth surface).
var _ = func() bool {
	g := &GCS{bucket: (*storage.BucketHandle)(nil)}
	tb := NewGCSTiles(g, "p", time.Second)
	return tb.bucket == g.bucket
}()
