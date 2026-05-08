/*
FILE PATH:

	api/tile_handler_test.go

DESCRIPTION:

	Tests for the Static-CT tile-serving handlers. Pin contracts:
	happy-path success, 404 on os.ErrNotExist, 400 on path-
	traversal attempts, Cache-Control header semantics, Range
	header support via http.ServeContent, nil-backend defensive
	503 path.

KEY ARCHITECTURAL DECISIONS:
  - Use a synthetic stubBackend (api/-local) to keep tests
    hermetic (no on-disk POSIX dir required). The interface is
    already small and test-friendly by design.
  - Each test exercises ONE invariant. No table-driven hybrid
    that masks which assertion failed.
  - Path-traversal tests cover stdlib mux's PathValue surface
    directly so the handler's defense doesn't depend on the
    mux reaching it cleanly.
*/
package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// -------------------------------------------------------------------------------------------------
// 1) Stub backend
// -------------------------------------------------------------------------------------------------

type stubTileBackend struct {
	checkpoint     []byte
	checkpointErr  error
	tiles          map[string][]byte
	tileNotFoundOK bool // when true, missing tiles return os.ErrNotExist
	pathSeen       string
}

func (s *stubTileBackend) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	if s.checkpointErr != nil {
		return nil, s.checkpointErr
	}
	if s.checkpoint == nil {
		return nil, os.ErrNotExist
	}
	return s.checkpoint, nil
}

func (s *stubTileBackend) ReadTileByPath(ctx context.Context, path string) ([]byte, error) {
	s.pathSeen = path
	if data, ok := s.tiles[path]; ok {
		return data, nil
	}
	if s.tileNotFoundOK {
		return nil, os.ErrNotExist
	}
	return nil, os.ErrNotExist
}

var _ TileBackend = (*stubTileBackend)(nil)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// -------------------------------------------------------------------------------------------------
// 2) Checkpoint handler
// -------------------------------------------------------------------------------------------------

func TestCheckpointHandler_HappyPath(t *testing.T) {
	t.Parallel()
	want := []byte("origin\n42\nroot==\n\n— signer base64sig\n")
	backend := &stubTileBackend{checkpoint: want}
	h := NewCheckpointHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/checkpoint", nil)
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "max-age=2") {
		t.Errorf("Cache-Control = %q; want contains max-age=2", rr.Header().Get("Cache-Control"))
	}
	if !equalBytes(rr.Body.Bytes(), want) {
		t.Errorf("body = %q; want %q", rr.Body.String(), string(want))
	}
}

func TestCheckpointHandler_NotFoundBeforeFirstIntegration(t *testing.T) {
	t.Parallel()
	backend := &stubTileBackend{} // checkpoint nil → ErrNotExist
	h := NewCheckpointHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/checkpoint", nil)
	h(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 before first integration", rr.Code)
	}
}

func TestCheckpointHandler_NilBackendReturns503(t *testing.T) {
	t.Parallel()
	h := NewCheckpointHandler(nil, quietLogger())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/checkpoint", nil)
	h(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("nil-backend status = %d, want 503", rr.Code)
	}
}

func TestCheckpointHandler_InternalError(t *testing.T) {
	t.Parallel()
	backend := &stubTileBackend{checkpointErr: errors.New("disk read failed")}
	h := NewCheckpointHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/checkpoint", nil)
	h(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 on backend error", rr.Code)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Tile handler — happy paths
// -------------------------------------------------------------------------------------------------

func TestTileHandler_HashTile_FullTileImmutable(t *testing.T) {
	t.Parallel()
	want := []byte("hash-tile-bytes")
	backend := &stubTileBackend{
		tiles: map[string][]byte{"tile/0/x001/067": want},
	}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := newTileReq(t, "0", "x001/067")
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("full tile Cache-Control = %q; want immutable", rr.Header().Get("Cache-Control"))
	}
	if backend.pathSeen != "tile/0/x001/067" {
		t.Errorf("backend path = %q; want %q", backend.pathSeen, "tile/0/x001/067")
	}
	if !equalBytes(rr.Body.Bytes(), want) {
		t.Errorf("body mismatch")
	}
}

func TestTileHandler_PartialTileShortCache(t *testing.T) {
	t.Parallel()
	want := []byte("partial-bytes")
	backend := &stubTileBackend{
		tiles: map[string][]byte{"tile/0/x001/067.p/42": want},
	}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := newTileReq(t, "0", "x001/067.p/42")
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "max-age=2") {
		t.Errorf("partial tile Cache-Control = %q; want short max-age",
			rr.Header().Get("Cache-Control"))
	}
}

func TestTileHandler_EntryBundleTile(t *testing.T) {
	t.Parallel()
	want := []byte("entry-tile-bytes")
	backend := &stubTileBackend{
		tiles: map[string][]byte{"tile/entries/x001/067": want},
	}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := newTileReq(t, "entries", "x001/067")
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !equalBytes(rr.Body.Bytes(), want) {
		t.Errorf("body mismatch")
	}
}

func TestTileHandler_NotFoundReturns404(t *testing.T) {
	t.Parallel()
	backend := &stubTileBackend{tileNotFoundOK: true}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := newTileReq(t, "0", "x001/067")
	h(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Path-traversal defense
// -------------------------------------------------------------------------------------------------

func TestTileHandler_RejectsPathTraversalInLevel(t *testing.T) {
	t.Parallel()
	backend := &stubTileBackend{}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := newTileReq(t, "..", "etc/passwd")
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 on .. level", rr.Code)
	}
	if backend.pathSeen != "" {
		t.Errorf("backend pathSeen = %q; backend should NOT have been called", backend.pathSeen)
	}
}

func TestTileHandler_RejectsPathTraversalInRest(t *testing.T) {
	t.Parallel()
	backend := &stubTileBackend{}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := newTileReq(t, "0", "../../etc/passwd")
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 on .. in rest", rr.Code)
	}
	if backend.pathSeen != "" {
		t.Errorf("backend pathSeen = %q; backend should NOT have been called", backend.pathSeen)
	}
}

func TestTileHandler_RejectsAbsolutePath(t *testing.T) {
	t.Parallel()
	backend := &stubTileBackend{}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := newTileReq(t, "0", "/etc/passwd")
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 on absolute path in rest", rr.Code)
	}
}

func TestTileHandler_RejectsNonPrintableInPath(t *testing.T) {
	t.Parallel()
	backend := &stubTileBackend{}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	// httptest.NewRequest refuses control bytes in the URL string,
	// so we construct a clean URL request and override
	// PathValue("level") with the hostile content directly. This
	// mirrors a hostile path that bypasses the URL-parser layer
	// (e.g., a custom listener / WAF rewrite that lets bytes
	// through).
	req := httptest.NewRequest(http.MethodGet, "/tile/x/x001/067", nil)
	req.SetPathValue("level", "0\x00bad")
	req.SetPathValue("rest", "x001/067")
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 on non-printable level", rr.Code)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Range header support
// -------------------------------------------------------------------------------------------------

func TestTileHandler_RangeHeaderHonored(t *testing.T) {
	t.Parallel()
	full := []byte("0123456789abcdef")
	backend := &stubTileBackend{
		tiles: map[string][]byte{"tile/0/x001/067": full},
	}
	h := NewTileHandler(backend, quietLogger())

	rr := httptest.NewRecorder()
	req := newTileReq(t, "0", "x001/067")
	req.Header.Set("Range", "bytes=4-9")
	h(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206 Partial Content; body=%q", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "456789" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "456789")
	}
}

// -------------------------------------------------------------------------------------------------
// 6) Path validators (unit-level)
// -------------------------------------------------------------------------------------------------

func TestValidPathSegment(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"0":       true,
		"5":       true,
		"entries": true,
		"":        false,
		".":       false,
		"..":      false,
		"a/b":     false,
		"a\\b":    false,
		"\x00":    false,
		"\x7F":    false, // DEL is non-printable
		"abcDEF":  true,
	}
	for in, want := range cases {
		if got := validPathSegment(in); got != want {
			t.Errorf("validPathSegment(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestValidRestPath(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"x001/067":      true,
		"x001/067.p/42": true,
		"":              false,
		"../etc":        false,
		"/abs":          false,
		"a/../b":        false,
		"x001/067 abc":  false, // space rejected
	}
	for in, want := range cases {
		if got := validRestPath(in); got != want {
			t.Errorf("validRestPath(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestIsPartialTilePath(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"x001/067":      false,
		"x001/067.p/42": true,
		"x001/067p/42":  false, // no dot
		".p/":           true,
	}
	for in, want := range cases {
		if got := isPartialTilePath(in); got != want {
			t.Errorf("isPartialTilePath(%q) = %v; want %v", in, got, want)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 7) Helpers
// -------------------------------------------------------------------------------------------------

// newTileReq builds a *http.Request with PathValue("level") and
// PathValue("rest") set as the live mux would. Enables direct
// handler invocation without mounting the full mux.
func newTileReq(t *testing.T, level, rest string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/tile/"+level+"/"+rest, nil)
	req.SetPathValue("level", level)
	req.SetPathValue("rest", rest)
	return req
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
