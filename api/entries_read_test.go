/*
FILE PATH: api/entries_read_test.go

Evidence-based tests for the /v1/entries/{seq}/raw routing decision
matrix. The handler's correctness is encoded entirely in the
"which source serves the bytes?" decision, so tests focus on that:

  WAL state                 Presigner       Outcome
  ────────────────────────  ──────────────  ─────────────────────────
  StateSequenced            (any)           200 OK + WAL bytes inline
  StateManual               (any)           200 OK + WAL bytes inline
  StatePending              (any)           200 OK + WAL bytes inline (defensive)
  StateShipped              configured      302 + presigned URL
  StateShipped              nil             500 (loud misconfig)
  wal.ErrNotFound           configured      302 + presigned URL (post-GC path)
  wal.ErrNotFound           nil             500
  Postgres "no row at seq"  —               404
  Invalid seq in path       —               400

Tests bypass HTTP middleware by constructing http.Request directly
against the handler closure. Postgres is faked; WAL is faked; the
presigner is faked.
*/
package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

type fakeSeqHashLookup struct {
	hashesBySeq  map[uint64][32]byte
	logTimeBySeq map[uint64]time.Time
	err          error
}

func (f *fakeSeqHashLookup) FetchHashBySeq(_ context.Context, seq uint64) ([32]byte, time.Time, bool, error) {
	if f.err != nil {
		return [32]byte{}, time.Time{}, false, f.err
	}
	h, ok := f.hashesBySeq[seq]
	if !ok {
		return [32]byte{}, time.Time{}, false, nil
	}
	return h, f.logTimeBySeq[seq], true, nil
}

type fakeWAL struct {
	mu         sync.Mutex
	wires      map[[32]byte][]byte
	metas      map[[32]byte]wal.Meta
	notFound   map[[32]byte]bool // hashes for which MetaState returns wal.ErrNotFound
	hardErr    error
	readHardEr error
}

func newFakeWAL() *fakeWAL {
	return &fakeWAL{
		wires:    map[[32]byte][]byte{},
		metas:    map[[32]byte]wal.Meta{},
		notFound: map[[32]byte]bool{},
	}
}

func (f *fakeWAL) Read(_ context.Context, hash [32]byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readHardEr != nil {
		return nil, f.readHardEr
	}
	w, ok := f.wires[hash]
	if !ok {
		return nil, fmt.Errorf("fakeWAL: no wire: %w", wal.ErrNotFound)
	}
	cp := make([]byte, len(w))
	copy(cp, w)
	return cp, nil
}

func (f *fakeWAL) MetaState(_ context.Context, hash [32]byte) (wal.Meta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hardErr != nil {
		return wal.Meta{}, f.hardErr
	}
	if f.notFound[hash] {
		return wal.Meta{}, fmt.Errorf("fakeWAL: meta missing: %w", wal.ErrNotFound)
	}
	m, ok := f.metas[hash]
	if !ok {
		return wal.Meta{}, fmt.Errorf("fakeWAL: no meta: %w", wal.ErrNotFound)
	}
	return m, nil
}

type fakePresigner struct {
	urlByPair map[uint64]string
	err       error
}

func (f *fakePresigner) PresignGet(_ context.Context, seq uint64, _ [32]byte, _ time.Duration) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if u, ok := f.urlByPair[seq]; ok {
		return u, nil
	}
	return fmt.Sprintf("https://test.example/entries/%d/data?signed=true", seq), nil
}

// discardLogger silences the handler's slog noise during tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError + 1,
	}))
}

func hashFor(name string) [32]byte { return sha256.Sum256([]byte(name)) }

// makeRequest builds a *http.Request with the seq embedded in a way
// the handler can parse. The handler reads r.URL.Path and strips
// the /v1/entries/ prefix + /raw suffix; tests build URLs that
// match that shape.
func makeRequest(seq uint64) *http.Request {
	url := fmt.Sprintf("/v1/entries/%d/raw", seq)
	return httptest.NewRequest(http.MethodGet, url, nil)
}

func newDeps(t *testing.T) (*EntryReadDeps, *fakeSeqHashLookup, *fakeWAL, *fakePresigner) {
	t.Helper()
	store := &fakeSeqHashLookup{
		hashesBySeq:  map[uint64][32]byte{},
		logTimeBySeq: map[uint64]time.Time{},
	}
	w := newFakeWAL()
	p := &fakePresigner{urlByPair: map[uint64]string{}}
	deps := &EntryReadDeps{
		EntryStore: store,
		WAL:        w,
		Presigner:  p,
		Logger:     discardLogger(),
		PresignTTL: 1 * time.Hour,
	}
	return deps, store, w, p
}

// ─────────────────────────────────────────────────────────────────────
// 1) StateSequenced → 200 OK + inline WAL bytes
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_Sequenced_InlineFromWAL(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("entry-sequenced")
	wire := []byte("the durable wire bytes")
	store.hashesBySeq[42] = hash
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != string(wire) {
		t.Fatalf("body: got %q, want %q", got, wire)
	}
	if rec.Header().Get("X-Source") != "wal" {
		t.Errorf("X-Source: got %q, want wal", rec.Header().Get("X-Source"))
	}
}

func TestRawEntry_Manual_InlineFromWAL(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("entry-manual")
	wire := []byte("retry-exhausted-bytes")
	store.hashesBySeq[7] = hash
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateManual, Sequence: 7}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(7))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if rec.Body.String() != string(wire) {
		t.Fatal("body mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2) StateShipped + Presigner → 302 redirect
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_Shipped_RedirectVia302(t *testing.T) {
	deps, store, w, p := newDeps(t)

	hash := hashFor("entry-shipped")
	store.hashesBySeq[100] = hash
	w.metas[hash] = wal.Meta{State: wal.StateShipped, Sequence: 100}
	p.urlByPair[100] = "https://gcs.example/entries/100/abcd?Signature=..."

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(100))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://gcs.example/entries/100/abcd?Signature=..." {
		t.Fatalf("Location: got %q", got)
	}
	if rec.Header().Get("X-Source") != "bytestore" {
		t.Errorf("X-Source: got %q, want bytestore", rec.Header().Get("X-Source"))
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3) StateShipped + nil Presigner → 500 (loud misconfig)
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_Shipped_NoPresigner_Returns500(t *testing.T) {
	deps, store, w, _ := newDeps(t)
	deps.Presigner = nil

	hash := hashFor("entry-shipped-no-presign")
	store.hashesBySeq[1] = hash
	w.metas[hash] = wal.Meta{State: wal.StateShipped, Sequence: 1}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(1))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500 (loud misconfig)", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4) wal.ErrNotFound → fall through to bytestore (post-GC path)
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_PostGC_RedirectViaPresigner(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("entry-post-gc")
	store.hashesBySeq[500] = hash
	w.notFound[hash] = true // WAL has GC'd this entry

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(500))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if rec.Header().Get("X-Source") != "bytestore" {
		t.Errorf("X-Source mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5) Read-only operator (WAL=nil) → always redirects
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_NilWAL_AlwaysRedirects(t *testing.T) {
	deps, store, _, _ := newDeps(t)
	deps.WAL = nil // read-only operator

	hash := hashFor("entry-readonly")
	store.hashesBySeq[42] = hash

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if rec.Header().Get("X-Source") != "bytestore" {
		t.Errorf("X-Source: got %q", rec.Header().Get("X-Source"))
	}
}

// ─────────────────────────────────────────────────────────────────────
// 6) Postgres "no row at seq" → 404
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_NoSeqInIndex_404(t *testing.T) {
	deps, _, _, _ := newDeps(t)

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(99999))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 7) Invalid sequence number in path → 400
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_InvalidSeq_400(t *testing.T) {
	deps, _, _, _ := newDeps(t)

	r := httptest.NewRequest(http.MethodGet, "/v1/entries/not-a-number/raw", nil)
	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8) Postgres transport error → 500
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_PostgresError_500(t *testing.T) {
	deps, store, _, _ := newDeps(t)
	store.err = errors.New("pg: connection refused")

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(1))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 9) WAL transport error (non-NotFound) → 500
// ─────────────────────────────────────────────────────────────────────

func TestRawEntry_WALMetaTransportError_500(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("walfail")
	store.hashesBySeq[1] = hash
	w.hardErr = errors.New("badger: I/O error")

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(1))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 10) Concurrent-GC race between probe and read → graceful fallback
// ─────────────────────────────────────────────────────────────────────

// MetaState returns StateSequenced (so we go down the inline path),
// but Read returns wal.ErrNotFound (the entry was GC'd between
// probe and read). Handler must fall through to Presigner instead
// of 500ing.
func TestRawEntry_ConcurrentGC_FallsThroughToPresigner(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("concurrent-gc")
	store.hashesBySeq[42] = hash
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}
	// Note: NO wires[hash] entry — Read returns wal.ErrNotFound.

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302 (fallback after concurrent GC)", rec.Code)
	}
}

// Same scenario but no presigner configured → 500 (no fallback path).
func TestRawEntry_ConcurrentGC_NoPresigner_Returns500(t *testing.T) {
	deps, store, w, _ := newDeps(t)
	deps.Presigner = nil

	hash := hashFor("concurrent-gc-no-presign")
	store.hashesBySeq[42] = hash
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// X-Log-Time + X-Sequence header pin (Tier-2 alignment)
// ─────────────────────────────────────────────────────────────────────
//
// SDK's log.HTTPEntryFetcher reads X-Sequence and X-Log-Time from
// /raw responses (both 200-inline and post-302). Tests pin both
// values so a future refactor that drops X-Log-Time fails here
// rather than silently making the SDK fetcher round-trip to the
// JSON metadata endpoint for LogTime.

func TestRawEntry_Inline_StampsXSequenceAndXLogTime(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("inline-headers")
	wire := []byte("inline bytes")
	logTime := time.Date(2026, 4, 29, 21, 30, 0, 0, time.UTC)
	store.hashesBySeq[42] = hash
	store.logTimeBySeq[42] = logTime
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 42}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(42))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Sequence"); got != "42" {
		t.Errorf("X-Sequence: got %q, want %q", got, "42")
	}
	wantLT := logTime.Format(time.RFC3339Nano)
	if got := rec.Header().Get("X-Log-Time"); got != wantLT {
		t.Errorf("X-Log-Time: got %q, want %q", got, wantLT)
	}
}

func TestRawEntry_Redirect_StampsXSequenceAndXLogTime(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("redirect-headers")
	logTime := time.Date(2026, 4, 29, 22, 0, 0, 0, time.UTC)
	store.hashesBySeq[7] = hash
	store.logTimeBySeq[7] = logTime
	w.metas[hash] = wal.Meta{State: wal.StateShipped, Sequence: 7}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(7))

	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("X-Sequence"); got != "7" {
		t.Errorf("X-Sequence: got %q, want %q", got, "7")
	}
	wantLT := logTime.Format(time.RFC3339Nano)
	if got := rec.Header().Get("X-Log-Time"); got != wantLT {
		t.Errorf("X-Log-Time: got %q, want %q", got, wantLT)
	}
}

// X-Log-Time is omitted (not stamped as zero-valued string) when
// the operator does not have a log_time on file. The SDK fetcher
// tolerates absence with a zero LogTime; the worst possible
// regression would be stamping "0001-01-01T00:00:00Z" which the
// fetcher would parse as a valid (but bogus) timestamp.
func TestRawEntry_OmitsXLogTime_WhenNotPersisted(t *testing.T) {
	deps, store, w, _ := newDeps(t)

	hash := hashFor("no-log-time")
	wire := []byte("legacy")
	store.hashesBySeq[1] = hash
	// Deliberately leave logTimeBySeq[1] unset → zero time.
	w.wires[hash] = wire
	w.metas[hash] = wal.Meta{State: wal.StateSequenced, Sequence: 1}

	rec := httptest.NewRecorder()
	NewRawEntryHandler(deps)(rec, makeRequest(1))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Sequence"); got != "1" {
		t.Errorf("X-Sequence: got %q, want %q", got, "1")
	}
	if got := rec.Header().Get("X-Log-Time"); got != "" {
		t.Errorf("X-Log-Time should be absent for zero log_time, got %q", got)
	}
}
