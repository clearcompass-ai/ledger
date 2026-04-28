/*
FILE PATH: bytestore/conformance_test.go

Conformance suite — single source of truth for the bytestore.Store and
bytestore.Backend contracts. Every adapter (Memory, GCS, S3) is run
through the same scenarios so divergence between implementations is
caught at CI time.

Adapter-specific internals (LRU caches, SDK auth flows, key
construction) are covered in gcs_test.go / s3_test.go / memory_test.go;
this file is strictly the contract.

WHAT WE ASSERT (Store):
  - WriteEntry → ReadEntry round-trip preserves bytes verbatim.
  - ReadEntry on a missing (seq, hash) returns an error wrapping
    ErrNotFound (errors.Is). Callers depend on this for the read
    path's 404 mapping.
  - WriteEntry rejects empty wire bytes (caller bug: an entry with
    no canonical form should never reach the byte store).
  - ReadEntryBatch preserves input order and is fatal on any miss
    (consumers expect aligned slices).
  - Concurrent writers are safe (interface is goroutine-safe).

WHAT WE ASSERT (Backend, adds Presigner):
  - PresignGet returns a URL whose HTTP GET fetches the same bytes
    the producer wrote (real-cloud path: validates SigV4 / V4 signing
    end-to-end including the network round-trip).
  - The presigned URL contains the entry's hash hex in its path —
    this is the static-verifiability invariant the 302 redirect
    relies on. Without this, a consumer can't tell whether a
    redirect points at the bytes the operator promised.

BACKEND MATRIX (each entry point gates on its env vars; otherwise
skips):

  TestConformance_Memory          (always runs — Store only)
  TestConformance_GCS_Container   (ORTHOLOG_TEST_GCS_ENDPOINT)  Store
  TestConformance_GCS_Real        (ORTHOLOG_TEST_GCS_BUCKET, no
                                   endpoint) Backend
  TestConformance_S3_Container    (ORTHOLOG_TEST_S3_ENDPOINT)   Backend
                                  (MinIO/RustFS issue valid SigV4
                                  URLs that local SigV4 verifies)
  TestConformance_S3_Real         (ORTHOLOG_TEST_S3_REAL=1 +
                                   ORTHOLOG_TEST_S3_BUCKET)     Backend

  GCS container (fake-gcs-server) does NOT validate V4 signatures,
  so it can only run the Store half of the suite.
*/
package bytestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// runStoreConformance exercises the Store contract: WriteEntry/
// ReadEntry/ReadEntryBatch with the boundary cases that the operator
// depends on. Each subtest uses an isolated (seq, hash) so they can
// run in any order against a shared bucket.
func runStoreConformance(ctx context.Context, t *testing.T, store Store) {
	t.Helper()

	t.Run("WriteRoundTrip_Verbatim", func(t *testing.T) {
		wire := []byte("conformance: round-trip payload — every byte must come back")
		hash := sha256.Sum256(wire)
		const seq uint64 = 1_000_001

		if err := store.WriteEntry(ctx, seq, hash, wire); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
		got, err := store.ReadEntry(ctx, seq, hash)
		if err != nil {
			t.Fatalf("ReadEntry: %v", err)
		}
		if !bytes.Equal(got, wire) {
			t.Fatalf("round-trip mismatch:\n  got=%x\n want=%x", got, wire)
		}
	})

	t.Run("ReadMissing_ErrNotFound", func(t *testing.T) {
		var hash [32]byte
		hash[0] = 0xff // Far away from anything else the suite writes.
		_, err := store.ReadEntry(ctx, 9_876_543_210, hash)
		if err == nil {
			t.Fatal("ReadEntry on missing key returned nil error; expected ErrNotFound")
		}
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("ReadEntry missing did not wrap ErrNotFound: %v", err)
		}
	})

	t.Run("WriteEmpty_Rejected", func(t *testing.T) {
		var hash [32]byte
		if err := store.WriteEntry(ctx, 1_000_002, hash, nil); err == nil {
			t.Fatal("WriteEntry(nil) accepted empty wire bytes; expected error")
		}
		if err := store.WriteEntry(ctx, 1_000_003, hash, []byte{}); err == nil {
			t.Fatal("WriteEntry([]) accepted empty wire bytes; expected error")
		}
	})

	t.Run("ReadBatch_PreservesOrder", func(t *testing.T) {
		// Write three distinct entries, request them out of order,
		// assert the result slice matches the request slice.
		wires := [][]byte{
			[]byte("batch entry alpha"),
			[]byte("batch entry beta — different length"),
			[]byte("g"), // single byte
		}
		seqs := []uint64{1_000_010, 1_000_011, 1_000_012}
		hashes := make([][32]byte, len(wires))
		for i, w := range wires {
			hashes[i] = sha256.Sum256(w)
			if err := store.WriteEntry(ctx, seqs[i], hashes[i], w); err != nil {
				t.Fatalf("WriteEntry seq=%d: %v", seqs[i], err)
			}
		}

		// Out-of-order request: 2, 0, 1.
		refs := []EntryRef{
			{Seq: seqs[2], Hash: hashes[2]},
			{Seq: seqs[0], Hash: hashes[0]},
			{Seq: seqs[1], Hash: hashes[1]},
		}
		got, err := store.ReadEntryBatch(ctx, refs)
		if err != nil {
			t.Fatalf("ReadEntryBatch: %v", err)
		}
		if len(got) != len(refs) {
			t.Fatalf("ReadEntryBatch returned %d entries, expected %d", len(got), len(refs))
		}
		want := [][]byte{wires[2], wires[0], wires[1]}
		for i := range refs {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("position %d:\n  got=%x\n want=%x", i, got[i], want[i])
			}
		}
	})

	t.Run("ReadBatch_MissingIsFatal", func(t *testing.T) {
		// Write one real entry; mix it with a definitely-missing ref;
		// assert the whole batch errors (not a partial result).
		wire := []byte("batch fatal check")
		hash := sha256.Sum256(wire)
		const realSeq uint64 = 1_000_020
		if err := store.WriteEntry(ctx, realSeq, hash, wire); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}

		var missingHash [32]byte
		missingHash[0] = 0xee
		refs := []EntryRef{
			{Seq: realSeq, Hash: hash},
			{Seq: 1_111_111_111, Hash: missingHash},
		}
		_, err := store.ReadEntryBatch(ctx, refs)
		if err == nil {
			t.Fatal("ReadEntryBatch with one missing ref returned nil; expected error")
		}
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("ReadEntryBatch missing did not wrap ErrNotFound: %v", err)
		}
	})

	t.Run("Concurrent_Writers_Safe", func(t *testing.T) {
		// Per-goroutine seq + hash so writes don't collide. We're
		// asserting the interface itself is goroutine-safe; the
		// underlying SDK clients all promise this, and the operator
		// shares one *Backend across admission goroutines.
		const N = 12
		var wg sync.WaitGroup
		errCh := make(chan error, N)
		for i := 0; i < N; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				wire := []byte(fmt.Sprintf("concurrent writer %d", i))
				hash := sha256.Sum256(wire)
				seq := uint64(2_000_000 + i)
				if err := store.WriteEntry(ctx, seq, hash, wire); err != nil {
					errCh <- fmt.Errorf("writer %d: %w", i, err)
					return
				}
				got, err := store.ReadEntry(ctx, seq, hash)
				if err != nil {
					errCh <- fmt.Errorf("writer %d read-back: %w", i, err)
					return
				}
				if !bytes.Equal(got, wire) {
					errCh <- fmt.Errorf("writer %d: read-back mismatch", i)
				}
			}(i)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Error(err)
		}
	})
}

// runBackendConformance adds the Presigner contract: the produced URL
// must (1) fetch the same bytes via plain HTTP GET, and (2) embed the
// hash hex in its path so consumers can statically verify that a 302
// destination matches the promised bytes before fetching.
func runBackendConformance(ctx context.Context, t *testing.T, backend Backend) {
	t.Helper()

	runStoreConformance(ctx, t, backend)

	t.Run("Presign_URLFetchesBytes", func(t *testing.T) {
		wire := []byte("presign conformance: fetch via 302 path with no SDK on the consumer side")
		hash := sha256.Sum256(wire)
		const seq uint64 = 3_000_001

		if err := backend.WriteEntry(ctx, seq, hash, wire); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
		url, err := backend.PresignGet(ctx, seq, hash, 5*time.Minute)
		if err != nil {
			t.Fatalf("PresignGet: %v", err)
		}
		if url == "" {
			t.Fatal("PresignGet returned empty URL")
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("HTTP status %d: %s\nbody: %s", resp.StatusCode, resp.Status, body)
		}
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !bytes.Equal(got, wire) {
			t.Fatalf("presigned GET returned wrong bytes:\n  got=%x\n want=%x", got, wire)
		}
	})

	t.Run("Presign_URLContainsHashHex", func(t *testing.T) {
		// Static-verifiability invariant: a consumer following a 302
		// redirect MUST be able to verify (without fetching) that the
		// URL points at the bytes the operator promised. We achieve
		// this by including the hash hex in the object path
		// (layoutKey: <prefix>/<seq:016x>/<hash_hex>). If the URL
		// doesn't contain the hex, the redirect path is broken.
		wire := []byte("hash-suffix invariant — checked at the URL surface")
		hash := sha256.Sum256(wire)
		hashHex := hex.EncodeToString(hash[:])
		const seq uint64 = 3_000_002

		if err := backend.WriteEntry(ctx, seq, hash, wire); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
		url, err := backend.PresignGet(ctx, seq, hash, 5*time.Minute)
		if err != nil {
			t.Fatalf("PresignGet: %v", err)
		}
		if !strings.Contains(url, hashHex) {
			t.Fatalf("URL missing hash hex (static verifiability lost):\n  url=%s\n  hash=%s", url, hashHex)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────
// Backend matrix entry points
// ─────────────────────────────────────────────────────────────────────

func TestConformance_Memory(t *testing.T) {
	// Memory satisfies Store but not Backend (no Presigner). This
	// matches its role: tests/dev only, never production.
	runStoreConformance(context.Background(), t, NewMemory())
}

func TestConformance_GCS_Container(t *testing.T) {
	// fake-gcs-server: we get full Store coverage but PresignGet
	// V4 signing isn't validated by the fake. Skip the Backend
	// suite — it lives in TestConformance_GCS_Real.
	if os.Getenv("ORTHOLOG_TEST_GCS_ENDPOINT") == "" {
		t.Skip("ORTHOLOG_TEST_GCS_ENDPOINT unset; skipping fake-gcs conformance")
	}
	store := requireGCS(t)
	runStoreConformance(context.Background(), t, store)
}

func TestConformance_GCS_Real(t *testing.T) {
	// Real-GCS: bucket configured, no endpoint override. Uses ADC
	// (GOOGLE_APPLICATION_CREDENTIALS) for signed-URL keys.
	if os.Getenv("ORTHOLOG_TEST_GCS_ENDPOINT") != "" {
		t.Skip("ORTHOLOG_TEST_GCS_ENDPOINT set — that's container mode; this test is real-GCS only")
	}
	if os.Getenv("ORTHOLOG_TEST_GCS_BUCKET") == "" {
		t.Skip("ORTHOLOG_TEST_GCS_BUCKET unset; skipping real-GCS conformance")
	}
	store := requireGCS(t)
	runBackendConformance(context.Background(), t, store)
}

func TestConformance_S3_Container(t *testing.T) {
	// MinIO/RustFS: full Backend coverage. SigV4 is validated by
	// the container, and the local SigV4 signer in the SDK
	// produces verifiable URLs.
	if os.Getenv("ORTHOLOG_TEST_S3_ENDPOINT") == "" {
		t.Skip("ORTHOLOG_TEST_S3_ENDPOINT unset; skipping S3 container conformance")
	}
	if os.Getenv("ORTHOLOG_TEST_S3_REAL") == "1" {
		t.Skip("ORTHOLOG_TEST_S3_REAL=1 — that's real-AWS mode; this test is for the local container")
	}
	store := requireS3(t)
	runBackendConformance(context.Background(), t, store)
}

func TestConformance_S3_Real(t *testing.T) {
	// Real AWS S3: default credential chain, virtual-host URLs.
	if os.Getenv("ORTHOLOG_TEST_S3_REAL") != "1" {
		t.Skip("ORTHOLOG_TEST_S3_REAL!=1; skipping real-AWS conformance")
	}
	if os.Getenv("ORTHOLOG_TEST_S3_BUCKET") == "" {
		t.Skip("ORTHOLOG_TEST_S3_BUCKET unset; skipping real-AWS conformance")
	}
	store := requireS3(t)
	runBackendConformance(context.Background(), t, store)
}
