/*
FILE PATH: bytestore/gcs_fake_diagnostic_test.go

Targeted diagnostic tests for the fake-gcs-server failure pattern
that surfaced in TestGCS_Cache_EvictsOldestAtCapacity
and TestGCS_ConcurrentWriters: writes return success,
LIST returns the object's path, but GET on that exact path 404s
even after a 1.5-second retry budget.

Each test runs ONLY against fake-gcs-server (skipped if
ATTESTA_TEST_GCS_ENDPOINT is unset). Real GCS doesn't exhibit
this pattern, so running there is wasted I/O.

Each experiment validates one hypothesis with a controlled change
and explicit logging:

	E1 PathExactMatch       — Does LIST return the same string GET
	                           constructs? (validates path-shape bug
	                           vs. handler bug.)
	E2 FlatPath             — Same write/read flow, but objects live
	                           at <prefix>/<seq:016x> instead of
	                           <prefix>/<seq:016x>/data. (Validates
	                           nested-directory-creation bug.)
	E3 AttrsRightAfterClose — Write ONE object, then call .Attrs()
	                           AND .NewReader() back-to-back. (If
	                           Attrs sees it but NewReader doesn't,
	                           fake-gcs's read paths disagree among
	                           themselves.)
	E4 BurstWriteSettle     — Same eviction-style burst, but sleep
	                           5s before reading seq=0. (If 5s fixes
	                           it but 1.5s doesn't, the bug IS just
	                           a long settle window.)

Read the t.Logf output to interpret. Each test logs every read
attempt with the exact path string for paste-into-an-issue clarity.
*/
package bytestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// requireFakeGCS skips unless ATTESTA_TEST_GCS_ENDPOINT is set.
// Diagnostic tests are fake-gcs-specific by design.
func requireFakeGCS(t *testing.T) (string, string) {
	t.Helper()
	endpoint := os.Getenv("ATTESTA_TEST_GCS_ENDPOINT")
	if endpoint == "" {
		t.Skip("ATTESTA_TEST_GCS_ENDPOINT unset; diagnostic is fake-gcs-only")
	}
	bucket := os.Getenv("ATTESTA_TEST_GCS_BUCKET")
	if bucket == "" {
		bucket = "attesta-test-bytes"
	}
	return endpoint, bucket
}

// rawClient builds a bare GCS client against fake-gcs. Used by
// experiments that bypass bytestore.GCS so the diagnostic isn't
// confounded by our own caching/path logic.
func rawClient(t *testing.T, endpoint string) *storage.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := storage.NewClient(ctx,
		option.WithEndpoint(endpoint),
		option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("storage.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// ─────────────────────────────────────────────────────────────────
// E1 — Does LIST return the same string GET constructs?
// ─────────────────────────────────────────────────────────────────
//
// HYPOTHESIS:
//   fake-gcs's GET handler canonicalizes the URL path differently
//   from its LIST handler (e.g., slash collapsing, URL decoding,
//   case folding), so the path bytestore.GCS.ReadEntry constructs
//   matches what was written but doesn't match what GET expects.
//
// PREDICTION:
//   If hypothesis holds: store.keyOf(seq, sha256.Sum256([]byte{byte(seq)})) != attrs.Name from
//   listing, OR the byte string matches but GET on attrs.Name also
//   404s.
//   If refuted: paths match exactly AND GET on either string works.

func TestFakeGCS_Diagnostic_E1_PathExactMatchAfterEviction(t *testing.T) {
	endpoint, _ := requireFakeGCS(t)
	_ = endpoint
	store := requireGCS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Reproduce the eviction-style burst: 17 writes, cache cap=16.
	for i := uint64(0); i < 17; i++ {
		if err := store.WriteEntry(ctx, i, sha256.Sum256([]byte{byte(i)}), []byte{byte(i)}); err != nil {
			t.Fatalf("WriteEntry seq=%d: %v", i, err)
		}
	}

	// Settle briefly — generous, just to be fair to fake-gcs.
	time.Sleep(500 * time.Millisecond)

	// Step 1: enumerate via LIST.
	t.Logf("─── LIST under prefix %q ───", store.objectPrefix)
	listed := make(map[string]bool)
	it := store.bucket.Objects(ctx, &storage.Query{Prefix: store.objectPrefix})
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			t.Fatalf("LIST iter: %v", err)
		}
		t.Logf("LIST: %q  size=%d  generation=%d", attrs.Name, attrs.Size, attrs.Generation)
		listed[attrs.Name] = true
	}
	t.Logf("LIST returned %d entries", len(listed))

	// Step 2: what does our code expect to GET for seq=0?
	expectedSeq0 := store.keyOf(0, sha256.Sum256([]byte{0}))
	t.Logf("─── store.keyOf(0, sha256.Sum256([]byte{0})) = %q ───", expectedSeq0)

	// Step 3: byte-equality check.
	if listed[expectedSeq0] {
		t.Logf("✓ LIST contains the exact path our GET will use")
	} else {
		t.Errorf("✗ LIST does NOT contain %q", expectedSeq0)
		t.Logf("Closest LIST entries:")
		for name := range listed {
			t.Logf("  %q", name)
		}
	}

	// Step 4: GET on the constructed path (the failing path in the
	// production test).
	r1, err1 := store.bucket.Object(expectedSeq0).NewReader(ctx)
	if err1 != nil {
		t.Logf("GET store.keyOf(0, sha256.Sum256([]byte{0}))=%q: ERR %v", expectedSeq0, err1)
	} else {
		_, _ = io.ReadAll(r1)
		_ = r1.Close()
		t.Logf("GET store.keyOf(0, sha256.Sum256([]byte{0}))=%q: OK", expectedSeq0)
	}

	// Step 5: GET on every name returned by LIST. If any of these
	// 404s, the LIST→GET contract is broken in fake-gcs.
	t.Logf("─── GET each LIST entry ───")
	getMisses := 0
	for name := range listed {
		r, err := store.bucket.Object(name).NewReader(ctx)
		if err != nil {
			t.Logf("GET %q: ERR %v", name, err)
			getMisses++
			continue
		}
		_, _ = io.ReadAll(r)
		_ = r.Close()
		t.Logf("GET %q: OK", name)
	}
	if getMisses > 0 {
		t.Errorf("✗ %d/%d objects returned by LIST 404d on GET", getMisses, len(listed))
	}
}

// ─────────────────────────────────────────────────────────────────
// E2 — Flat path layout (no per-seq subdirectory)
// ─────────────────────────────────────────────────────────────────
//
// HYPOTHESIS:
//   fake-gcs has a race or bug specifically around creating
//   nested-directory objects (multiple parents under a shared
//   prefix). Our path scheme is "<prefix>/<seq:016x>/data" — three
//   levels under prefix. Flat scheme would be "<prefix>/<seq:016x>"
//   — one level under prefix.
//
// PREDICTION:
//   If hypothesis holds: 17 sequential writes to flat paths all
//   GET-readable.
//   If refuted: same write-readback failure on flat paths too.
//   Result either way is a hard data point — fix path shape OR
//   stop blaming directories.

func TestFakeGCS_Diagnostic_E2_FlatPath_NoSubdirPerSeq(t *testing.T) {
	endpoint, bucketName := requireFakeGCS(t)
	client := rawClient(t, endpoint)
	bucket := client.Bucket(bucketName)

	prefix := fmt.Sprintf("diag-e2-flat/%d", time.Now().UnixNano())
	flatName := func(seq uint64) string {
		// One slash, no /data suffix.
		return fmt.Sprintf("%s/%016x", prefix, seq)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Cleanup at end.
	t.Cleanup(func() {
		cleanCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		it := bucket.Objects(cleanCtx, &storage.Query{Prefix: prefix})
		for {
			a, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return
			}
			_ = bucket.Object(a.Name).Delete(cleanCtx)
		}
	})

	// 17 sequential writes to flat paths.
	for i := uint64(0); i < 17; i++ {
		w := bucket.Object(flatName(i)).NewWriter(ctx)
		if _, err := w.Write([]byte{byte(i)}); err != nil {
			_ = w.Close()
			t.Fatalf("write seq=%d: %v", i, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close seq=%d: %v", i, err)
		}
	}

	// Brief settle.
	time.Sleep(500 * time.Millisecond)

	// Read each.
	misses := 0
	for i := uint64(0); i < 17; i++ {
		name := flatName(i)
		r, err := bucket.Object(name).NewReader(ctx)
		if err != nil {
			if errors.Is(err, storage.ErrObjectNotExist) {
				t.Logf("✗ seq=%d %q: NOT FOUND", i, name)
				misses++
				continue
			}
			t.Logf("✗ seq=%d %q: ERR %v", i, name, err)
			misses++
			continue
		}
		_, _ = io.ReadAll(r)
		_ = r.Close()
	}

	if misses > 0 {
		t.Errorf("FLAT layout: %d/17 reads missed → bug is NOT specific to nested subdirs", misses)
	} else {
		t.Logf("✓ FLAT layout: all 17 reads succeeded → bug IS specific to nested-directory paths")
		t.Logf("  Action: change bytestore.GCS.objectName to flat layout in production.")
	}
}

// ─────────────────────────────────────────────────────────────────
// E3 — Attrs vs NewReader after Close
// ─────────────────────────────────────────────────────────────────
//
// HYPOTHESIS:
//   fake-gcs's two read endpoints — Attrs (GET .../o/<name>) and
//   media download (GET .../o/<name>?alt=media) — disagree about
//   object visibility right after Close(). One sees it; the other
//   doesn't.
//
// PREDICTION:
//   If Attrs succeeds but NewReader fails on the same object, we
//   know fake-gcs has a per-endpoint visibility lag.
//   If both succeed, the bug is elsewhere (likely concurrent-write
//   indexing under burst load, validated by E2 outcome).

func TestFakeGCS_Diagnostic_E3_AttrsRightAfterClose(t *testing.T) {
	endpoint, bucketName := requireFakeGCS(t)
	client := rawClient(t, endpoint)
	bucket := client.Bucket(bucketName)

	prefix := fmt.Sprintf("diag-e3/%d", time.Now().UnixNano())
	name := fmt.Sprintf("%s/single/data", prefix)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Cleanup(func() {
		cleanCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = bucket.Object(name).Delete(cleanCtx)
	})

	// Write.
	w := bucket.Object(name).NewWriter(ctx)
	want := []byte("attrs-vs-reader")
	if _, err := w.Write(want); err != nil {
		_ = w.Close()
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Logf("WRITE %q: ok (%d bytes)", name, len(want))

	// Right after Close: try Attrs.
	attrs, attrsErr := bucket.Object(name).Attrs(ctx)
	if attrsErr != nil {
		t.Logf("✗ Attrs(%q): %v", name, attrsErr)
	} else {
		t.Logf("✓ Attrs(%q): size=%d generation=%d updated=%v",
			name, attrs.Size, attrs.Generation, attrs.Updated)
	}

	// Right after Attrs: try NewReader.
	r, rErr := bucket.Object(name).NewReader(ctx)
	if rErr != nil {
		t.Logf("✗ NewReader(%q): %v", name, rErr)
	} else {
		got, _ := io.ReadAll(r)
		_ = r.Close()
		if !bytes.Equal(got, want) {
			t.Errorf("✗ NewReader: got %q, want %q", got, want)
		} else {
			t.Logf("✓ NewReader(%q): %q (matches)", name, got)
		}
	}

	// Diagnostic: if Attrs succeeded but NewReader failed, that's
	// the bug. Otherwise this test passes silently.
	if attrsErr == nil && rErr != nil {
		t.Errorf("Attrs sees the object, NewReader does not — fake-gcs read-endpoint inconsistency")
	}
}

// ─────────────────────────────────────────────────────────────────
// E4 — Burst write + 5s settle + read
// ─────────────────────────────────────────────────────────────────
//
// HYPOTHESIS:
//   fake-gcs's eventual consistency window under bursty writes is
//   longer than the 1.5s our retry helper budgets, but FINITE. A
//   long settle (5s) would resolve the failure.
//
// PREDICTION:
//   If hypothesis holds: 17 writes + 5s sleep → read seq=0 succeeds.
//   If refuted: read seq=0 still 404s after 5s. Then the bug is
//   not "settle window" — it's a structural issue (E1 / E2 territory).

func TestFakeGCS_Diagnostic_E4_BurstWriteSettleTime(t *testing.T) {
	requireFakeGCS(t)
	store := requireGCS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i := uint64(0); i < 17; i++ {
		if err := store.WriteEntry(ctx, i, sha256.Sum256([]byte{byte(i)}), []byte{byte(i)}); err != nil {
			t.Fatalf("WriteEntry seq=%d: %v", i, err)
		}
	}

	// Force seq=0 out of the in-process cache so the read goes to GCS.
	store.mu.Lock()
	delete(store.cache, store.keyOf(0, sha256.Sum256([]byte{0})))
	delete(store.access, store.keyOf(0, sha256.Sum256([]byte{0})))
	store.mu.Unlock()

	// Settle period — 5 seconds, ~3.3x the previous retry budget.
	t.Logf("sleeping 5s to give fake-gcs all the time it could possibly need...")
	time.Sleep(5 * time.Second)

	// Single GET, no retry.
	expected := store.keyOf(0, sha256.Sum256([]byte{0}))
	r, err := store.bucket.Object(expected).NewReader(ctx)
	if err != nil {
		t.Errorf("✗ seq=0 still NOT visible after 5s settle: %v", err)
		t.Logf("  This refutes the 'settle window' hypothesis. The bug is structural.")
		t.Logf("  Run E1 and E2 to narrow further.")
		return
	}
	got, _ := io.ReadAll(r)
	_ = r.Close()
	if len(got) == 0 {
		t.Errorf("seq=0 read returned empty body")
		return
	}
	t.Logf("✓ seq=0 visible after 5s settle (%d bytes)", len(got))
	t.Logf("  Hypothesis: fake-gcs has a >1.5s but <5s read-after-write window under burst.")
	t.Logf("  Action: bump readEntryWithRetry budget OR move to flat layout (E2).")
}

// ─────────────────────────────────────────────────────────────────
// E6 — XML reads vs JSON reads against fake-gcs (the smoking gun)
// ─────────────────────────────────────────────────────────────────
//
// HYPOTHESIS:
//   The Cloud Storage Go SDK at v1.62.1 (and earlier) defaults
//   ObjectHandle.NewReader to the XML API
//   (GET <scheme>://<host>/<bucket>/<object>), while WriteEntry
//   uploads and bucket.Objects() LIST both go through the JSON
//   API (`/storage/v1/...`). option.WithEndpoint redirects the
//   JSON API correctly to fake-gcs but does NOT cover the XML
//   surface. Real GCS supports both transports identically so the
//   bug is invisible there.
//
//   See cloud.google.com/go/storage/http_client.go:872-882:
//     if c.config.useJSONforReads {
//         return c.newRangeReaderJSON(...)
//     }
//     return c.newRangeReaderXML(...)
//
//   See option.go:124-138 docstring:
//     "Currently, the default API used for reads is XML, but JSON
//     will become the default in a future release."
//
// PREDICTION:
//   - Without storage.WithJSONReads(): reads under burst load 404
//     on fake-gcs (reproduces the production failure).
//   - With storage.WithJSONReads(): reads succeed on fake-gcs.
//
// CONFIRMS BUG ROOT CAUSE if the WithJSONReads variant passes
// while the default variant fails on the same write/read pattern.

func TestFakeGCS_Diagnostic_E6_XMLDefault_vs_JSONReads(t *testing.T) {
	endpoint, bucketName := requireFakeGCS(t)

	mkClient := func(useJSONReads bool) *storage.Client {
		opts := []option.ClientOption{
			option.WithEndpoint(endpoint),
			option.WithoutAuthentication(),
		}
		if useJSONReads {
			opts = append(opts, storage.WithJSONReads())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := storage.NewClient(ctx, opts...)
		if err != nil {
			t.Fatalf("storage.NewClient(json=%v): %v", useJSONReads, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	runBurst := func(label string, client *storage.Client) (int, int) {
		t.Helper()
		bucket := client.Bucket(bucketName)
		prefix := fmt.Sprintf("diag-e6-%s/%d", label, time.Now().UnixNano())
		objName := func(i uint64) string {
			return fmt.Sprintf("%s/%016x/data", prefix, i)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// 17 sequential writes (matches the eviction test pattern).
		for i := uint64(0); i < 17; i++ {
			w := bucket.Object(objName(i)).NewWriter(ctx)
			if _, err := w.Write([]byte{byte(i)}); err != nil {
				_ = w.Close()
				t.Fatalf("[%s] write seq=%d: %v", label, i, err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("[%s] close seq=%d: %v", label, i, err)
			}
		}

		// Cleanup at end.
		t.Cleanup(func() {
			cleanCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
			defer c()
			it := bucket.Objects(cleanCtx, &storage.Query{Prefix: prefix})
			for {
				a, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					return
				}
				_ = bucket.Object(a.Name).Delete(cleanCtx)
			}
		})

		// Brief settle.
		time.Sleep(300 * time.Millisecond)

		// Read each back without retry; capture count of OK vs 404.
		ok, missing := 0, 0
		for i := uint64(0); i < 17; i++ {
			r, err := bucket.Object(objName(i)).NewReader(ctx)
			if err != nil {
				if errors.Is(err, storage.ErrObjectNotExist) {
					missing++
					continue
				}
				t.Logf("[%s] seq=%d unexpected err: %v", label, i, err)
				missing++
				continue
			}
			_, _ = io.ReadAll(r)
			_ = r.Close()
			ok++
		}
		return ok, missing
	}

	// Variant 1: SDK default (XML reads).
	xmlOK, xmlMissing := runBurst("xml", mkClient(false))
	t.Logf("XML reads (SDK default): %d/17 ok, %d/17 missing", xmlOK, xmlMissing)

	// Variant 2: WithJSONReads (the proposed fix).
	jsonOK, jsonMissing := runBurst("json", mkClient(true))
	t.Logf("JSON reads (WithJSONReads): %d/17 ok, %d/17 missing", jsonOK, jsonMissing)

	// Conclusion.
	switch {
	case xmlMissing > 0 && jsonMissing == 0:
		t.Logf("✓ HYPOTHESIS CONFIRMED: XML-API reads fail on fake-gcs; JSON-API reads work.")
		t.Logf("  Production fix: pass storage.WithJSONReads() in NewGCS.")
	case xmlMissing == 0 && jsonMissing == 0:
		t.Logf("Neither variant exhibited the bug — couldn't reproduce in this run.")
	case xmlMissing == 0 && jsonMissing > 0:
		t.Errorf("Unexpected: JSON reads failing but XML reads succeeded — refutes hypothesis.")
	case xmlMissing > 0 && jsonMissing > 0:
		t.Errorf("Both variants failed (%d xml, %d json missing) — bug isn't transport choice.",
			xmlMissing, jsonMissing)
	}
}

// ─────────────────────────────────────────────────────────────────
// E5 — Compare write paths byte-by-byte across the loop
// ─────────────────────────────────────────────────────────────────
//
// SECONDARY HYPOTHESIS (specific to our code path):
//   bytestore.GCS.objectName produces a STABLE string for a given
//   seq, but maybe somehow the writer and reader observe different
//   strings due to concurrency. This eliminates that possibility.

func TestFakeGCS_Diagnostic_E5_ObjectNameStability(t *testing.T) {
	store := &GCS{objectPrefix: "stability-test"}
	for i := uint64(0); i < 100; i++ {
		first := store.keyOf(i, sha256.Sum256([]byte{byte(i)}))
		second := store.keyOf(i, sha256.Sum256([]byte{byte(i)}))
		if first != second {
			t.Errorf("seq=%d: %q != %q (objectName is non-deterministic!)", i, first, second)
		}
	}
	// Specifically check the seqs that failed in production.
	cases := []uint64{0, 100, 101, 200}
	for _, seq := range cases {
		t.Logf("objectName(%d) = %q", seq, store.keyOf(seq, sha256.Sum256([]byte{byte(seq)})))
	}
}
