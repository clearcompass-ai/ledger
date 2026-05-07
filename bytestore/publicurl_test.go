/*
FILE PATH:
    bytestore/publicurl_test.go

DESCRIPTION:
    Pins the Path B public-URL contract:

      1. URL composition matches the canonical CT-log shape
         (baseURL + "/" + layoutKey).
      2. Empty baseURL returns ErrPublicURLNotConfigured (the
         api 302 handler treats this as a misconfiguration and
         returns 500 — there is no private-bucket fallback).
      3. Default-URL helpers produce the documented prefixes for
         GCS, S3 path-style, and S3 virtual-host modes.
      4. Trailing slashes on the configured baseURL are
         normalized away (administrators frequently trip on this).
      5. The same (seq, hash) → same URL across calls
         (deterministic; what makes consumer caches valid).
      6. PublicURL output ALIGNS with layoutKey output — a
         bucket written by WriteEntry can be read via the
         PublicURL it produces.

    Each test pins one structural property. A regression that
    silently changes the URL shape (e.g., adds a query string,
    changes the path separator, drops the prefix) fails here.
*/
package bytestore

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// -------------------------------------------------------------------
// 1) URL composition
// -------------------------------------------------------------------

// TestPublicURLMapper_CanonicalShape pins the URL format:
//
//	baseURL/{prefix}/{seq:016x}/{hash_hex}
//
// Catches a refactor that swaps separators, drops zero-padding,
// or reorders fields.
func TestPublicURLMapper_CanonicalShape(t *testing.T) {
	m := newPublicURLMapper("https://cdn.example.com/log", "entries")

	hash := sha256.Sum256([]byte("payload"))
	got, err := m.PublicURL(0xabcd, hash)
	if err != nil {
		t.Fatalf("PublicURL: %v", err)
	}
	want := "https://cdn.example.com/log/entries/000000000000abcd/" +
		hexEncode(hash[:])
	if got != want {
		t.Errorf("PublicURL = %q\n want = %q", got, want)
	}
}

// TestPublicURLMapper_AlignsWithLayoutKey pins the most important
// invariant: PublicURL(seq, hash) MUST encode the same key
// layoutKey() produces. Without this, a public reader can't fetch
// what the writer stored.
func TestPublicURLMapper_AlignsWithLayoutKey(t *testing.T) {
	const baseURL = "https://example.com/bucket"
	const prefix = "entries"
	m := newPublicURLMapper(baseURL, prefix)

	for _, seq := range []uint64{0, 1, 0xff, 0xffff_ffff_ffff_ffff} {
		hash := sha256.Sum256([]byte{byte(seq)})
		got, err := m.PublicURL(seq, hash)
		if err != nil {
			t.Fatalf("PublicURL(seq=%d): %v", seq, err)
		}
		want := baseURL + "/" + layoutKey(prefix, seq, hash)
		if got != want {
			t.Errorf("seq=%d misaligned with layoutKey:\n got %q\n want %q", seq, got, want)
		}
	}
}

// -------------------------------------------------------------------
// 2) Empty / not-configured signal
// -------------------------------------------------------------------

// TestPublicURLMapper_EmptyBaseURLSignalsNotConfigured pins the
// not-configured signal the api 302 handler treats as a 500.
func TestPublicURLMapper_EmptyBaseURLSignalsNotConfigured(t *testing.T) {
	m := newPublicURLMapper("", "entries")
	hash := sha256.Sum256([]byte("x"))
	url, err := m.PublicURL(1, hash)
	if !errors.Is(err, ErrPublicURLNotConfigured) {
		t.Errorf("err = %v; want ErrPublicURLNotConfigured", err)
	}
	if url != "" {
		t.Errorf("url = %q; want empty on not-configured", url)
	}
}

// TestPublicURLMapper_NilSignalsNotConfigured pins the nil-receiver
// safety. Adapters that don't initialize publicURL should still get
// the same fallback signal.
func TestPublicURLMapper_NilSignalsNotConfigured(t *testing.T) {
	var m *publicURLMapper // nil
	hash := sha256.Sum256([]byte("x"))
	url, err := m.PublicURL(1, hash)
	if !errors.Is(err, ErrPublicURLNotConfigured) {
		t.Errorf("nil-receiver err = %v; want ErrPublicURLNotConfigured", err)
	}
	if url != "" {
		t.Errorf("url = %q; want empty on nil", url)
	}
}

// -------------------------------------------------------------------
// 3) Default-URL helpers
// -------------------------------------------------------------------

func TestDefaultGCSPublicBaseURL(t *testing.T) {
	got := DefaultGCSPublicBaseURL("my-bucket")
	want := "https://storage.googleapis.com/my-bucket"
	if got != want {
		t.Errorf("DefaultGCSPublicBaseURL = %q\n want = %q", got, want)
	}
}

func TestDefaultS3PathStylePublicBaseURL(t *testing.T) {
	cases := []struct {
		endpoint, bucket, want string
	}{
		{"http://localhost:8333", "attesta", "http://localhost:8333/attesta"},
		// Trailing slash on endpoint is normalized.
		{"https://seaweed.example.com/", "logs", "https://seaweed.example.com/logs"},
		// Empty bucket OR endpoint → empty (signal to caller).
		{"", "logs", ""},
		{"http://localhost", "", ""},
	}
	for _, tc := range cases {
		got := DefaultS3PathStylePublicBaseURL(tc.endpoint, tc.bucket)
		if got != tc.want {
			t.Errorf("DefaultS3PathStylePublicBaseURL(%q,%q) = %q; want %q",
				tc.endpoint, tc.bucket, got, tc.want)
		}
	}
}

func TestDefaultS3VirtualHostPublicBaseURL(t *testing.T) {
	got := DefaultS3VirtualHostPublicBaseURL("my-log", "us-east-1")
	want := "https://my-log.s3.us-east-1.amazonaws.com"
	if got != want {
		t.Errorf("DefaultS3VirtualHostPublicBaseURL = %q\n want = %q", got, want)
	}
	// Empty bucket OR region → empty signal.
	if got := DefaultS3VirtualHostPublicBaseURL("", "us-east-1"); got != "" {
		t.Errorf("empty bucket should signal empty: got %q", got)
	}
	if got := DefaultS3VirtualHostPublicBaseURL("my-log", ""); got != "" {
		t.Errorf("empty region should signal empty: got %q", got)
	}
}

// -------------------------------------------------------------------
// 4) baseURL normalization
// -------------------------------------------------------------------

// TestPublicURLMapper_TrailingSlashNormalized pins the trailing-
// slash defensive normalization. Administrators frequently set
// LEDGER_BYTE_STORE_PUBLIC_BASE_URL=https://cdn.example.com/ and
// the resulting URLs would have a double-slash without this fix.
func TestPublicURLMapper_TrailingSlashNormalized(t *testing.T) {
	hash := sha256.Sum256([]byte("p"))

	withSlash := newPublicURLMapper("https://cdn.example.com/", "entries")
	withoutSlash := newPublicURLMapper("https://cdn.example.com", "entries")

	gotWith, _ := withSlash.PublicURL(1, hash)
	gotWithout, _ := withoutSlash.PublicURL(1, hash)
	if gotWith != gotWithout {
		t.Errorf("trailing slash NOT normalized:\n with /  = %q\n without = %q",
			gotWith, gotWithout)
	}
	// Also ensure no `//` in the produced URL (other than the protocol).
	if count := strings.Count(strings.TrimPrefix(gotWith, "https://"), "//"); count > 0 {
		t.Errorf("URL contains double-slash beyond protocol: %q", gotWith)
	}
}

// -------------------------------------------------------------------
// 5) Determinism
// -------------------------------------------------------------------

// TestPublicURLMapper_Deterministic pins the deterministic property:
// same (seq, hash) → same URL across N calls. This is what makes
// consumer caches (CDN, witness, auditor) valid.
func TestPublicURLMapper_Deterministic(t *testing.T) {
	m := newPublicURLMapper("https://example.com/log", "entries")
	hash := sha256.Sum256([]byte("xyz"))
	first, _ := m.PublicURL(42, hash)
	for i := 0; i < 100; i++ {
		got, _ := m.PublicURL(42, hash)
		if got != first {
			t.Fatalf("call #%d differs: %q vs first %q", i, got, first)
		}
	}
}

// -------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------

// hexEncode is a small local helper to avoid importing encoding/hex
// just for this; layoutKey() does the real encoding internally.
func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0x0f]
	}
	return string(out)
}
