/*
FILE PATH:

	api/fuzz_test.go

DESCRIPTION:

	J1 — Fuzz tests for every wire-format parser the api package
	consumes from untrusted bytes. Untrusted-bytes parsers are
	the #1 historical CVE class for transparency logs (Trillian
	CVE-2022-23552, Gin CVE-2023-29401, etc.).

	Run nightly via .github/workflows/fuzz.yml; one-off invocations:

	    go test -run=^$ -fuzz=^FuzzTileHandlerPath$ -fuzztime=30s ./api/
	    go test -run=^$ -fuzz=^FuzzAdmissionEnvelope$ -fuzztime=30s ./api/

	A crash artifact lands in testdata/fuzz/<FuzzName>/<crash-hash>;
	add it to the seed corpus permanently so the fuzzer never
	regresses.

KEY ARCHITECTURAL DECISIONS:
  - Properties are RANGE properties (rejection is closed under
    arbitrary 8-bit input), not specific-value properties. The
    validator must say no to EVERY hostile path.
  - Seed corpus reuses production-shaped inputs from existing
    tile_handler_test.go so the fuzzer starts from realistic
    coverage.
  - Each fuzzer panics ONLY on a property violation; never on
    the wire-parser itself (the fuzzer tolerates errors;
    missing bounds-checks become the failure mode).
*/
package api

import (
	"bytes"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// -------------------------------------------------------------------------------------------------
// 1) FuzzTileHandlerPath — pin validRestPath + validPathSegment
// -------------------------------------------------------------------------------------------------

// FuzzTileHandlerPath asserts: for any string input, the
// validators NEVER ACCEPT a path containing ".." (traversal),
// "/" prefix (absolute), or non-ASCII / non-printable bytes.
//
// Property: rejection is closed under arbitrary input. A bug
// would be: validators accept some clever encoding (e.g.,
// "%2e%2e/" already URL-decoded; or "..\x00") that still
// resolves to a path-traversal at the storage layer.
func FuzzTileHandlerPath(f *testing.F) {
	// Production-shaped seeds.
	f.Add("0", "x001/067")
	f.Add("0", "x001/067.p/42")
	f.Add("entries", "x001/067")
	f.Add("entries", "x001/067.p/100")
	// Hostile seeds.
	f.Add("..", "etc/passwd")
	f.Add("0", "../../../etc/passwd")
	f.Add("0", "/absolute")
	f.Add("0", "x001/\x00null")
	f.Add("\x7F", "x001/067") // DEL byte in level

	f.Fuzz(func(t *testing.T, level, rest string) {
		levelOK := validPathSegment(level)
		restOK := validRestPath(rest)
		// Property: if EITHER the level OR the rest contains "..",
		// "\\", non-printable, or absolute-prefix, the validator
		// MUST reject (one or both must return false).
		if hasTraversalShape(level) && levelOK {
			t.Errorf("validPathSegment accepted hostile level %q", level)
		}
		if hasTraversalShape(rest) && restOK {
			t.Errorf("validRestPath accepted hostile rest %q", rest)
		}
		// If both validators accept, the resulting path must
		// be representable as a clean tile path (no embedded
		// escapes that resurface downstream).
		if levelOK && restOK {
			joined := "tile/" + level + "/" + rest
			if strings.Contains(joined, "..") {
				t.Errorf("accepted level=%q + rest=%q produce traversal: %q",
					level, rest, joined)
			}
		}
	})
}

// hasTraversalShape returns true if s contains shapes the
// validators MUST reject. Used as the property-side oracle so
// the fuzzer detects "validator returned true for input that's
// obviously hostile" failures.
func hasTraversalShape(s string) bool {
	if s == "." || s == ".." || strings.Contains(s, "..") {
		return true
	}
	if strings.HasPrefix(s, "/") {
		return true
	}
	if strings.ContainsAny(s, "\\") {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------------------------------
// 2) FuzzAdmissionEnvelope — pin envelope.Deserialize panic-resistance
// -------------------------------------------------------------------------------------------------

// FuzzAdmissionEnvelope asserts that envelope.Deserialize NEVER
// panics on any input — the load-bearing property for the admission
// hot path. POST /v1/entries calls Deserialize on raw bytes from
// arbitrary HTTP clients (api/submission.go:330); the sequencer
// replay path makes the same call against WAL-stored bytes
// (sequencer/loop.go:283, sequencer/replay.go:321). If either input
// can trigger a panic, an attacker who can either (a) submit a POST
// body or (b) write to the WAL via boot-time replay corruption can
// crash the ledger.
//
// Defense-in-depth: the SDK's Deserialize is structured to return
// errors for every malformed shape, but a fuzzer is the only way to
// prove the property holds across the entire 2^N input space (vs
// the dozen-or-so hand-written rejection tests in
// attesta/core/envelope/serialize_test.go).
//
// Properties enforced:
//
//   (a) Deserialize NEVER panics. (testing.T surfaces panics as
//       fuzz crashes automatically.)
//   (b) When Deserialize succeeds, the returned *Entry is non-nil
//       (nil-entry-with-nil-err is a contract violation that
//       would cause caller-side nil-pointer dereferences).
//   (c) When Deserialize succeeds, round-tripping through
//       Serialize produces canonical bytes that themselves
//       Deserialize successfully (idempotence). A bug here would
//       indicate non-determinism in the serializer — corrupting
//       any downstream hash-of-canonical-bytes invariant.
//
// Run nightly via .github/workflows/fuzz.yml; one-off invocation:
//
//	go test -run=^$ -fuzz=^FuzzAdmissionEnvelope$ -fuzztime=60s ./api/
func FuzzAdmissionEnvelope(f *testing.F) {
	// Realistic-shape seeds — known-malformed preambles that
	// exercise distinct error paths. Each seed should hit a
	// distinct branch in Deserialize so the fuzzer's coverage
	// graph starts dense.
	f.Add([]byte{})                              // empty
	f.Add([]byte{0x00})                          // shorter than preamble
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00}) // 6-byte preamble, hbl=0
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // all-0xFF preamble (huge hbl)
	// HBL pointing past the buffer end — bounds-check oracle.
	f.Add([]byte{0x00, 0x05, 0x00, 0x00, 0xFF, 0xFF})
	// Hostile seeds.
	f.Add(bytes.Repeat([]byte{0x00}, 32))
	f.Add(bytes.Repeat([]byte{0xFF}, 32))
	f.Add(bytes.Repeat([]byte{0x41}, 1024))
	// Boundary: pretends to be a valid v5 entry with hbl just over
	// the buffer length — exercises the hbl>len bounds check.
	f.Add([]byte{0x00, 0x05, 0x00, 0x00, 0x00, 0x07, 0xAA})

	f.Fuzz(func(t *testing.T, canonical []byte) {
		// Property (a): no panic. Implicit — any panic is a crash.
		entry, err := envelope.Deserialize(canonical)

		if err == nil {
			// Property (b): nil-entry + nil-err is a contract bug.
			if entry == nil {
				t.Errorf("Deserialize accepted input but returned nil entry; input=%x", canonical)
				return
			}
			// Property (c): re-serialize must succeed and the
			// result must itself Deserialize without error
			// (idempotence under canonicalization). We do NOT
			// assert byte-identity between input and round-trip
			// output: Deserialize tolerates additive trailing
			// HBL bytes for forward-compat (per the SDK
			// docblock), so the canonical form may differ.
			roundTrip, err := envelope.Serialize(entry)
			if err != nil {
				t.Errorf("Serialize(Deserialize(input)) failed: %v\ninput=%x", err, canonical)
				return
			}
			if _, err := envelope.Deserialize(roundTrip); err != nil {
				t.Errorf("Deserialize(Serialize(Deserialize(input))) failed: %v\ninput=%x\nroundTrip=%x",
					err, canonical, roundTrip)
			}
		}
		// If err != nil, the rejection is correct — Property (a)
		// is satisfied implicitly by the absence of a panic.
	})
}

// -------------------------------------------------------------------------------------------------
// 3) FuzzWriteTypedError_BodyShape — pin error-response surface
// -------------------------------------------------------------------------------------------------

// FuzzWriteTypedError_BodyShape asserts: writeTypedError never
// panics on arbitrary (errorClass, status, msg) combinations
// AND the resulting JSON body is always parseable + contains
// no XSS / HTML-escape bypasses.
//
// Property: response body is always valid JSON.
//
// (Skipped on first cut — wiring requires a httptest harness
// per call which inflates the fuzz body. Documented as a
// future fuzzer in operations.md.)
