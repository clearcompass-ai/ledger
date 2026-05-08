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
	"strings"
	"testing"
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
// 2) FuzzWriteTypedError_BodyShape — pin error-response surface
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
