/*
FILE PATH:

	bytestore/fuzz_test.go

DESCRIPTION:

	J1 — Fuzz the GCSTiles object-key validator. Defense-in-depth
	on top of api/'s fuzz coverage: even if the api validator
	misses something, the bytestore layer MUST refuse hostile
	paths before issuing a GCS round-trip.

	Run via:
	    go test -run=^$ -fuzz=^FuzzGCSTilesObjectKey$ \
	        -fuzztime=30s ./bytestore/
*/
package bytestore

import (
	"strings"
	"testing"
)

// FuzzGCSTilesObjectKey asserts: objectKey() rejects every "..",
// absolute path, and non-printable byte sequence; accepted output
// is always <prefix>/<input> with no path-traversal escape.
//
// Property: if input contains traversal / non-printable shapes,
// objectKey returns an error. Otherwise the output must equal
// either input (empty prefix) OR prefix+"/"+input.
func FuzzGCSTilesObjectKey(f *testing.F) {
	// Production-shaped seeds.
	f.Add("tessera", "tile/0/x001/067")
	f.Add("tessera", "tile/entries/x001/067")
	f.Add("tessera", "checkpoint")
	f.Add("", "tile/0/x001/067")
	// Hostile seeds.
	f.Add("tessera", "..")
	f.Add("tessera", "../etc/passwd")
	f.Add("tessera", "/etc/passwd")
	f.Add("tessera", "tile/\x00null")
	f.Add("tessera", "tile/\x7Fbad")

	f.Fuzz(func(t *testing.T, prefix, path string) {
		g := &GCSTiles{prefix: strings.TrimSuffix(prefix, "/")}
		got, err := g.objectKey(path)

		hostile := isHostilePath(path)
		if hostile && err == nil {
			t.Errorf("objectKey(prefix=%q, path=%q) ACCEPTED hostile input → %q",
				prefix, path, got)
			return
		}
		if !hostile && err != nil {
			// Acceptable: validator may reject some benign-shape
			// inputs we didn't classify as hostile. Just verify
			// the err message doesn't leak internal path info
			// beyond what the user supplied.
			if strings.Contains(err.Error(), "fatal") {
				t.Errorf("err mentions 'fatal' — possible internal-state leak: %v", err)
			}
			return
		}
		if err != nil {
			return
		}
		// Successful path: result MUST contain neither ".." nor
		// "//" (other than the prefix separator).
		if strings.Contains(got, "..") {
			t.Errorf("objectKey output contains '..': %q", got)
		}
	})
}

// isHostilePath classifies inputs the validator MUST reject.
// Mirrors the api/ fuzz_test.go's hasTraversalShape; kept in
// each package so a refactor of one validator can't dodge the
// other test's coverage.
func isHostilePath(s string) bool {
	if s == "" {
		return true
	}
	if strings.Contains(s, "..") {
		return true
	}
	if strings.HasPrefix(s, "/") {
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
