// FILE PATH: tests/chaos/smt_reconstruction/reconstructor_test.go
//
// Unit tests for the helpers in reconstructor.go that don't need
// a live Postgres connection. The Reconstruct function itself
// requires real PG state and is exercised by the chaos suite's
// kill-restart tests (which populate a real DB then validate the
// SMT root survives the kill).
package smt_reconstruction

import (
	"strings"
	"testing"
)

func TestResult_FormatMismatch_EmptyOnMatch(t *testing.T) {
	r := Result{
		LeafCount: 100,
		Match:     true,
		// Roots happen to be equal — Format must return "" on match.
		ReconstructedRoot: [32]byte{1, 2, 3},
		PersistedRoot:     [32]byte{1, 2, 3},
	}
	if got := r.FormatMismatch(); got != "" {
		t.Errorf("FormatMismatch on Match=true returned %q, want empty", got)
	}
}

func TestResult_FormatMismatch_IncludesAllFields(t *testing.T) {
	r := Result{
		LeafCount:         12345,
		TreeSize:          12344,
		ReconstructedRoot: [32]byte{0xAA, 0xBB},
		PersistedRoot:     [32]byte{0xCC, 0xDD},
		Match:             false,
	}
	got := r.FormatMismatch()
	for _, want := range []string{
		"12345",                  // LeafCount
		"12344",                  // TreeSize
		"aabb",                   // reconstructed root prefix
		"ccdd",                   // persisted root prefix
		"mismatch",               // diagnostic header
		"reconstructed",          // labelled field
		"persisted",              // labelled field
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatMismatch missing %q in:\n%s", want, got)
		}
	}
}
