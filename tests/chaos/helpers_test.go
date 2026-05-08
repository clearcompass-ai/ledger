//go:build chaos
// +build chaos

/*
FILE PATH:

	tests/chaos/helpers_test.go

DESCRIPTION:

	Shared helpers for the chaos suite. Lives in its own file
	so individual scenarios can be deleted/refactored without
	breaking siblings that share these primitives.
*/
package chaos

// quietWriter is an io.Writer that swallows all output. Used
// to suppress slog output during chaos tests that don't need
// the noise (and where stdout/stderr would race with the
// chaos signal).
type quietWriter struct{}

func (quietWriter) Write(b []byte) (int, error) { return len(b), nil }
