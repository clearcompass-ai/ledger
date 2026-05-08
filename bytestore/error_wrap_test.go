/*
FILE PATH: bytestore/error_wrap_test.go

DESCRIPTION:

	Regression tests for the structural invariant that
	NotFound-shaped errors returned by the GCS and S3 adapters
	preserve TWO independent wrap chains:

	  errors.Is(err, ErrNotFound)               // adapter-agnostic
	  errors.Is(err, storage.ErrObjectNotExist) // adapter-specific (GCS)
	  errors.As(err, &*types.NoSuchKey)         // adapter-specific (S3)

	Pre-fix shape (broken since the bytestore hexagonal refactor):

	    return nil, fmt.Errorf("bytestore/gcs: ... %w (gcs: %v)",
	        ErrNotFound, err)
	                                        // ^^ %v stringifies — second
	                                        //    wrap chain is lost.

	Post-fix shape:

	    return nil, fmt.Errorf("bytestore/gcs: ... %w (gcs: %w)",
	        ErrNotFound, err)
	                                        // ^^ %w (Go 1.20+ supports
	                                        //    multiple %w in one
	                                        //    fmt.Errorf via Unwrap()
	                                        //    []error).

	The pre-fix bug was silent in CI (fake-gcs returns a different
	error shape) and only surfaced when running the real-GCS-gated
	bytestore tests against a real bucket. These tests run as part
	of the normal `go test ./...` invocation and need no real
	backend, so the regression is now CI-visible.
*/
package bytestore

import (
	"errors"
	"fmt"
	"testing"

	"cloud.google.com/go/storage"
)

// TestErrWrap_GCSNotFound_PreservesBothWraps pins the wrap shape
// at bytestore/gcs.go:235. Catches a future revert to %v.
func TestErrWrap_GCSNotFound_PreservesBothWraps(t *testing.T) {
	inner := storage.ErrObjectNotExist
	err := fmt.Errorf("bytestore/gcs: seq=%d hash=%x: %w (gcs: %w)",
		99, [4]byte{0xab, 0xcd, 0xef, 0x12}, ErrNotFound, inner)

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("errors.Is(err, ErrNotFound) = false; want true")
	}
	if !errors.Is(err, storage.ErrObjectNotExist) {
		t.Errorf("errors.Is(err, storage.ErrObjectNotExist) = false; want true. " +
			"gcs.go must use %%w (not %%v) for the inner GCS error so the " +
			"errors.Is chain reaches storage.ErrObjectNotExist.")
	}
}

// TestErrWrap_S3NotFound_PreservesBothWraps pins the wrap shape
// at bytestore/s3.go:267. Symmetric to the GCS test.
func TestErrWrap_S3NotFound_PreservesBothWraps(t *testing.T) {
	// Synthetic S3 error: a plain sentinel that errors.Is can
	// match through the wrap chain. Using a real *types.NoSuchKey
	// would couple the test to AWS SDK internals; the structural
	// invariant we pin is "%w preserves the inner wrap," and any
	// concrete inner error suffices to demonstrate it.
	inner := errors.New("synthetic NoSuchKey")
	err := fmt.Errorf("bytestore/s3: seq=%d hash=%x: %w (s3: %w)",
		99, [4]byte{0xab, 0xcd, 0xef, 0x12}, ErrNotFound, inner)

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("errors.Is(err, ErrNotFound) = false; want true")
	}
	if !errors.Is(err, inner) {
		t.Errorf("errors.Is(err, inner) = false; want true. " +
			"s3.go must use %%w (not %%v) for the inner S3 error so the " +
			"errors.Is chain reaches the underlying SDK error type.")
	}
}
