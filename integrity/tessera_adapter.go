/*
FILE PATH: integrity/tessera_adapter.go

TesseraAdapter — single struct satisfying both Verifier and
Reasserter against the operator's embedded Tessera library. This
is what cmd/operator/main.go wires into the Detector.

DESIGN:
  Two-surface aggregation. The integrity-side abstractions
  (Verifier + Reasserter) keep the boot reconciliation and periodic
  sample-verify paths decoupled from each other and from the
  underlying Tessera primitives. The adapter holds the union of
  what's needed:

    - AppenderBackend (for re-Add) — *tessera.EmbeddedAppender
    - TileReader (for hash-at-seq reads) — *tessera.TileReader

  Both come from the existing tessera package and were already
  constructed by cmd/operator/main.go for the builder loop and
  proof generation; the integrity adapter just borrows references.

LIFECYCLE:
  Stateless. The adapter does not own its underlying primitives —
  it borrows references from the composition root, which already
  manages the appender's Close.
*/
package integrity

// TesseraAdapter satisfies Verifier + Reasserter by composing
// per-surface implementations. Construct via NewTesseraAdapter at
// the composition root.
type TesseraAdapter struct {
	Verifier
	Reasserter
}

// NewTesseraAdapter returns an adapter wrapping the supplied
// AppenderBackend (for re-Add) and TileReader (for hash-at-seq
// reads). Both arguments MUST be non-nil — the integrity Detector
// is useless without either.
func NewTesseraAdapter(appender AppenderBackend, tiles TileReader) *TesseraAdapter {
	return &TesseraAdapter{
		Verifier:   NewVerifier(tiles),
		Reasserter: NewReasserter(appender),
	}
}

// Compile-time pin: TesseraAdapter satisfies both interfaces.
var (
	_ Verifier   = (*TesseraAdapter)(nil)
	_ Reasserter = (*TesseraAdapter)(nil)
)
