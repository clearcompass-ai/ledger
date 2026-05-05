/*
FILE PATH: integrity/tessera_adapter.go

TesseraAdapter — satisfies Verifier against the ledger's
embedded Tessera tile reader. This is what cmd/ledger/main.go
wires into the Detector.

POST-CLEANUP NOTE:

	Pre-cleanup the adapter aggregated Verifier + Reasserter and
	carried two underlying primitives (AppenderBackend +
	TileReader). With Reasserter deleted (the Sequencer subsumes
	boot recovery via its drainOnce on Run start), this adapter
	collapses to a thin Verifier-only wrapper. We keep the named
	type for symmetry with the rest of the integrity wiring and
	for the compile-time pin below.

LIFECYCLE:

	Stateless. The adapter does not own the TileReader — it borrows
	the reference from the composition root, which already manages
	the appender's Close.
*/
package integrity

// TesseraAdapter satisfies Verifier by delegating HashAt reads to
// a *tessera.TileReader. Construct via NewTesseraAdapter at the
// composition root.
type TesseraAdapter struct {
	Verifier
}

// NewTesseraAdapter returns an adapter that resolves HashAt against
// the supplied TileReader. tiles MUST be non-nil — the Detector
// is useless without it.
func NewTesseraAdapter(tiles TileReader) *TesseraAdapter {
	return &TesseraAdapter{
		Verifier: NewVerifier(tiles),
	}
}

// Compile-time pin: TesseraAdapter satisfies the Verifier
// interface.
var _ Verifier = (*TesseraAdapter)(nil)
