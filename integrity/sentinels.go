/*
FILE PATH: integrity/sentinels.go

Transient-condition sentinels for the integrity package. Distinct
from the divergence/phantom sentinels in integrity.go because the
conditions here are NOT correctness failures — they're flow-state
markers that the Detector uses to discriminate "no signal yet"
from "signal says diverged".
*/
package integrity

import "errors"

// ErrTileNotYetFlushed indicates the sampled seq is in a tile
// that Tessera has integrated in-memory but not yet flushed to
// durable tile storage AT THE PARTIAL COUNT the verifier asked
// for. Transient by construction: Tessera flushes at
// batch_max_age (default 1s) or batch_size (256) boundaries,
// after which the tile materializes either as a partial with the
// new count or as a full tile. Not a cryptographic divergence —
// sampling should resume on the next cycle.
//
// The Detector treats this as a skip, incrementing samplesSkipped
// rather than invariantFailures.
var ErrTileNotYetFlushed = errors.New("integrity: tile not yet flushed")
