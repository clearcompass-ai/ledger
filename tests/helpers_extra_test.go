/*
FILE PATH: tests/helpers_extra_test.go

DESCRIPTION:

	Additive helpers — testLedgerDID + a thin wrapper for entry
	construction that defaults Destination when callers leave it
	unset. Companion to helpers_test.go; kept separate to keep
	helpers_test.go diff-stable.

KEY ARCHITECTURAL DECISIONS:
  - testLedgerDID mirrors testLogDID (the canonical DID the test
    server is configured with). Helpers default Destination to
    testLogDID. Tests that exercise cross-destination behavior pass
    an explicit Destination in the ControlHeader.
  - makeUnsignedEntry runs envelope.NewUnsignedEntry (not a struct
    literal) so it exercises the same write-time gate that production
    callers hit on the unsigned-construction path. Tests that
    deliberately forge malformed entries bypass this helper and
    hand-construct via struct literal; tests that need signed entries
    call envelope.NewEntry directly with a []Signature third argument.
  - No global state. Every helper takes *testing.T for failure reporting.
*/
package tests

import (
	"github.com/clearcompass-ai/attesta/core/envelope"
)

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────

// testLedgerDID is the DID the test server's cfg.LedgerDID field
// receives. It tracks testLogDID so existing fixtures keep working
// without a per-test edit.
//
// MUST match the value the test server's config passes into
// api.SubmissionDeps.LogDID, or every default-Destination entry will
// fail step 3b's destination check with 403 Forbidden.
const testLedgerDID = testLogDID

// ─────────────────────────────────────────────────────────────────────
// Compile-time sanity checks
// ─────────────────────────────────────────────────────────────────────

// These var declarations exercise the SDK's primary Entry-hashing
// primitives at compile time. If the SDK ever renames or removes one of
// these, the test suite breaks at build time — making the API drift
// obvious before any test run.
var (
	_ = envelope.EntryIdentity // Tessera dedup key (preferred vocabulary)
	_ = envelope.EntryLeafHash // RFC 6962 leaf hash (consumer-side only)
	_ = envelope.Serialize     // canonical bytes (signatures embedded)
	_ = envelope.Deserialize   // canonical parser (signatures extracted)
	_ = envelope.ValidateDestination
)
