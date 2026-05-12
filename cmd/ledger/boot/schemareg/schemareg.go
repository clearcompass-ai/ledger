/*
Package schemareg builds the ledger's schema.Registry — the
explicit, dependency-injected binding container introduced in
attesta SDK v0.4.0.

# Why a dedicated boot package

The SDK's schema.Registry is the artifact the composition root
produces when it declares which schemas this DEPLOYMENT admits.
The SDK ships ValidatePREGrantCommitmentEntry and
ValidateEscrowSplitCommitmentEntry as exported package functions
(neutral, domain-agnostic primitives); the ledger is the consumer
that decides "yes, our admission pipeline accepts these two."

We isolate the registry construction in its own package for three
reasons:

 1. AUDITABILITY. An auditor reading boot/schemareg/schemareg.go
    learns the full list of admitted schemas without scanning
    init() functions across the import graph (the SDK explicitly
    avoids init()-based registration for this reason).
 2. SINGLE-DECLARATION. The registry is Frozen immediately after
    wiring; the same construction code can't accidentally re-bind
    a schema with different semantics later in the boot sequence.
 3. TEST-FRIENDLY. Integration tests construct their own registry
    via NewRegistry + Bind, exercising the same bindings the
    production composition root produces, without depending on
    init() ordering.

# Adoption story

Before v0.4.0 the ledger's admission gate for commitment schemas
was a hard-coded switch in sequencer/loop.go::dispatchCommitmentSchema:

	switch peek.SchemaID {
	case artifact.PREGrantCommitmentSchemaID: ...
	case escrow.EscrowSplitCommitmentSchemaID: ...
	}

That switch baked schema admission into the sequencer hot path.
With v0.4.0 the same admission decision is data-driven through the
Registry: the sequencer consults Registry.Has + Registry.ValidateEntry
and the schema list is declared exactly once, here.

# What this registry binds

Two SDK-shipped commitment schemas, both used by the recording-
network admission path:

  - artifact.PREGrantCommitmentSchemaID → ValidatePREGrantCommitmentEntry
  - escrow.EscrowSplitCommitmentSchemaID → ValidateEscrowSplitCommitmentEntry

Both bindings use the SDK's default Extractor (the registry's
fallback JSONParameterExtractor); the ledger does not currently
consume the extracted SchemaParameters but the binding remains
extractor-capable so a future projection consumer can wire in
without re-declaring the schema list.

# Lifecycle

	reg, err := BuildLedgerSchemaRegistry()      // wire + freeze
	seq = seq.WithSchemaRegistry(reg)            // inject

The registry is Frozen on return; downstream code calls
Registry.ValidateEntry under a read-lock with no contention.
*/
package schemareg

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/crypto/escrow"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
)

// BuildLedgerSchemaRegistry constructs the ledger's schema
// admission registry, binds the two SDK-shipped commitment
// schemas, and freezes the registry. Returns an error only if the
// SDK constants drift in an incompatible way (e.g., two SDK
// schemas accidentally exporting the same ID) — a defensive
// signal that the SDK version was bumped without re-vetting the
// schema list.
//
// The returned registry is frozen; callers SHOULD treat it as
// immutable. Concurrent reads are safe.
func BuildLedgerSchemaRegistry() (*sdkschema.Registry, error) {
	reg := sdkschema.NewRegistry()

	// Bind PRE-grant commitment schema. Validator is the SDK's
	// ValidatePREGrantCommitmentEntry — checks ControlHeader,
	// SchemaID match, hex envelope, and DeserializePREGrantCommitment
	// (threshold bounds, set-length consistency, on-curve points).
	if err := reg.Bind(
		sdkschema.SchemaID(artifact.PREGrantCommitmentSchemaID),
		&sdkschema.Binding{
			Validator: sdkschema.ValidatePREGrantCommitmentEntry,
			// Extractor nil → registry's default JSONParameterExtractor.
		},
	); err != nil {
		return nil, fmt.Errorf("schemareg: bind %s: %w",
			artifact.PREGrantCommitmentSchemaID, err)
	}

	// Bind escrow-split commitment schema. Validator is the SDK's
	// ValidateEscrowSplitCommitmentEntry.
	if err := reg.Bind(
		sdkschema.SchemaID(escrow.EscrowSplitCommitmentSchemaID),
		&sdkschema.Binding{
			Validator: sdkschema.ValidateEscrowSplitCommitmentEntry,
		},
	); err != nil {
		return nil, fmt.Errorf("schemareg: bind %s: %w",
			escrow.EscrowSplitCommitmentSchemaID, err)
	}

	// Freeze: no further Bind calls succeed after this point. The
	// composition root declares its admitted schemas exactly here,
	// in one place, and the runtime cannot drift.
	reg.Freeze()

	return reg, nil
}
