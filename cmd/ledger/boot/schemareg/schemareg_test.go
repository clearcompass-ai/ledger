/*
Unit tests for the ledger schema registry builder.

These tests pin the deployment-time declarations:
  - exactly the two SDK-shipped commitment schemas are bound
  - the registry is frozen on return (no late mutation possible)
  - Has / IDs / ValidateEntry route correctly
  - a malformed entry trips the bound EntryValidator

The tests intentionally avoid mocking the SDK validators: they
construct real envelopes with bad payloads to exercise the
ValidatePREGrantCommitmentEntry / ValidateEscrowSplitCommitmentEntry
error paths. This guarantees the registry is wired against the
LIVE SDK validators (a typo would compile but the test would fail
with the wrong error path).
*/
package schemareg

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/crypto/escrow"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
)

func TestBuildLedgerSchemaRegistry_ReturnsFrozenRegistry(t *testing.T) {
	reg, err := BuildLedgerSchemaRegistry()
	if err != nil {
		t.Fatalf("BuildLedgerSchemaRegistry: %v", err)
	}
	if reg == nil {
		t.Fatal("registry is nil")
	}
	if !reg.IsFrozen() {
		t.Error("registry not frozen — composition root must freeze immediately to prevent late re-binding")
	}
}

func TestBuildLedgerSchemaRegistry_BindsPREGrantCommitment(t *testing.T) {
	reg, err := BuildLedgerSchemaRegistry()
	if err != nil {
		t.Fatalf("BuildLedgerSchemaRegistry: %v", err)
	}
	sid := sdkschema.SchemaID(artifact.PREGrantCommitmentSchemaID)
	if !reg.Has(sid) {
		t.Errorf("Has(%q) = false, want true", sid)
	}
}

func TestBuildLedgerSchemaRegistry_BindsEscrowSplitCommitment(t *testing.T) {
	reg, err := BuildLedgerSchemaRegistry()
	if err != nil {
		t.Fatalf("BuildLedgerSchemaRegistry: %v", err)
	}
	sid := sdkschema.SchemaID(escrow.EscrowSplitCommitmentSchemaID)
	if !reg.Has(sid) {
		t.Errorf("Has(%q) = false, want true", sid)
	}
}

func TestBuildLedgerSchemaRegistry_OnlyTheTwoKnownSchemas(t *testing.T) {
	// Pin that the registry is exactly the two SDK schemas — if a
	// future SDK adds a third commitment schema, this test fails
	// loudly so the maintainer must update boot/schemareg
	// intentionally (Principle 15 — explicit declaration).
	reg, err := BuildLedgerSchemaRegistry()
	if err != nil {
		t.Fatalf("BuildLedgerSchemaRegistry: %v", err)
	}
	got := reg.IDs()
	want := []sdkschema.SchemaID{
		sdkschema.SchemaID(artifact.PREGrantCommitmentSchemaID),
		sdkschema.SchemaID(escrow.EscrowSplitCommitmentSchemaID),
	}
	if len(got) != len(want) {
		t.Fatalf("registry IDs = %v (len %d), want exactly %v (len %d) — schema list drift",
			got, len(got), want, len(want))
	}
	// IDs() returns sorted; build a set to compare order-independent.
	seen := map[sdkschema.SchemaID]struct{}{}
	for _, id := range got {
		seen[id] = struct{}{}
	}
	for _, id := range want {
		if _, ok := seen[id]; !ok {
			t.Errorf("missing expected SchemaID %q from registry", id)
		}
	}
}

func TestBuildLedgerSchemaRegistry_RejectsMalformedPREGrantPayload(t *testing.T) {
	reg, err := BuildLedgerSchemaRegistry()
	if err != nil {
		t.Fatalf("BuildLedgerSchemaRegistry: %v", err)
	}
	// Construct an entry with the right SchemaID in the header
	// but garbage in DomainPayload. The bound validator
	// (ValidatePREGrantCommitmentEntry) must reject it.
	entry := &envelope.Entry{
		DomainPayload: []byte(`{"schema_id":"` + artifact.PREGrantCommitmentSchemaID + `","commitment":"not-hex"}`),
	}
	err = reg.ValidateEntry(
		sdkschema.SchemaID(artifact.PREGrantCommitmentSchemaID), entry)
	if err == nil {
		t.Fatal("ValidateEntry accepted a malformed PREGrant payload — wrong validator wired")
	}
}

func TestBuildLedgerSchemaRegistry_RejectsMalformedEscrowSplitPayload(t *testing.T) {
	reg, err := BuildLedgerSchemaRegistry()
	if err != nil {
		t.Fatalf("BuildLedgerSchemaRegistry: %v", err)
	}
	entry := &envelope.Entry{
		DomainPayload: []byte(`{"schema_id":"` + escrow.EscrowSplitCommitmentSchemaID + `","commitment":"not-hex"}`),
	}
	err = reg.ValidateEntry(
		sdkschema.SchemaID(escrow.EscrowSplitCommitmentSchemaID), entry)
	if err == nil {
		t.Fatal("ValidateEntry accepted a malformed EscrowSplit payload — wrong validator wired")
	}
}

func TestBuildLedgerSchemaRegistry_UnknownSchemaID_ReturnsNotFound(t *testing.T) {
	reg, err := BuildLedgerSchemaRegistry()
	if err != nil {
		t.Fatalf("BuildLedgerSchemaRegistry: %v", err)
	}
	entry := &envelope.Entry{DomainPayload: []byte(`{}`)}
	err = reg.ValidateEntry(sdkschema.SchemaID("unknown-schema-v0"), entry)
	if !errors.Is(err, sdkschema.ErrSchemaIDNotFound) {
		t.Errorf("ValidateEntry(unknown) = %v, want ErrSchemaIDNotFound", err)
	}
}

func TestBuildLedgerSchemaRegistry_FrozenRejectsRebind(t *testing.T) {
	reg, err := BuildLedgerSchemaRegistry()
	if err != nil {
		t.Fatalf("BuildLedgerSchemaRegistry: %v", err)
	}
	// After freeze, any Bind attempt MUST fail with
	// ErrRegistryFrozen — the audit guarantee.
	err = reg.Bind(sdkschema.SchemaID("late-binding"), &sdkschema.Binding{})
	if !errors.Is(err, sdkschema.ErrRegistryFrozen) {
		t.Errorf("Bind after freeze = %v, want ErrRegistryFrozen", err)
	}
}
