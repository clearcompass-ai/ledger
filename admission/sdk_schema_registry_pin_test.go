/*
FILE PATH: admission/sdk_schema_registry_pin_test.go

DESCRIPTION:

	Pin tests for the SDK's *schema.Registry (attesta v0.4.0) as the
	concrete that satisfies the local admission.SchemaRegistry
	interface. Mirrors sdk_resolver_pin_test.go for the DID resolver
	plumbing.

	Three guarantees this file pins:

	(1) Compile-time: *sdkschema.Registry satisfies the local
	    admission.SchemaRegistry interface. If the SDK ever changes
	    Has or ValidateEntry's signature, the build breaks here before
	    any handler test runs.

	(2) Runtime: VerifyEntrySchema correctly routes a recognized
	    SchemaID through the bound validator and surfaces the
	    validator's error wrapped in ErrSchemaInvalid.

	(3) Negative: a nil registry, an empty payload, a non-JSON
	    payload, a JSON payload without schema_id, and a payload with
	    an unbound schema_id all pass through without error — the
	    front door must not over-reject schemaless or unknown-schema
	    entries.

	Together these prove the admission gate is wired against the LIVE
	SDK type (a typo in the constructor would fail the round-trip
	assertion below).
*/
package admission

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
)

// ─────────────────────────────────────────────────────────────────────
// (1) Compile-time interface assertion
// ─────────────────────────────────────────────────────────────────────

// _ pins *sdkschema.Registry to the local SchemaRegistry shape so any
// future SDK API change surfaces at build time, not at handler-test
// runtime.
var _ SchemaRegistry = (*sdkschema.Registry)(nil)

// ─────────────────────────────────────────────────────────────────────
// (2) Runtime: registered SchemaID + valid payload → nil
// ─────────────────────────────────────────────────────────────────────

const testSchemaID = "test-schema-v1"

// alwaysAcceptValidator is the trivial EntryValidator used for the
// runtime tests: nil ⇒ valid. Production validators (e.g.,
// ValidatePREGrantCommitmentEntry) carry domain-specific rules; this
// fixture isolates the routing under test from validator-internal logic.
func alwaysAcceptValidator(_ *envelope.Entry) error { return nil }

// alwaysRejectValidator returns a sentinel; lets the tests prove the
// validator's error path round-trips through VerifyEntrySchema.
var errStubReject = errors.New("stub validator rejection")

func alwaysRejectValidator(_ *envelope.Entry) error { return errStubReject }

func newTestRegistry(t *testing.T, v sdkschema.EntryValidator) *sdkschema.Registry {
	t.Helper()
	r := sdkschema.NewRegistry()
	if err := r.Bind(sdkschema.SchemaID(testSchemaID), &sdkschema.Binding{
		Validator: v,
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	r.Freeze()
	return r
}

func TestVerifyEntrySchema_Accept(t *testing.T) {
	reg := newTestRegistry(t, alwaysAcceptValidator)
	entry := &envelope.Entry{
		DomainPayload: []byte(`{"schema_id":"` + testSchemaID + `","ok":true}`),
	}
	if err := VerifyEntrySchema(context.Background(), entry, reg); err != nil {
		t.Errorf("VerifyEntrySchema = %v, want nil", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (3) Runtime: registered SchemaID + invalid payload → ErrSchemaInvalid
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntrySchema_RejectWrapsSentinel(t *testing.T) {
	reg := newTestRegistry(t, alwaysRejectValidator)
	entry := &envelope.Entry{
		DomainPayload: []byte(`{"schema_id":"` + testSchemaID + `"}`),
	}
	err := VerifyEntrySchema(context.Background(), entry, reg)
	if err == nil {
		t.Fatal("VerifyEntrySchema accepted a validator-rejected payload")
	}
	if !errors.Is(err, ErrSchemaInvalid) {
		t.Errorf("expected ErrSchemaInvalid in chain, got %v", err)
	}
	if !errors.Is(err, errStubReject) {
		t.Errorf("expected stub validator error in chain, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (4) Negative: pass-through paths
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntrySchema_NilRegistry_PassThrough(t *testing.T) {
	entry := &envelope.Entry{
		DomainPayload: []byte(`{"schema_id":"` + testSchemaID + `"}`),
	}
	if err := VerifyEntrySchema(context.Background(), entry, nil); err != nil {
		t.Errorf("nil registry must pass through, got %v", err)
	}
}

func TestVerifyEntrySchema_EmptyPayload_PassThrough(t *testing.T) {
	reg := newTestRegistry(t, alwaysRejectValidator) // would reject if reached
	entry := &envelope.Entry{DomainPayload: nil}
	if err := VerifyEntrySchema(context.Background(), entry, reg); err != nil {
		t.Errorf("empty payload must pass through, got %v", err)
	}
}

func TestVerifyEntrySchema_NonJSONPayload_PassThrough(t *testing.T) {
	reg := newTestRegistry(t, alwaysRejectValidator)
	entry := &envelope.Entry{DomainPayload: []byte("not json {{{")}
	if err := VerifyEntrySchema(context.Background(), entry, reg); err != nil {
		t.Errorf("non-JSON payload must pass through, got %v", err)
	}
}

func TestVerifyEntrySchema_JSONWithoutSchemaID_PassThrough(t *testing.T) {
	reg := newTestRegistry(t, alwaysRejectValidator)
	entry := &envelope.Entry{
		DomainPayload: []byte(`{"some_other_field":"value"}`),
	}
	if err := VerifyEntrySchema(context.Background(), entry, reg); err != nil {
		t.Errorf("schema_id-less JSON must pass through, got %v", err)
	}
}

func TestVerifyEntrySchema_UnboundSchemaID_PassThrough(t *testing.T) {
	reg := newTestRegistry(t, alwaysRejectValidator)
	entry := &envelope.Entry{
		DomainPayload: []byte(`{"schema_id":"unbound-schema-v0"}`),
	}
	if err := VerifyEntrySchema(context.Background(), entry, reg); err != nil {
		t.Errorf("unbound schema_id must pass through, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (5) Nil entry surfaces a programming-error
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntrySchema_NilEntry_Errors(t *testing.T) {
	reg := newTestRegistry(t, alwaysAcceptValidator)
	if err := VerifyEntrySchema(context.Background(), nil, reg); err == nil {
		t.Fatal("nil entry must surface a programming error")
	}
}
