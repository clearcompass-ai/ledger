/*
FILE PATH:

	admission/entry_schema_verifier.go

DESCRIPTION:

	Schema validation at the ledger's trust boundary, mirroring the
	signature/DID-resolver and BLS-quorum gates in this package.

	The admission HTTP path (POST /v1/entries) must reject malformed
	commitment payloads BEFORE they consume a Tessera sequence number
	and a WAL slot. The downstream sequencer's post-AppendLeaf
	dispatch is defense-in-depth — adequate when the front door
	already enforces structure, but the front door is the right place
	to enforce it.

	This file plays the same role for the SDK's schema.Registry that
	entry_signature_verifier.go plays for the SDK's did resolver: a
	local minimal interface (admission.SchemaRegistry) declaring the
	exact surface admission needs, structurally satisfied by the SDK's
	concrete *schema.Registry (proven by the compile-time pin in
	sdk_schema_registry_pin_test.go).

KEY ARCHITECTURAL DECISIONS:

  - SchemaRegistry is a LOCAL interface, not a re-export. The ledger
    owns its admission contract; the SDK's Registry happens to
    satisfy it structurally. Production wiring threads a real
    *sdkschema.Registry; tests wire stubs. The DI pattern is
    identical to admission.DIDResolver.

  - The verifier consults Has() before ValidateEntry(). An unknown
    SchemaID is treated as "not a commitment schema we care about" —
    the same back-compat semantics as the sequencer's legacy switch.
    This keeps schema-less entries (lifecycle markers, peer anchors)
    flowing through admission without forcing every domain payload
    to declare a registered schema.

  - Nil registry is permitted at the call site of VerifyEntrySchema
    and triggers the "no schema gate" trust model. Mirrors the nil
    DIDResolver semantics: the wire format was still envelope-checked
    upstream; this verifier just doesn't apply the additional schema
    structural gate.

  - The schema_id peek uses identical JSON shape to
    sequencer/loop.go::commitmentPayloadPeek. The two must stay in
    sync; a future refactor could lift the peek into a shared SDK
    helper, but today the duplication is small and the trust
    boundaries are distinct (admission front door vs sequencer
    post-AppendLeaf dispatch) so the two callsites read clearly.

KEY DEPENDENCIES:

  - github.com/clearcompass-ai/attesta/core/envelope: Entry.
  - JSON peek: encoding/json (stdlib).
*/
package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
)

// ErrSchemaInvalid is returned by VerifyEntrySchema when an entry's
// DomainPayload references a registered SchemaID but the bound
// validator rejects the payload structure. Maps to HTTP 422
// Unprocessable Entity at the api layer.
var ErrSchemaInvalid = errors.New("admission: entry schema invalid")

// SchemaRegistry is the admission-side surface of the SDK's
// schema.Registry — the methods VerifyEntrySchema actually calls.
// The SDK's concrete *schema.Registry satisfies this structurally
// (pinned in sdk_schema_registry_pin_test.go); test fixtures can
// supply stubs.
//
// The interface uses sdkschema.SchemaID (a typed string) — not
// plain string — so the SDK's concrete *Registry satisfies it
// structurally. Go's interface satisfaction is exact-type-match,
// not assignability; the named SchemaID type cannot be substituted
// with plain string at the interface level. The admission package
// already imports the SDK's core/envelope; adding core/schema as a
// peer SDK coupling carries no architectural cost.
//
// Has reports whether a SchemaID has a binding in the registry.
// Returns false for empty or unbound IDs.
//
// ValidateEntry routes admission-time validation through the bound
// EntryValidator. Returns nil if the registry has no validator
// configured for the binding, the SDK's sentinel error
// ErrSchemaIDNotFound if the binding is missing, or the validator's
// own error on a structural rejection.
type SchemaRegistry interface {
	Has(id sdkschema.SchemaID) bool
	ValidateEntry(id sdkschema.SchemaID, entry *envelope.Entry) error
}

// schemaPeek is the minimum-fields JSON shape used to extract the
// SchemaID from an entry's DomainPayload at admission time.
// Identical in intent to sequencer/loop.go::commitmentPayloadPeek.
type schemaPeek struct {
	SchemaID string `json:"schema_id"`
}

// VerifyEntrySchema validates the entry against the schema registry.
//
// Returns:
//   - nil when the registry is nil (no schema gate configured).
//   - nil when the entry's DomainPayload is empty or non-JSON
//     (schemaless entries pass through; the envelope already
//     enforces wire-format integrity upstream).
//   - nil when the entry's schema_id is not bound in the registry
//     (back-compat with unknown schemas; same semantic as the
//     sequencer's legacy default branch).
//   - ErrSchemaInvalid wrapped with the underlying validator error
//     when the bound validator rejects the payload structure.
//
// VerifyEntrySchema does NOT extract the SplitID. SplitID extraction
// lives in the sequencer's post-AppendLeaf path because it is a
// projection-side concern (indexing), not an admission gate. Keeping
// the two responsibilities separate lets either side evolve
// independently — and lets test fixtures exercise the admission gate
// without standing up an in-process sequencer.
func VerifyEntrySchema(
	ctx context.Context,
	entry *envelope.Entry,
	registry SchemaRegistry,
) error {
	if entry == nil {
		return fmt.Errorf("admission: VerifyEntrySchema called with nil entry")
	}
	if registry == nil {
		// No schema gate configured. Wire-format-integrity-only
		// trust model — same semantic as a nil DIDResolver.
		return nil
	}
	if len(entry.DomainPayload) == 0 {
		// Empty payload: nothing to schema-check.
		return nil
	}

	var peek schemaPeek
	if err := json.Unmarshal(entry.DomainPayload, &peek); err != nil {
		// Non-JSON payload: not a recognized commitment schema. The
		// envelope already verified wire integrity; we don't enforce
		// JSON-shapedness on every DomainPayload here.
		return nil
	}
	if peek.SchemaID == "" {
		// JSON without a schema_id field: schemaless entry.
		return nil
	}
	sid := sdkschema.SchemaID(peek.SchemaID)
	if !registry.Has(sid) {
		// Unknown SchemaID: not a commitment schema we admit. Pass
		// through — same back-compat as the sequencer's default branch.
		return nil
	}
	if err := registry.ValidateEntry(sid, entry); err != nil {
		// Multi-wrap (Go 1.20+) so callers can errors.Is against both
		// ErrSchemaInvalid (the admission-side classification) AND the
		// validator's own sentinel (e.g., the SDK's
		// ErrCommitmentPayloadMalformed). Without the double-%w only
		// ErrSchemaInvalid would chain.
		return fmt.Errorf("%w: schema_id=%s: %w",
			ErrSchemaInvalid, peek.SchemaID, err)
	}
	_ = ctx // reserved for future per-validator contexts; signature stable
	return nil
}
