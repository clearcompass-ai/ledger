/*
FILE PATH:

	admission/ledger_policy_resolver_test.go

DESCRIPTION:

	Binding tests for PR-I's LedgerPolicyResolver. Pins each arm
	of the six-condition self-gate:

	  1-2. entry self-declares SchemaRef + AttestationPolicyName
	  3.   schema entry resolves + parameters extract cleanly
	  4.   named policy declared on the schema
	  5.   v1.5 AdmissionEnforced=true (the load-bearing branch
	       for the rollout)
	  6.   TargetRoot non-nil, local, resolves

	Per-condition tests confirm a miss returns found=false WITHOUT
	error (defer to read-time) and a structural failure returns
	an error. The happy-path test confirms found=true returns a
	populated policy + primary + candidates.
*/
package admission

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
	"github.com/clearcompass-ai/attesta/types"
)

const lprTestLogDID = "did:web:lpr-test.log"

// fakeEntryFetcher returns configured outcomes keyed by position.
type fakeEntryFetcher struct {
	entries map[types.LogPosition]*types.EntryWithMetadata
	err     error
}

func (f *fakeEntryFetcher) Fetch(_ context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.entries[pos], nil
}

// fakeCandidateFetcher returns a configured candidate list.
type fakeCandidateFetcher struct {
	out []types.EntryWithMetadata
	err error
}

func (f *fakeCandidateFetcher) FetchByCosignatureOf(_ context.Context, _ types.LogPosition) ([]types.EntryWithMetadata, error) {
	return f.out, f.err
}

// fakeSchemas implements SchemaParametersExtractor with a
// configured outcome.
type fakeSchemas struct {
	params *types.SchemaParameters
	err    error
}

func (f *fakeSchemas) ExtractParameters(_ sdkschema.SchemaID, _ *envelope.Entry) (*types.SchemaParameters, error) {
	return f.params, f.err
}

// schemaEntryAt builds a real EntryWithMetadata whose payload
// carries `{"schema_id": "<id>"}` so the resolver's peek succeeds.
func schemaEntryAt(t *testing.T, pos types.LogPosition, schemaID string) *types.EntryWithMetadata {
	t.Helper()
	stub := []envelope.Signature{{
		SignerDID: "did:web:schema-author",
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	payload, _ := json.Marshal(map[string]string{"schema_id": schemaID})
	entry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID:   "did:web:schema-author",
		Destination: lprTestLogDID,
	}, payload, stub)
	if err != nil {
		t.Fatalf("schemaEntryAt NewEntry: %v", err)
	}
	bytes, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("schemaEntryAt Serialize: %v", err)
	}
	return &types.EntryWithMetadata{
		CanonicalBytes: bytes,
		LogTime:        time.Now().UTC(),
		Position:       pos,
	}
}

// primaryEntryAt builds a real primary entry at position pos.
// Used as the target of TargetRoot in the resolver's flow.
func primaryEntryAt(t *testing.T, pos types.LogPosition) *types.EntryWithMetadata {
	t.Helper()
	stub := []envelope.Signature{{
		SignerDID: "did:web:primary-author",
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	entry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID:   "did:web:primary-author",
		Destination: lprTestLogDID,
	}, nil, stub)
	if err != nil {
		t.Fatalf("primaryEntryAt NewEntry: %v", err)
	}
	bytes, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("primaryEntryAt Serialize: %v", err)
	}
	return &types.EntryWithMetadata{
		CanonicalBytes: bytes,
		LogTime:        time.Now().UTC(),
		Position:       pos,
	}
}

// adminGatedPolicy returns a policy with AdmissionEnforced=true.
func adminGatedPolicy(name string) types.AttestationPolicy {
	return types.AttestationPolicy{
		Name:              name,
		MinAttestors:      1,
		Required:          true,
		AdmissionEnforced: true,
	}
}

// readTimePolicy returns a policy with AdmissionEnforced=false.
func readTimePolicy(name string) types.AttestationPolicy {
	return types.AttestationPolicy{
		Name:              name,
		MinAttestors:      1,
		Required:          true,
		AdmissionEnforced: false,
	}
}

// newResolverWith builds a resolver wired against the supplied
// stubs, with sensible defaults for missing pieces.
func newResolverWith(t *testing.T, fetcher *fakeEntryFetcher, candidates *fakeCandidateFetcher, schemas *fakeSchemas) *LedgerPolicyResolver {
	t.Helper()
	if fetcher == nil {
		fetcher = &fakeEntryFetcher{}
	}
	if candidates == nil {
		candidates = &fakeCandidateFetcher{}
	}
	if schemas == nil {
		schemas = &fakeSchemas{}
	}
	return NewLedgerPolicyResolver(LedgerPolicyResolverConfig{
		Fetcher:    fetcher,
		Candidates: candidates,
		Schemas:    schemas,
		LogDID:     lprTestLogDID,
	})
}

// candidateEntry builds an entry-with-metadata fixture, opaque
// to the resolver — used only as a count signal in the candidate
// slice.
func candidateEntry(seq uint64) types.EntryWithMetadata {
	return types.EntryWithMetadata{
		CanonicalBytes: []byte{0x01, 0x02},
		LogTime:        time.Now().UTC(),
		Position:       types.LogPosition{LogDID: lprTestLogDID, Sequence: seq},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Programmer-error rejections
// ─────────────────────────────────────────────────────────────────────────────

func TestLedgerPolicyResolver_NilEntryRejects(t *testing.T) {
	t.Parallel()
	r := newResolverWith(t, nil, nil, nil)
	_, _, _, found, err := r.ResolvePolicy(context.Background(), nil)
	if found || err == nil {
		t.Errorf("nil entry: found=%v err=%v; want (false, error)", found, err)
	}
}

func TestLedgerPolicyResolver_NewPanicsOnMissingDeps(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  LedgerPolicyResolverConfig
	}{
		{"nil Fetcher", LedgerPolicyResolverConfig{Candidates: &fakeCandidateFetcher{}, Schemas: &fakeSchemas{}, LogDID: lprTestLogDID}},
		{"nil Candidates", LedgerPolicyResolverConfig{Fetcher: &fakeEntryFetcher{}, Schemas: &fakeSchemas{}, LogDID: lprTestLogDID}},
		{"nil Schemas", LedgerPolicyResolverConfig{Fetcher: &fakeEntryFetcher{}, Candidates: &fakeCandidateFetcher{}, LogDID: lprTestLogDID}},
		{"empty LogDID", LedgerPolicyResolverConfig{Fetcher: &fakeEntryFetcher{}, Candidates: &fakeCandidateFetcher{}, Schemas: &fakeSchemas{}}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s: NewLedgerPolicyResolver did not panic", tc.name)
				}
			}()
			_ = NewLedgerPolicyResolver(tc.cfg)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Conditions 1-2: entry self-declaration
// ─────────────────────────────────────────────────────────────────────────────

func TestLedgerPolicyResolver_NoSchemaRefNoop(t *testing.T) {
	t.Parallel()
	r := newResolverWith(t, nil, nil, nil)
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:   "did:web:any",
		Destination: lprTestLogDID,
	}}
	_, _, _, found, err := r.ResolvePolicy(context.Background(), entry)
	if found || err != nil {
		t.Errorf("missing SchemaRef should defer; got found=%v err=%v", found, err)
	}
}

func TestLedgerPolicyResolver_NoPolicyNameNoop(t *testing.T) {
	t.Parallel()
	r := newResolverWith(t, nil, nil, nil)
	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:   "did:web:any",
		Destination: lprTestLogDID,
		SchemaRef:   &schemaRef,
	}}
	_, _, _, found, err := r.ResolvePolicy(context.Background(), entry)
	if found || err != nil {
		t.Errorf("missing AttestationPolicyName should defer; got found=%v err=%v", found, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Condition 3: schema fetch + parameter extraction
// ─────────────────────────────────────────────────────────────────────────────

func TestLedgerPolicyResolver_SchemaFetchErrorPropagates(t *testing.T) {
	t.Parallel()
	transient := errors.New("transport: db unreachable")
	r := newResolverWith(t, &fakeEntryFetcher{err: transient}, nil, nil)

	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	policyName := "p"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:             "did:web:any",
		Destination:           lprTestLogDID,
		SchemaRef:             &schemaRef,
		AttestationPolicyName: &policyName,
	}}
	_, _, _, _, err := r.ResolvePolicy(context.Background(), entry)
	if !errors.Is(err, transient) {
		t.Errorf("schema fetch err not wrapped: got %v", err)
	}
}

func TestLedgerPolicyResolver_SchemaNotFoundNoop(t *testing.T) {
	t.Parallel()
	r := newResolverWith(t, &fakeEntryFetcher{}, nil, nil)
	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	policyName := "p"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:             "did:web:any",
		Destination:           lprTestLogDID,
		SchemaRef:             &schemaRef,
		AttestationPolicyName: &policyName,
	}}
	_, _, _, found, err := r.ResolvePolicy(context.Background(), entry)
	if found || err != nil {
		t.Errorf("schema not on log should defer; got found=%v err=%v", found, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Condition 4: policy not declared on the schema
// ─────────────────────────────────────────────────────────────────────────────

func TestLedgerPolicyResolver_PolicyNameNotInSchemaNoop(t *testing.T) {
	t.Parallel()

	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	fetcher := &fakeEntryFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
		schemaRef: schemaEntryAt(t, schemaRef, "court-schema-v1"),
	}}
	schemas := &fakeSchemas{params: &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{adminGatedPolicy("other-policy")},
	}}
	r := newResolverWith(t, fetcher, nil, schemas)

	policyName := "missing-policy"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:             "did:web:any",
		Destination:           lprTestLogDID,
		SchemaRef:             &schemaRef,
		AttestationPolicyName: &policyName,
	}}
	_, _, _, found, err := r.ResolvePolicy(context.Background(), entry)
	if found || err != nil {
		t.Errorf("missing policy name should defer; got found=%v err=%v", found, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Condition 5: AdmissionEnforced=false → defer (load-bearing for rollout)
// ─────────────────────────────────────────────────────────────────────────────

func TestLedgerPolicyResolver_ReadTimePolicyDefers(t *testing.T) {
	t.Parallel()

	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	targetRoot := types.LogPosition{LogDID: lprTestLogDID, Sequence: 9}
	fetcher := &fakeEntryFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
		schemaRef:  schemaEntryAt(t, schemaRef, "schema-v1"),
		targetRoot: primaryEntryAt(t, targetRoot),
	}}
	schemas := &fakeSchemas{params: &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{readTimePolicy("concurring-1")},
	}}
	candidates := &fakeCandidateFetcher{out: []types.EntryWithMetadata{candidateEntry(11)}}
	r := newResolverWith(t, fetcher, candidates, schemas)

	policyName := "concurring-1"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:             "did:web:any",
		Destination:           lprTestLogDID,
		SchemaRef:             &schemaRef,
		AttestationPolicyName: &policyName,
		TargetRoot:            &targetRoot,
	}}
	_, _, gotCandidates, found, err := r.ResolvePolicy(context.Background(), entry)
	if found {
		t.Error("AdmissionEnforced=false policy fired admission gate; rollout invariant violated")
	}
	if err != nil {
		t.Errorf("read-time policy errored: %v", err)
	}
	if len(gotCandidates) != 0 {
		t.Errorf("read-time policy returned candidates; resolver did extra work: %d", len(gotCandidates))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Condition 6: primary anchor (TargetRoot) shape
// ─────────────────────────────────────────────────────────────────────────────

func TestLedgerPolicyResolver_AdmissionEnforcedButNoTargetRootDefers(t *testing.T) {
	t.Parallel()
	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	fetcher := &fakeEntryFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
		schemaRef: schemaEntryAt(t, schemaRef, "schema-v1"),
	}}
	schemas := &fakeSchemas{params: &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{adminGatedPolicy("board-attest")},
	}}
	r := newResolverWith(t, fetcher, nil, schemas)

	policyName := "board-attest"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:             "did:web:any",
		Destination:           lprTestLogDID,
		SchemaRef:             &schemaRef,
		AttestationPolicyName: &policyName,
		// TargetRoot intentionally nil
	}}
	_, _, _, found, err := r.ResolvePolicy(context.Background(), entry)
	if found || err != nil {
		t.Errorf("admission-enforced + nil TargetRoot should defer; got found=%v err=%v", found, err)
	}
}

func TestLedgerPolicyResolver_AdmissionEnforcedForeignTargetRootDefers(t *testing.T) {
	t.Parallel()
	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	foreignTarget := types.LogPosition{LogDID: "did:web:other-log", Sequence: 1}
	fetcher := &fakeEntryFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
		schemaRef: schemaEntryAt(t, schemaRef, "schema-v1"),
	}}
	schemas := &fakeSchemas{params: &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{adminGatedPolicy("board-attest")},
	}}
	r := newResolverWith(t, fetcher, nil, schemas)

	policyName := "board-attest"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:             "did:web:any",
		Destination:           lprTestLogDID,
		SchemaRef:             &schemaRef,
		AttestationPolicyName: &policyName,
		TargetRoot:            &foreignTarget,
	}}
	_, _, _, found, err := r.ResolvePolicy(context.Background(), entry)
	if found || err != nil {
		t.Errorf("foreign-log TargetRoot should defer; got found=%v err=%v", found, err)
	}
}

func TestLedgerPolicyResolver_AdmissionEnforcedMissingTargetEntryErrors(t *testing.T) {
	t.Parallel()
	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	missingTarget := types.LogPosition{LogDID: lprTestLogDID, Sequence: 99999}
	fetcher := &fakeEntryFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
		schemaRef: schemaEntryAt(t, schemaRef, "schema-v1"),
	}}
	schemas := &fakeSchemas{params: &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{adminGatedPolicy("board-attest")},
	}}
	r := newResolverWith(t, fetcher, nil, schemas)

	policyName := "board-attest"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:             "did:web:any",
		Destination:           lprTestLogDID,
		SchemaRef:             &schemaRef,
		AttestationPolicyName: &policyName,
		TargetRoot:            &missingTarget,
	}}
	_, _, _, found, err := r.ResolvePolicy(context.Background(), entry)
	if found || err == nil {
		t.Errorf("missing TargetRoot should error; got found=%v err=%v", found, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy path: all six conditions hold
// ─────────────────────────────────────────────────────────────────────────────

func TestLedgerPolicyResolver_HappyPath(t *testing.T) {
	t.Parallel()
	schemaRef := types.LogPosition{LogDID: lprTestLogDID, Sequence: 5}
	targetRoot := types.LogPosition{LogDID: lprTestLogDID, Sequence: 9}

	expectedPrimary := primaryEntryAt(t, targetRoot)
	fetcher := &fakeEntryFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
		schemaRef:  schemaEntryAt(t, schemaRef, "schema-v1"),
		targetRoot: expectedPrimary,
	}}
	policy := adminGatedPolicy("board-attest")
	schemas := &fakeSchemas{params: &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{policy},
	}}
	expectedCandidates := []types.EntryWithMetadata{candidateEntry(11), candidateEntry(13)}
	candidates := &fakeCandidateFetcher{out: expectedCandidates}
	r := newResolverWith(t, fetcher, candidates, schemas)

	policyName := "board-attest"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:             "did:web:any",
		Destination:           lprTestLogDID,
		SchemaRef:             &schemaRef,
		AttestationPolicyName: &policyName,
		TargetRoot:            &targetRoot,
	}}
	gotPolicy, gotPrimary, gotCandidates, found, err := r.ResolvePolicy(context.Background(), entry)
	if err != nil {
		t.Fatalf("happy path: %v", err)
	}
	if !found {
		t.Fatal("happy path: found=false")
	}
	if gotPolicy.Name != "board-attest" {
		t.Errorf("policy.Name=%q, want board-attest", gotPolicy.Name)
	}
	if !gotPolicy.AdmissionEnforced {
		t.Errorf("policy.AdmissionEnforced=false on happy path; gate should not have fired")
	}
	if !gotPrimary.Position.Equal(targetRoot) {
		t.Errorf("primary.Position=%v, want %v", gotPrimary.Position, targetRoot)
	}
	if len(gotCandidates) != len(expectedCandidates) {
		t.Errorf("candidates len=%d, want %d", len(gotCandidates), len(expectedCandidates))
	}
}

// Compile-time assertion: LedgerPolicyResolver implements
// PolicyResolver. A drift in either side surfaces at build time.
var _ PolicyResolver = (*LedgerPolicyResolver)(nil)

// Compile-time assertion: types.AttestationPolicy carries
// AdmissionEnforced (the v1.5 field load-bearing for the
// resolver). Pinning here so a future SDK downgrade
// surfaces as a build failure in the ledger.
var _ = types.AttestationPolicy{AdmissionEnforced: true}

// Silence unused vars to keep imports compact across stub
// permutations as future arms are added.
var _ = attestation.Policy{}
