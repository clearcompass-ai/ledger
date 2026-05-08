# admission

The ledger's admission package houses the trust-boundary
enforcement stages that fire on every inbound entry before it
reaches Tessera or Postgres. Each file in this package is one
stage; each stage is fail-closed and returns a sentinel error the
API layer maps to a typed `error_class` (full taxonomy in
[../docs/observability.md](../docs/observability.md)).

The full admission flow — including how this package's stages
slot in around envelope deserialization and signature verification
— is documented in
[../docs/architecture.md](../docs/architecture.md) `## Admission flow`.

## Pipeline ordering

1. Deserialize (lives in `core/envelope`, not here)
2. **NFC check** — `nfc_check.go` (this package)
3. **Signature verify** — `entry_signature_verifier.go` (this package)
4. Schema dispatch — `api/submission.go` calls into `schema/`
5. **Witness quorum verify** — `bls_quorum_verifier.go` (this
   package; wired in `cmd/ledger/main.go`). Fires only on entries
   whose payload schema is recognized by `EntryEmbedsTreeHead`
   (`bls_quorum_verifier.go:238`) — a closed-set predicate that
   currently returns `false` for every schema, so this stage is
   structurally a no-op until ledger-owned schemas opt in.
6. Index population — `store/`
7. Tessera enqueue — `tessera/` adapter

## Domain-agnostic boundary

The admission package never inspects `DomainPayload` for semantic
interpretation. It validates protocol-level invariants only —
structural envelope correctness, NFC discipline on identifiers,
signature cryptographic validity, witness quorum on embedded
checkpoints. Anything domain-specific (delegation depth,
sealing-order activation delay, role hierarchy) belongs to domain
networks, not here.

## No normalization, only assertion

The NFC check rejects non-NFC input rather than normalizing it.
The SDK's caller-normalizes contract places normalization at the
caller boundary; downstream consumers compute SplitIDs against
the NFC-normalized DIDs the caller supplied. If the ledger
silently normalized on ingress, the canonical hash the caller
signed and the bytes the ledger stored would diverge — a
soundness break dressed up as a usability feature.

## SDK alignment

This package holds `*cosign.WitnessKeySet` directly — the SDK's
encapsulated topology object (keys + NetworkID + K-of-N quorum +
BLS verifier). Cross-package contract pinning lives in
`admission/v011_contract_test.go`. The full per-package SDK
import set + interface anchors are listed in
[../docs/sdk-validation.md](../docs/sdk-validation.md).
