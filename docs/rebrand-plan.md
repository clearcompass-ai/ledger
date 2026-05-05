# Rebrand history

This document is historical. It captures the renames that landed, not
work to do. Two distinct renames happened, in two phases.

## Phase 1 — SDK + module-path rename (v1.0.0)

The SDK was rebranded from `ortholog-sdk` to `attesta`, and the
operator binary's module path was rebranded from `ortholog-operator`
to `ledger`. Both renames shipped together with attesta v1.0.0.

### SDK rename: `ortholog-sdk` → `attesta`

| Aspect | Before | After |
|---|---|---|
| Module path | `github.com/clearcompass-ai/ortholog-sdk` | `github.com/clearcompass-ai/attesta` |
| Tag | v0.9.6 | v1.0.0 |
| Wire format | (within v0.9.x) | hard fork — wire-incompatible with v0.9.x |

The rename touched every protocol-internal hash that mixed in the
literal string `"Ortholog"`. Updated frozen values are documented
in the SDK's CHANGELOG entry for v1.0.0:

- EIP-712 protocol salt, entry type hash, domain separator
- HGenerator seed (Pedersen second-generator derivation)
- SCT signing-payload domain prefix
- Escrow / PRE-grant split-ID DST strings
- DLEQ challenge DST

Unchanged (intentionally):
- Algorithm IDs (frozen on the wire): `SigAlgoECDSA = 0x0001`, etc.
- Gossip Kind strings (`OL-GOSSIP-*` is a protocol identifier, not branding).
- Multicodec prefixes.

### Module-path rename: `ortholog-operator` → `ledger`

| Aspect | Before | After |
|---|---|---|
| Module path | `github.com/clearcompass-ai/ortholog-operator` | `github.com/clearcompass-ai/ledger` |
| SDK pin | `ortholog-sdk v0.9.6` | `attesta v1.0.0` |
| Test env vars | `ORTHOLOG_TEST_*` | `ATTESTA_TEST_*` |

In phase 1 the binary identifier (`OPERATOR_*` env vars,
`cmd/operator/`, log messages saying "operator") was deliberately
left in place to keep the wire-format scope bounded.

## Phase 2 — binary identifier rename (this commit)

The deferred binary-side terminology is now flipped. Every place
that called the binary an "operator" now calls it a "ledger". This
is identifier-level only — wire format is unchanged from phase 1.

| Aspect | Before | After |
|---|---|---|
| Binary directory | `cmd/operator/` | `cmd/ledger/` |
| Read-only sibling | `cmd/operator-reader/` | `cmd/ledger-reader/` |
| Env vars | `OPERATOR_*` (33 vars) | `LEDGER_*` |
| Go config fields | `OperatorDID`, `OperatorSignerKeyFile`, `OperatorSignerPriv`, `OperatorURL`, `OperatorEndpoint` (operator-local) | `LedgerDID`, `LedgerSignerKeyFile`, `LedgerSignerPriv`, `LedgerURL`, `LedgerEndpoint` |
| YAML / log keys | `operator_did`, `operator_endpoint` | `ledger_did`, `ledger_endpoint` |
| Comments + log messages | "operator" / "Operators" | "ledger" / "Ledgers" |
| Test names | `TestCrossOperator_*`, `TestEquivocationBinding_OperatorMatchesSDK` | `TestCrossLedger_*`, `TestEquivocationBinding_LedgerMatchesSDK` |
| Test fixture file | `gossipnet/cross_operator_test.go` | `gossipnet/cross_ledger_test.go` |
| Service name (OTel) | `"operator"` (was already `"ledger"` in phase 1) | unchanged |

What still uses "Operator" (intentionally — SDK-owned API surface):

- `attesta/log.OperatorQueryAPI` — SDK interface; the ledger
  implements it via `store/indexes.PostgresQueryAPI`.
- `attesta/gossip/findings.VerifiedCosignedTreeHeadFinding.OperatorEndpoint()`
  — SDK accessor; the ledger calls it but does not own it. The
  field on the wire (the `OperatorEndpoint` field of the SDK's
  `CosignedTreeHeadFinding`) is part of the canonical bytes and
  has not been renamed.
- `attesta/log.SubmitterConfig.OperatorDID` — SDK config field
  (the ledger does not currently construct this, but other
  consumers do).

Wire-format unchanged in phase 2:
- HTTP route paths (`/v1/entries`, `/v1/tree/head`, etc.).
- Response shapes (`signer_did`, `log_did`, `canonical_hash`).
- Postgres table names + column names.
- BadgerDB keyspace prefixes.
- Gossip event canonical bytes (the SDK-owned `OperatorEndpoint`
  field stays on the wire).

State from a phase-1 deployment (using `OPERATOR_*` env vars and
`cmd/operator`) reads byte-identical on disk to a phase-2
deployment (using `LEDGER_*` env vars and `cmd/ledger`). The
deployment-plan change is just env-var renaming and the binary
path; no data migration.

## Wire-incompatibility note (phase 1)

A v1.0.0 `attesta` deployment is wire-incompatible with any
v0.9.x `ortholog-sdk` deployment. Drain v0.9.x before bringing
up v1.0.0; do not run mixed populations. Old signed events,
SCTs, and commitment artifacts cannot be re-verified by v1.0.0
code — the underlying domain hashes changed.

This was a deliberate hard fork, not a back-compatible release.

## What's still pending

| Item | Owner | Notes |
|---|---|---|
| Migrate sibling consumers (`artifact-store`, `judicial-network`, `tessera`) | Each repo's owner | Each repo has its own go.mod with the SDK pin; same drop-replace + `go get attesta@v1.0.0` cycle, plus the API breakage from the v0.8.x → v1.0.0 surface (NetworkID plumbing, BLSAggregateVerifier, WitnessKeySet). |
| Deployment plan: drain v0.9.x | Operations | Wire-incompatibility from phase 1 means old deployments produce signatures the new code refuses. Coordinate the cutover in deployment runbooks. |
| Deployment plan: env-var rename | Operations | Phase-2 cutover requires updating Helm / Terraform / SOPS to set `LEDGER_*` instead of `OPERATOR_*`. |

Once these land, this document and any remaining rebrand-history
references in code comments can be deleted.
