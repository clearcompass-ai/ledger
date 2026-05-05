# Rebrand history

The repository was rebranded from `ortholog-sdk` + `ortholog-operator`
to `attesta` + `ledger`. This document is now historical — it
captures what shipped, not work to do.

## What shipped

### SDK rename: `ortholog-sdk` → `attesta`

| Aspect | Before | After |
|---|---|---|
| Module path | `github.com/clearcompass-ai/ortholog-sdk` | `github.com/clearcompass-ai/attesta` |
| Tag | v0.9.6 | v1.0.0 |
| Wire format | wire-incompatible with v1.0.0 | hard fork from v0.9.x |

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

### Operator rename: `ortholog-operator` → `ledger`

| Aspect | Before | After |
|---|---|---|
| Module path | `github.com/clearcompass-ai/ortholog-operator` | `github.com/clearcompass-ai/ledger` |
| SDK pin | `ortholog-sdk v0.9.6` | `attesta v1.0.0` |
| Env vars (test-only) | `ORTHOLOG_TEST_*` | `ATTESTA_TEST_*` |

The HTTP API, Postgres schema, BadgerDB keyspace (`0x07 0x01..0x0D`),
and on-disk file layouts are byte-compatible. The rename is at the
identifier level only — operator state from a `ortholog-operator`
deployment is readable by a `ledger` deployment.

What did NOT rename:

- `OPERATOR_*` env vars: still present. The "operator" framing is
  the binary's role name, not branding. A future major release may
  reframe this as "ledger" but the identifier-level rename is
  deliberately deferred to keep the v1.0.0 scope bounded.
- HTTP route paths (`/v1/entries`, `/v1/tree/head`, etc.): wire
  contracts; unchanged.
- Response shapes (`signer_did`, `log_did`, `canonical_hash`): wire
  contracts; unchanged.
- Postgres table names: byte-compatible.
- BadgerDB keyspace prefixes: byte-compatible.

## Wire-incompatibility note

A v1.0.0 `attesta` deployment is wire-incompatible with any v0.9.x
`ortholog-sdk` deployment. Drain v0.9.x before bringing up v1.0.0;
do not run mixed populations. Old signed events, SCTs, and
commitment artifacts cannot be re-verified by v1.0.0 code — the
underlying domain hashes changed.

This was a deliberate hard fork, not a back-compatible release.

## What's still pending

A small set of follow-ups remain when the broader release is
coordinated:

| Item | Owner | Notes |
|---|---|---|
| Tag `attesta@v1.0.0` | SDK release engineer | After all 17 wire-format-lock goldens were regenerated and tests run green; tag pushed to `clearcompass-ai/ortholog-sdk` (legacy URL; will move to `clearcompass-ai/attesta` when that repo is created). |
| Drop the `replace` directive in operator `go.mod` | Operator owner | Currently pinned via `replace github.com/clearcompass-ai/attesta => /home/user/ortholog-sdk`. After the SDK tag publishes, run `go mod edit -dropreplace` + `go get github.com/clearcompass-ai/attesta@v1.0.0` + `go mod tidy`. |
| Migrate sibling consumers (`artifact-store`, `judicial-network`, `tessera`) | Each repo's owner | Same pin migration. Each repo has its own go.mod with the SDK pin. |
| Deployment plan: drain v0.9.x | Operations | Wire-incompatibility means old deployments produce signatures the new code refuses. Coordinate the cutover in deployment runbooks. |

Once these land, this document and the rebrand-history references
in code comments can be deleted.
