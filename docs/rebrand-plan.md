# Rebrand plan: attesta → attesta · operator → ledger

**Status:** plan only — no code change in this document. Execution is
deferred until the SDK rename to `attesta` ships and the new operator
repo `ledger` is bootstrapped.

Two parallel renames:

| From | To | Concept shift |
|---|---|---|
| `github.com/clearcompass-ai/attesta` | `github.com/clearcompass-ai/attesta` | SDK rebrand |
| `github.com/clearcompass-ai/ledger` | `github.com/clearcompass-ai/ledger` | The operator becomes a "ledger" — a simpler, more accurate name. The "operator" framing is retired |

The rebrand reframes the project: this binary is no longer "an
operator" with implied policy ownership; it is a **ledger** — a
content-addressed, append-only, cryptographically-verifiable record.
Witnesses + auditors observe the ledger; clients submit to it.
The ledger does not orchestrate; it records.

## Sequencing

The rename happens in five phases. **Each phase produces a green
build before the next starts** — never two breaking renames in flight
at once.

### Phase A — SDK rebrand lands first (separate repo)

Owned by the SDK team. Constraints we can rely on after Phase A
completes:

- New module path: `github.com/clearcompass-ai/attesta`.
- Tagged release. Old `attesta` repo accepts no further commits
  but stays readable for at least 90 days.
- Public API is byte-compatible: only the import path changes. No
  type renames, no breaking signature changes. (Renaming the
  protocol internals — `gossip.Kind` strings, signing-purpose
  values, on-disk fixtures — is OUT of scope for the rename phase
  and would belong to a separate semver-major release.)

If the SDK team needs to rename internal symbols, that is a separate
release and the operator MUST NOT begin Phase B until that release
also lands on a tagged version.

### Phase B — Operator: import-path migration only

In the existing `ledger` repo, on a feature branch:

```
1. go mod edit -dropreplace github.com/clearcompass-ai/attesta
2. go mod edit -droprequire github.com/clearcompass-ai/attesta
3. go get github.com/clearcompass-ai/attesta@vX.Y.Z
4. find . -name '*.go' | xargs sed -i \
       's|github.com/clearcompass-ai/attesta|github.com/clearcompass-ai/attesta|g'
5. go mod tidy
6. go vet ./...
7. go test -count=1 -race -short ./...
```

Verify zero residual references:

```
$ go list -deps ./... | grep attesta | wc -l
0

$ grep -rn 'attesta' --include='*.go' --include='*.mod' --include='*.sum'
(no matches)
```

**Do NOT rename the operator repo or module path in this phase.** The
operator repo still lives at `ledger` and still has module
path `github.com/clearcompass-ai/ledger`. Only the SDK
import changes. This keeps consumer-side breakage to one phase.

Commit message convention: `deps: migrate from attesta → attesta`.

### Phase C — Operator → ledger module rename

After Phase B is green and merged, on a separate feature branch:

```
1. Create new repo github.com/clearcompass-ai/ledger.
2. git push --mirror so history follows.
3. In the new repo:
     a. go mod edit -module github.com/clearcompass-ai/ledger
     b. find . -name '*.go' | xargs sed -i \
            's|github.com/clearcompass-ai/ledger|github.com/clearcompass-ai/ledger|g'
     c. go mod tidy
     d. go vet ./...
     e. go test -count=1 -race -short ./...
4. Verify zero residual references:
     $ grep -rn 'ledger' --include='*.go' --include='*.mod' --include='*.sum' --include='*.md' --include='*.yml' --include='*.yaml'
     (no matches)
5. Tag the first ledger release.
6. Archive the old ledger repo (read-only); link the README
   to the new repo.
```

### Phase D — Conceptual rename: "operator" → "ledger"

This phase is a documentation + identifier sweep. Behavioral code does
NOT change. Mechanical replacements:

| Token | Replacement | Files affected |
|---|---|---|
| `cmd/operator/` | `cmd/ledger/` | The main binary directory rename (one git mv) |
| `cmd/operator-reader/` | `cmd/ledger-reader/` | Same |
| `OPERATOR_*` env vars | `LEDGER_*` env vars | Every env-var reference in `cmd/ledger/main.go::loadConfig` plus all test fixtures, docs, and run scripts |
| Identifiers: `Operator`, `OperatorDID`, `OperatorSignerKeyFile`, etc. | `Ledger`, `LedgerDID`, `LedgerSignerKeyFile`, ... | Throughout the codebase |
| Documentation: "the operator" | "the ledger" | All `docs/*.md` |

**Backwards-compatible path for env vars:** during a deprecation
window (one release), the binary reads BOTH `LEDGER_*` and `OPERATOR_*`,
preferring the new name and logging a deprecation warning when the
old one is set. After the window closes, drop the old names.

```go
// In Phase D, transitional helper:
func envOrLegacy(canonical, legacy, fallback string) string {
    if v := os.Getenv(canonical); v != "" { return v }
    if v := os.Getenv(legacy); v != "" {
        slog.Default().Warn("env var deprecated; rename",
            "from", legacy, "to", canonical)
        return v
    }
    return fallback
}
```

This keeps existing deployments running while operators migrate.

### Phase E — On-disk + on-wire rename (optional, breaking)

This phase is the only one that touches user-visible state. **Skip it
if the cost > value.**

Items that are user-visible:

- HTTP route paths: `/v1/entries`, `/v1/tree/head`, etc. These are
  domain-neutral nouns; no rename needed.
- Response shapes: `signer_did`, `log_did`, `canonical_hash`. These
  are wire-format identifiers; renaming breaks every consumer. **Do
  not rename.**
- Postgres table names: `entry_index`, `commitment_split_id`, etc.
  Domain-neutral; no rename needed.
- BadgerDB key prefixes (`0x07 0x01..0x0D`): byte values, no rename.
- Service version strings (`OPERATOR_SERVICE_VERSION` → `LEDGER_SERVICE_VERSION`):
  configuration only; rename in Phase D.
- Metric prefix (`attesta_api_errors_total`): rename to
  `attesta_ledger_errors_total` IF AND ONLY IF the broader observability
  pipeline (dashboards, alerts) is moving in lockstep. Otherwise
  leave as-is and rename in a future major release.

## What stays the same (intentionally)

The protocol itself is unchanged. The rebrand is purely about what
people call it, not what it does:

- Wire formats: identical bytes on disk and in transit.
- Cryptographic primitives: same SHA-256 binding hash, same V7.75
  commitment shapes, same SCT signing payload, same RFC-6962 dense
  log root.
- HTTP API: identical routes, identical request/response shapes.
- BadgerDB keyspace layout (`0x07 0x01..0x0D`): byte-compatible.
- Postgres schema: byte-compatible.
- SDK contract (after the SDK's own tagged rebrand release).

In other words: a `ledger` running attesta-vX.Y.Z observes the same
Merkle tree, accepts the same entries, emits the same SCTs as an
`ledger` running attesta-v0.9.6 against the same
inputs. **The rename is a relabeling; it is not a fork.**

## Risk register

| Risk | Mitigation |
|---|---|
| SDK rename breaks downstream simultaneously | The SDK team owns Phase A; the SDK ships first AND tags. Operator-side migration only begins after SDK pin compiles in a clean module. |
| Two repos diverging during the migration window | Single feature branch per phase. No phase opens until the previous phase merges + tags. |
| Production deployments lose env-var bindings on upgrade | Phase D ships dual-name acceptance with a logged deprecation warning. Drop old names only after a confirmed deployment-wide migration. |
| Metric prefix breaks dashboards | Phase E excludes metric rename unless dashboards rename in lockstep. The metric is `attesta_api_errors_total` until then. |
| Documentation drift between rebrand phases | Each phase commit MUST update `docs/` in lockstep with code. CI gate: `grep -rn 'attesta\|ledger' README.md docs/` returns 0 after each phase. |
| Old import path lingers in tests / generated code | `go list -deps ./...` is the canonical check. Run after each phase. |

## Rollback

Phase B and C are pure rename refactors — `git revert` is sufficient
if anything goes wrong. Phase D is a conceptual sweep with the
transitional dual-acceptance helper, so production deployments can
roll back to old env-var names without redeploying. Phase E is the
only phase that's hard to roll back because metric / wire renames
ripple to consumers; treat it as a major-version bump.

## Acceptance criteria per phase

| Phase | Done when |
|---|---|
| A | SDK at `attesta` is tagged + reachable via `go get`. Public surface is byte-compatible with the prior `attesta` tag |
| B | `go list -deps ./... \| grep attesta` returns 0; full test suite green; no `attesta` strings in `go.mod` / `go.sum` / `*.go` |
| C | New `ledger` repo has a tagged release; `grep -rn 'ledger' .` returns 0 across `*.go`, `*.mod`, `*.sum`, `*.md`, `*.yml`; old repo is archived |
| D | `cmd/ledger/` builds + runs; both `LEDGER_*` and `OPERATOR_*` env vars are accepted with a deprecation log; `docs/` references "ledger" not "operator" |
| E | (optional) Metric / wire renames complete; consumer dashboards updated in lockstep |

## Forecast scope

| Phase | Files touched (estimate) | LOC delta |
|---|---|---|
| A | (out of scope — SDK team) | — |
| B | ~80 (every `*.go` with an SDK import) | ~+0/-0 (path swap) |
| C | ~250 (every `*.go` + `go.mod` + docs) | ~+0/-0 (path swap) |
| D | ~30 (cmd/, env-var sites, docs) | ~+200/-200 |
| E | (decision-deferred) | — |

Total phases B + C + D: ~360 files modified, primarily mechanical
search-and-replace. Pure-mechanical changes are easier to review than
their LOC count suggests; the value of staging is correctness, not
volume control.
