# admission

The ledger's admission package houses the trust-boundary enforcement
stages that fire on every inbound entry before it reaches Tessera or
Postgres. Each file in this package is one stage; each stage is
fail-closed and returns a sentinel error the API layer maps to a
specific HTTP status.

## Pipeline ordering

1. Deserialize (lives in `core/envelope`, not here)
2. **NFC check** — `nfc_check.go` (this package)
3. **Signature verify** — `entry_signature_verifier.go` (this package)
4. Schema dispatch — `api/submission.go` calls into `schema/`
5. Witness quorum verify — `bls_quorum_verifier.go` (wired in
   `cmd/ledger/main.go`; fires only on entries whose schema is
   recognized as embedding a cosigned tree head — closed-set
   predicate, currently empty)
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

The NFC check rejects non-NFC input rather than normalizing it. The
SDK's caller-normalizes contract places normalization at the caller
boundary; downstream consumers compute SplitIDs against the NFC-
normalized DIDs the caller supplied. If the ledger silently
normalized on ingress, the canonical hash the caller signed and the
bytes the ledger stored would diverge — a soundness break dressed
up as a usability feature.
