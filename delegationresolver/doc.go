/*
Package delegationresolver layers an LRU cache and a rotation-aware
invalidation hook over the SDK's delegation.EntrySource interface
so admission gates 3 (PR-E) and 4 (PR-F) can call
attestation.VerifyEntryAttestationPolicy / verifier.VerifyEvidenceChain
without going to disk on every request.

# Why a separate package

Per the SDK uniform-verify rollout sequence laid out in issue #75 +
#76: PR-B is the substrate every later gate depends on. Living
under its own package keeps the cache + invalidation policy out
of admission/, which stays SDK-driven and free of caching state
(Ledger Principle #1, "the dumb ledger").

# Three load-bearing pieces

  - cache.go        — Cached wraps any delegation.EntrySource. The
                      wrapper IS-A delegation.EntrySource, so callers
                      pass it to delegation.NewResolver unchanged.
  - invalidation.go — Invalidate(delegateDID) clears one row.
                      WireRotationListener subscribes a Cache to a
                      stream of (originator-DID) rotation events
                      from gossipnet.RotateOriginator.
  - metrics.go      — Hits + misses + invalidations counters wired
                      through the same Install* idiom as
                      api/instruments.go. A cache_hit_ratio gauge is
                      derivable in the dashboard from hits / (hits +
                      misses).

# What this package DOES NOT do

  - It does NOT implement the ledger-backed EntrySource (the bridge
    that maps a DelegateDID to the on-log delegation entry). That
    adapter is concrete to the consumer site (PR-E for policy
    enforcement) and lands when the consumer needs it. Tests here
    use the SDK's delegation.InMemorySource as the underlying
    source — the cache's behaviour is independent of the source's
    backing.
  - It does NOT key on (delegate_did, log_position). Position-aware
    caching is the concern of the verifier.VerifyKeyAtPosition
    consumer (PR-F evidence-chain walks); that cache lives next to
    that consumer when it lands.
*/
package delegationresolver
