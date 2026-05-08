/*
FILE PATH:

	api/body_caps.go

DESCRIPTION:

	Per-route HTTP body-size caps. Every route that reads a body
	has a documented, finite ceiling so an over-streaming peer
	is rejected with HTTP 413 by middleware.SizeLimit BEFORE the
	handler allocates memory. Routes that take no body (every
	GET) need no cap.

KEY ARCHITECTURAL DECISIONS:
  - Caps live in one file so the audit surface is finite. A
    reviewer sees every per-route ceiling at one glance.
  - Each cap is a typed int64 constant. Values are administrator-
    auditable and compile-time-constant — no runtime drift.
  - Caps include a small framing budget on top of the
    payload-shape ceiling because middleware.SizeLimit wraps
    r.Body in http.MaxBytesReader which fires AT-OR-BEFORE the
    cap; the handler still has to parse JSON / unmarshal a
    length-prefixed envelope, which can carry small amounts of
    structural overhead.
  - Defense-in-depth: handlers MAY enforce tighter caps after
    parse (e.g., AbsoluteMaxBatchPayloadBytes is the transport
    cap; the batch handler enforces the per-deployment
    MaxBatchSize × MaxEntrySize derived ceiling on top).

OVERVIEW:

	middleware.SizeLimit wraps r.Body for every route registered
	by api/server.go::NewServer. The ceiling chosen here is the
	transport-level absolute upper bound. Over-cap requests are
	rejected with HTTP 413 by net/http's MaxBytesReader on first
	Read, before the handler allocates any state.

KEY DEPENDENCIES:
  - api/middleware.SizeLimit: applies http.MaxBytesReader.
  - api/server.go: registers routes wrapped by SizeLimit.
*/
package api

// -------------------------------------------------------------------------------------------------
// 1) Witness cosign
// -------------------------------------------------------------------------------------------------

// MaxCosignRequestBytes caps POST /v1/cosign request bodies. The
// SDK's cosign.WitnessHandler internally bounds requests at
// cosign.DefaultMaxRequestBytes (~64 KiB); this is defense-in-
// depth at the transport so the request is rejected before the
// SDK even starts JSON-parsing.
const MaxCosignRequestBytes int64 = 128 << 10 // 128 KiB

// -------------------------------------------------------------------------------------------------
// 2) Gossip
// -------------------------------------------------------------------------------------------------

// MaxGossipPostBytes caps POST /v1/gossip request bodies. A
// signed event carries the canonical body bytes plus a signature
// envelope. The protocol-level cap is MaxCanonicalBytes (65,535)
// per body plus framing for the signature; we round up to the
// next power of two for clean math.
const MaxGossipPostBytes int64 = 128 << 10 // 128 KiB

// -------------------------------------------------------------------------------------------------
// 3) Escrow override
// -------------------------------------------------------------------------------------------------

// MaxEscrowOverrideBytes caps POST /v1/escrow-override request
// bodies. The handler accepts a tiny JSON
// {escrow_id, decision_hash, effective} shape; 64 KiB is two
// orders of magnitude beyond the legitimate payload.
const MaxEscrowOverrideBytes int64 = 64 << 10 // 64 KiB

// -------------------------------------------------------------------------------------------------
// 4) SMT batch endpoints
// -------------------------------------------------------------------------------------------------

// MaxSMTBatchPayloadBytes caps POST /v1/smt/batch_proof request
// bodies. Up to 1000 32-byte keys + JSON framing; 256 KiB is
// generous (raw 32 KB of keys + JSON literal overhead).
const MaxSMTBatchPayloadBytes int64 = 256 << 10 // 256 KiB

// MaxSMTLeavesPayloadBytes caps POST /v1/smt/leaves request
// bodies. Up to 100 keys + JSON framing.
const MaxSMTLeavesPayloadBytes int64 = 64 << 10 // 64 KiB
