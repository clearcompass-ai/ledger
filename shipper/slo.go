/*
FILE PATH: shipper/slo.go

Service Level Objectives the shipper must satisfy. These are the
contract between the shipper and the rest of the ledger; every
SLO here is locked in by a regression test in this package and
documented for ops dashboards.

Why named constants (not test-local literals):

  - SLOs are part of the shipper's public contract. The number
    is referenced by the test (shipper/throughput_slo_test.go),
    by dashboards (ops integrators expose it as a target line),
    and by future tuning work. Co-locating it with the shipper
    code makes the constraint discoverable from one place.

  - Changes to the SLO must be deliberate. A literal in a test
    file is easy to drift; a const in the package surfaces in
    review when the threshold is loosened.
*/
package shipper

// SLOThroughputEntriesPerSec is the minimum sustained ship-complete
// throughput the shipper must achieve, in entries per second,
// measured at a fast (1ms-per-write) bytestore.
//
// This SLO targets the shipper's INTERNAL serialization (scan loop,
// work channel, HWM advancer, in-flight dedupe), not the bytestore
// backend. A real S3/GCS bytestore adds tens of milliseconds of
// per-PUT latency that the shipper has no control over; the SLO
// here asks: "given a bytestore that is NOT the bottleneck, what
// throughput does the shipper itself sustain?" If this SLO degrades,
// production throughput on real S3 degrades by at least as much.
//
// 500 ent/sec rationale:
//
//   - S3 single-prefix limit is ~3,500 PUTs/sec. 500 ent/sec is
//     ~14% of that ceiling — modest enough that occasional bursts
//     do not approach the limit, large enough that 10M entries
//     drain in ~5h (acceptable backlog-recovery time for the
//     50-exchange / 500-client production target).
//
//   - A real 50ms-per-PUT S3 backend running at 500 ent/sec needs
//     25 concurrent uploads (Little's law: throughput × latency).
//     The shipper's MaxInFlight knob has to support that
//     concurrency for this SLO to translate from the fast-
//     bytestore test environment to production.
const SLOThroughputEntriesPerSec = 500
