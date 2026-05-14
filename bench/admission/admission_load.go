/*
FILE PATH:

	bench/admission/admission_load.go

DESCRIPTION:

	Representative admission-path load generator and percentile-
	capture harness. Issued under PR-A (issue #76) as the SLA
	baseline that every subsequent gate (PR-C through PR-F) MUST
	be benchmarked against to prove it didn't regress.

WHY A SEPARATE PACKAGE:

	The harness has its own dependencies (a real ECDSA keystore, a
	real DIDResolver stub returning the matching pubkey, a hot loop
	with timing capture). Living under bench/admission/ keeps it
	out of the production build graph — the admission/ package
	imports nothing from here, and `go build ./...` doesn't drag
	the harness into the binary.

WHAT IT MEASURES:

	The wall-clock latency of admission.VerifyEntrySignature on a
	pre-built mix of realistic entries. That call is the hot
	replaceable part of the admission pipeline; gates 1-4 either
	replace it (gate 1) or layer on top (gates 2-4). A regression
	on the baseline numbers here is a regression on the user-visible
	admission SLA.

PERCENTILE METHODOLOGY:

	Per-iteration wall-clock timings collected into a slice, sorted
	once at the end, indexed for p50/p95/p99/p999. Sorting once
	(not per-iteration) keeps the measurement loop tight; the sort
	cost lands AFTER the timed region. ResetTimer is called between
	the entry-mix prebuild and the verification loop so the bench
	report excludes setup.

ENTRY MIX:

	The "representative" mix is three sizes that bracket production
	traffic:
	  - small  (256 byte payload)  — typical commitment
	  - medium (4 KB payload)      — schema-bearing entry
	  - large  (16 KB payload)     — large-evidence entry
	Each size weighted equally. Signatures are real secp256k1 ECDSA
	produced by the SDK's signatures.SignEntry. SignerDIDs are
	"did:web:bench.ledger/N" with N rotating through the mix so
	the resolver stub returns a different pubkey per entry — the
	measurement isn't dominated by one cached pubkey.

BASELINE COMPARISON:

	CompareToBaseline reads bench/admission/baseline.json (committed
	output of an earlier bench run) and reports % change for each
	percentile. Used by PR-C/D/E/F to demonstrate non-regression
	without re-running the baseline by hand.
*/
package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"

	ledgeradmission "github.com/clearcompass-ai/ledger/admission"
)

// ─────────────────────────────────────────────────────────────────────────────
// Entry mix
// ─────────────────────────────────────────────────────────────────────────────

// SizeBucket is one of the three representative entry sizes.
type SizeBucket struct {
	Name        string // "small" / "medium" / "large"
	PayloadSize int    // bytes
}

// DefaultMix is the baseline mix every bench in this package uses.
// Equal weight across small/medium/large. Changing this changes the
// SLA — versioned via the BaselineMixVersion constant so any drift
// is visible in baseline.json.
var DefaultMix = []SizeBucket{
	{Name: "small", PayloadSize: 256},
	{Name: "medium", PayloadSize: 4 * 1024},
	{Name: "large", PayloadSize: 16 * 1024},
}

// BaselineMixVersion bumps when DefaultMix changes shape (add/remove
// bucket, change size). Embedded in baseline.json so cross-version
// comparisons surface as an explicit mismatch instead of silent
// apples-to-oranges drift.
const BaselineMixVersion = 1

// SignedEntry pairs a ready-to-verify entry with the artifacts the
// verifier needs at call time: the signature bytes and the public
// key the resolver MUST return. Production wires a real
// did.VerifierRegistry; the harness wires a closed-loop stub that
// always answers correctly so the measurement reflects the verifier's
// hot-path cost, not the resolver's.
type SignedEntry struct {
	Entry     *envelope.Entry
	Signature []byte
	PublicKey *ecdsa.PublicKey
	SignerDID string
}

// BuildMix constructs n signed entries cycling through DefaultMix.
// Distinct ECDSA keys per entry so the resolver stub can't cache
// across iterations. n must be > 0.
func BuildMix(n int) ([]SignedEntry, error) {
	if n <= 0 {
		return nil, errors.New("BuildMix: n must be > 0")
	}
	out := make([]SignedEntry, 0, n)
	for i := 0; i < n; i++ {
		bucket := DefaultMix[i%len(DefaultMix)]
		signed, err := buildSignedEntry(i, bucket)
		if err != nil {
			return nil, fmt.Errorf("BuildMix[%d]: %w", i, err)
		}
		out = append(out, signed)
	}
	return out, nil
}

func buildSignedEntry(index int, bucket SizeBucket) (SignedEntry, error) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		return SignedEntry{}, fmt.Errorf("GenerateKey: %w", err)
	}
	signerDID := fmt.Sprintf("did:web:bench.ledger/%d", index)
	payload := make([]byte, bucket.PayloadSize)
	for i := range payload {
		// Non-zero, non-uniform payload so any size-dependent
		// hashing cost is reflected in the measurement.
		payload[i] = byte(0x40 | (i & 0x3F))
	}
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   signerDID,
			Destination: "did:web:bench.log",
		},
		DomainPayload: payload,
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		return SignedEntry{}, fmt.Errorf("SignEntry: %w", err)
	}
	return SignedEntry{
		Entry:     entry,
		Signature: sig,
		PublicKey: &priv.PublicKey,
		SignerDID: signerDID,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolver stub
// ─────────────────────────────────────────────────────────────────────────────

// MapResolver answers ResolvePublicKey from an in-memory DID→pubkey
// map. Concurrency-safe — bench iterations may share one resolver
// when running with -cpu>1.
type MapResolver struct {
	mu  sync.RWMutex
	pub map[string]*ecdsa.PublicKey
}

// NewMapResolver constructs a MapResolver pre-populated with the
// SignerDID→PublicKey of every entry in mix.
func NewMapResolver(mix []SignedEntry) *MapResolver {
	r := &MapResolver{pub: make(map[string]*ecdsa.PublicKey, len(mix))}
	for _, e := range mix {
		r.pub[e.SignerDID] = e.PublicKey
	}
	return r
}

// ResolvePublicKey implements admission.DIDResolver.
func (r *MapResolver) ResolvePublicKey(_ context.Context, did string) (*ecdsa.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pub, ok := r.pub[did]
	if !ok {
		return nil, fmt.Errorf("MapResolver: unknown DID %q", did)
	}
	return pub, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Percentile-capturing measurement loop
// ─────────────────────────────────────────────────────────────────────────────

// LatencyReport is the captured shape of one harness run.
type LatencyReport struct {
	MixVersion  int            `json:"mix_version"`
	Iterations  int            `json:"iterations"`
	TotalNs     int64          `json:"total_ns"`
	MeanNs      int64          `json:"mean_ns"`
	P50Ns       int64          `json:"p50_ns"`
	P95Ns       int64          `json:"p95_ns"`
	P99Ns       int64          `json:"p99_ns"`
	P999Ns      int64          `json:"p999_ns"`
	MaxNs       int64          `json:"max_ns"`
	PerBucket   map[string]int `json:"per_bucket_count"`
	CapturedAt  time.Time      `json:"captured_at"`
	Description string         `json:"description"`
}

// MeasureVerify runs ledgeradmission.VerifyEntrySignature against
// every entry in mix `iterations` times, capturing per-call wall
// time, and returns the percentile report. Returns an error on
// the first verification failure — the SLA is meaningless if the
// hot path is rejecting.
//
// iterations must be >= len(mix) so each entry runs at least once.
func MeasureVerify(ctx context.Context, mix []SignedEntry, iterations int) (LatencyReport, error) {
	if iterations < len(mix) {
		return LatencyReport{}, fmt.Errorf(
			"MeasureVerify: iterations (%d) must be >= len(mix) (%d)",
			iterations, len(mix))
	}
	resolver := NewMapResolver(mix)
	timings := make([]int64, 0, iterations)
	bucketCounts := make(map[string]int, len(DefaultMix))
	start := time.Now()
	for i := 0; i < iterations; i++ {
		signed := mix[i%len(mix)]
		bucketName := DefaultMix[(i%len(mix))%len(DefaultMix)].Name
		bucketCounts[bucketName]++
		t0 := time.Now()
		err := ledgeradmission.VerifyEntrySignature(ctx, signed.Entry, signed.Signature, resolver)
		timings = append(timings, time.Since(t0).Nanoseconds())
		if err != nil {
			return LatencyReport{}, fmt.Errorf("MeasureVerify[%d]: verify failed: %w", i, err)
		}
	}
	total := time.Since(start)
	return summarize(timings, total, bucketCounts), nil
}

func summarize(timings []int64, total time.Duration, bucketCounts map[string]int) LatencyReport {
	sort.Slice(timings, func(i, j int) bool { return timings[i] < timings[j] })
	n := len(timings)
	var sum int64
	for _, v := range timings {
		sum += v
	}
	pct := func(p float64) int64 {
		if n == 0 {
			return 0
		}
		idx := int(float64(n) * p)
		if idx >= n {
			idx = n - 1
		}
		return timings[idx]
	}
	return LatencyReport{
		MixVersion: BaselineMixVersion,
		Iterations: n,
		TotalNs:    total.Nanoseconds(),
		MeanNs:     sum / int64(n),
		P50Ns:      pct(0.50),
		P95Ns:      pct(0.95),
		P99Ns:      pct(0.99),
		P999Ns:     pct(0.999),
		MaxNs:      timings[n-1],
		PerBucket:  bucketCounts,
		CapturedAt: time.Now().UTC(),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Baseline comparison
// ─────────────────────────────────────────────────────────────────────────────

// LoadBaseline reads the committed baseline JSON from path. Returns
// an error if the file is missing — the bench harness can't compare
// against a non-existent baseline. The first run of any new bench
// MUST capture and commit the baseline before regression comparison
// becomes meaningful.
func LoadBaseline(path string) (LatencyReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LatencyReport{}, fmt.Errorf("LoadBaseline: %w", err)
	}
	var r LatencyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return LatencyReport{}, fmt.Errorf("LoadBaseline: parse %s: %w", path, err)
	}
	return r, nil
}

// SaveReport writes report as JSON to path, creating the file if
// missing. Used by the "capture-baseline" bench mode and by tests
// that want to inspect a captured run.
func SaveReport(path string, report LatencyReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("SaveReport: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("SaveReport: write %s: %w", path, err)
	}
	return nil
}

// PercentDelta computes (current - baseline) / baseline as a
// percentage. Positive = regression, negative = improvement.
// Returns 0 if baseline is 0 (avoid divide-by-zero).
func PercentDelta(baseline, current int64) float64 {
	if baseline == 0 {
		return 0
	}
	return float64(current-baseline) / float64(baseline) * 100.0
}

// ComparisonRow is one percentile-line in the side-by-side report.
type ComparisonRow struct {
	Name      string
	BaselineN int64
	CurrentN  int64
	DeltaPct  float64
}

// CompareToBaseline returns a fixed-shape comparison across the
// four percentile lines. Used by gate PRs to gate their CI on the
// SLA: a row whose DeltaPct exceeds the configured budget fails
// the build.
func CompareToBaseline(baseline, current LatencyReport) []ComparisonRow {
	return []ComparisonRow{
		{Name: "p50", BaselineN: baseline.P50Ns, CurrentN: current.P50Ns, DeltaPct: PercentDelta(baseline.P50Ns, current.P50Ns)},
		{Name: "p95", BaselineN: baseline.P95Ns, CurrentN: current.P95Ns, DeltaPct: PercentDelta(baseline.P95Ns, current.P95Ns)},
		{Name: "p99", BaselineN: baseline.P99Ns, CurrentN: current.P99Ns, DeltaPct: PercentDelta(baseline.P99Ns, current.P99Ns)},
		{Name: "p999", BaselineN: baseline.P999Ns, CurrentN: current.P999Ns, DeltaPct: PercentDelta(baseline.P999Ns, current.P999Ns)},
	}
}
