/*
FILE PATH:

	delegationresolver/metrics.go

DESCRIPTION:

	OpenTelemetry instruments for the delegation resolver cache.
	Same Install* idiom as api/instruments.go: a package-level
	holder, idempotent install, nil-safe call sites.

INSTRUMENTS:

  - attesta_delegation_cache_hits_total          (counter)
  - attesta_delegation_cache_misses_total        (counter)
  - attesta_delegation_cache_invalidations_total (counter)

A cache_hit_ratio gauge is derived in the dashboard from
hits / (hits + misses); putting the ratio in the dashboard rather
than emitting it as a meter avoids the wide-string-attribute
cardinality blowup that would come from per-DID dimensions.

WHY COUNTERS, NOT RATES:

	Cumulative counters compose with Prometheus's rate() function;
	emitting rates directly would force a particular bucketisation
	(per-second? per-minute?) and break aggregation across replicas.
	Dashboards take rate(hits) / (rate(hits) + rate(misses)) — same
	ratio, choose-your-own window.

NIL-SAFE:

	A nil *Metrics receiver makes recordHit/recordMiss/
	recordInvalidation no-ops. Tests and dev runs that do not
	enable OTel still wire a Cached without metrics and the
	cache works exactly the same.
*/
package delegationresolver

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/metric"
)

// Metrics groups the three cumulative counters for the cache.
// Construct via NewMetrics; pass to NewCached. nil is permitted
// at the call site (recordX methods become no-ops).
type Metrics struct {
	hits          metric.Int64Counter
	misses        metric.Int64Counter
	invalidations metric.Int64Counter
}

// metricsState lets the package install one set of instruments
// per process (matches api/instruments.go's idiom). Tests that
// want fresh instruments build their own *Metrics directly via
// NewMetrics; production wires through Install.
var metricsState struct {
	mu      sync.RWMutex
	current *Metrics
}

// Install creates the cache-cohort instruments on meter and
// stores them in the package-level holder. Returns true on first
// install, false on a re-install attempt (matches the
// api.InstallRequestDurationHistogram contract). nil meter is a
// no-op.
//
// Production wires this from cmd/ledger/boot at the same
// initialisation point as api.InstallErrorCounter.
func Install(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	metricsState.mu.Lock()
	defer metricsState.mu.Unlock()
	if metricsState.current != nil {
		return false
	}
	m, err := NewMetrics(meter)
	if err != nil {
		return false
	}
	metricsState.current = m
	return true
}

// CurrentMetrics returns the package-level *Metrics installed by
// Install. Returns nil before Install is called or when Install
// failed. Callers (cache constructor in production wire) thread
// this into NewCached's metrics parameter.
func CurrentMetrics() *Metrics {
	metricsState.mu.RLock()
	defer metricsState.mu.RUnlock()
	return metricsState.current
}

// NewMetrics constructs a fresh Metrics bound to meter. Returns
// an error if any counter creation fails — caller decides whether
// to surface as boot failure or continue with metrics off.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	hits, err := meter.Int64Counter(
		"attesta_delegation_cache_hits_total",
		metric.WithDescription("DelegationResolver cache hits (positive + negative)."),
	)
	if err != nil {
		return nil, err
	}
	misses, err := meter.Int64Counter(
		"attesta_delegation_cache_misses_total",
		metric.WithDescription("DelegationResolver cache misses; each implies one underlying source lookup."),
	)
	if err != nil {
		return nil, err
	}
	invalidations, err := meter.Int64Counter(
		"attesta_delegation_cache_invalidations_total",
		metric.WithDescription("DelegationResolver cache invalidations (rotation-driven or operator)."),
	)
	if err != nil {
		return nil, err
	}
	return &Metrics{hits: hits, misses: misses, invalidations: invalidations}, nil
}

// recordHit increments the hit counter. nil receiver no-ops so
// the cache can run unmetered in tests / degraded modes.
func (m *Metrics) recordHit() {
	if m == nil || m.hits == nil {
		return
	}
	m.hits.Add(context.Background(), 1)
}

func (m *Metrics) recordMiss() {
	if m == nil || m.misses == nil {
		return
	}
	m.misses.Add(context.Background(), 1)
}

func (m *Metrics) recordInvalidation(n int64) {
	if m == nil || m.invalidations == nil {
		return
	}
	m.invalidations.Add(context.Background(), n)
}
