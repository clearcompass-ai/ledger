// Telemetry-instrument installation.
//
// FILE PATH:
//
//	cmd/ledger/boot/wire/instruments.go
//
// DESCRIPTION:
//
//	Installs the cross-package OTel histograms + counters on the
//	MeterProvider that alloc.allocateTelemetry already constructed.
//	Each install* helper is a no-op when the meter is nil so this
//	file is safe to call unconditionally.
//
//	Two phases of instrument install:
//
//	  - prebuilder: histograms + counters that depend only on the
//	    MeterProvider (api error counter, request duration, WAL
//	    submit duration, Tessera append, Postgres pool acquire,
//	    bytestore PUT, gossip witness/equivocation counters).
//	    Called from Wire BEFORE composeSequencer / composeShipper.
//
//	  - late-bound gauges: those that need the sequencer + shipper
//	    instances. Lives in wire.go's installLateBoundGauges.
package wire

import (
	"go.opentelemetry.io/otel"

	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/deps"
	"github.com/clearcompass-ai/ledger/gossipnet"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/tessera"
	"github.com/clearcompass-ai/ledger/wal"
)

// installPrebuilderInstruments installs the OTel histograms / counters
// that exist independent of the sequencer + shipper instances. No-op
// when MeterProvider is nil.
func installPrebuilderInstruments(d *deps.AppDeps) {
	if d.MeterProvider == nil {
		return
	}
	mp := otel.GetMeterProvider()
	apiMeter := mp.Meter("github.com/clearcompass-ai/ledger/api")
	if installed := api.InstallErrorCounter(apiMeter); installed {
		d.Logger.Info("metrics: api error counter installed",
			"metric", "attesta_api_errors_total")
	}
	if installed := api.InstallRequestDurationHistogram(apiMeter); installed {
		d.Logger.Info("metrics: api request duration installed",
			"metric", "attesta_api_request_duration_seconds")
	}

	walMeter := mp.Meter("github.com/clearcompass-ai/ledger/wal")
	if installed := wal.InstallSubmitDurationHistogram(walMeter); installed {
		d.Logger.Info("metrics: wal submit duration installed",
			"metric", "attesta_wal_submit_duration_seconds")
	}

	tesseraMeter := mp.Meter("github.com/clearcompass-ai/ledger/tessera")
	if installed := tessera.InstallAppendDurationHistogram(tesseraMeter); installed {
		d.Logger.Info("metrics: tessera append duration installed",
			"metric", "attesta_tessera_append_duration_seconds")
	}
	if installed := tessera.InstallCloseDrainResidualGauge(tesseraMeter); installed {
		// Sampled at EmbeddedAppender.Close exit. Persistent positive
		// values indicate upstream tessera.NewAppender's background
		// goroutines aren't draining within the configured budget —
		// see tessera/instruments.go for the operational rationale.
		d.Logger.Info("metrics: tessera close drain residual installed",
			"metric", "attesta_tessera_close_drain_residual_goroutines")
	}

	storeMeter := mp.Meter("github.com/clearcompass-ai/ledger/store")
	if installed := store.InstallPoolAcquireDurationHistogram(storeMeter); installed {
		d.Logger.Info("metrics: postgres pool acquire installed",
			"metric", "attesta_postgres_pool_acquire_seconds")
	}

	bsMeter := mp.Meter("github.com/clearcompass-ai/ledger/bytestore")
	if installed := bytestore.InstallPutDurationHistogram(bsMeter); installed {
		d.Logger.Info("metrics: bytestore put duration installed",
			"metric", "attesta_bytestore_put_duration_seconds")
	}

	if d.GossipMeter != nil {
		if installed := gossipnet.InstallWitnessQuorumFailureCounter(d.GossipMeter); installed {
			d.Logger.Info("metrics: witness quorum failures installed",
				"metric", "attesta_witness_quorum_failures_total")
		}
		if installed := gossipnet.InstallEquivocationDetectedCounter(d.GossipMeter); installed {
			d.Logger.Info("metrics: equivocation detected installed",
				"metric", "attesta_equivocation_detected_total")
		}
	}
}
