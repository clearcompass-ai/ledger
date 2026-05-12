/*
FILE PATH: tests/chaos/harness/harness.go

The main Harness type — composes Postgres, Witnesses, Bootstrap,
and Process into one end-to-end ledger subprocess test fixture.
Chaos tests construct a Harness, Start the ledger subprocess,
submit traffic via the HTTP client, optionally trigger SIGKILL +
Restart cycles, then assert invariants via the Postgres pool.

LIFECYCLE

  h := harness.New(t, harness.Config{...})    // sets up PG + witnesses
                                              // + temp dirs + binary
  h.Start(ctx)                                // spawns ledger subprocess
  // ... submit traffic ...
  h.Kill()                                    // SIGKILL
  h.Restart(ctx, harness.RestartOpts{...})    // re-spawn against same state
  // ... assert ...
  // t.Cleanup runs Postgres.Close + Witnesses.Close + Kill

PERSISTENT STATE BETWEEN START / RESTART

  - Postgres database — same across restarts (PG schema state
    durable on disk)
  - WAL Badger path — same (t.TempDir(), survives test until
    cleanup)
  - Tessera storage path — same
  - Bootstrap.json + signer key files — same
  - bytestore prefix — same (one prefix per Harness instance)

  Only the subprocess + its in-memory state is destroyed by Kill.

CHAOS INJECTION

  RestartOpts.PanicAt sets LEDGER_CHAOS_PANIC_AT for the next
  subprocess. RestartOpts.PanicAfterN sets the AFTER_N gate.
  Both default to empty / 0 so a Restart without chaos config
  just brings the ledger back cleanly.
*/
package harness

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Config is the per-test harness configuration.
type Config struct {
	// WitnessCount — N witnesses to spawn. Default 3.
	WitnessCount int

	// WitnessQuorumK — K-of-N quorum. Default = WitnessCount
	// (every witness must sign — most conservative for chaos
	// tests; override when testing K-of-N tolerances).
	WitnessQuorumK int

	// ExchangeDID — passed into bootstrap.json. Default
	// "did:web:chaos-test.example".
	ExchangeDID string

	// NetworkName — passed into bootstrap.json. Default
	// "chaos-test".
	NetworkName string

	// LogDID — set LEDGER_LOG_DID. Default
	// "did:attesta:ledger:chaos".
	LogDID string

	// ReadyTimeout — how long to wait for /healthz after Start.
	// Default 30 seconds.
	ReadyTimeout time.Duration

	// SequencerMaxInFlight — set LEDGER_SEQUENCER_MAX_INFLIGHT.
	// 0 = use binary default (4).
	SequencerMaxInFlight int

	// ExtraEnv — extra KEY=VALUE strings appended to the
	// subprocess env. Useful for setting chaos-injection vars
	// at Start (vs Restart, which has its own field).
	ExtraEnv []string
}

// RestartOpts controls a Restart cycle.
type RestartOpts struct {
	// PanicAt — sets LEDGER_CHAOS_PANIC_AT for the next
	// subprocess. Empty = no panic injection.
	PanicAt string

	// PanicAfterN — sets LEDGER_CHAOS_PANIC_AFTER_N. 0 = first
	// match panics.
	PanicAfterN int

	// ReadyTimeout — override Config.ReadyTimeout for this
	// restart. Zero = use Config default.
	ReadyTimeout time.Duration
}

// Harness is one end-to-end ledger subprocess fixture.
type Harness struct {
	t      *testing.T
	cfg    Config

	// Composed components.
	pg        *Postgres
	witnesses *Witnesses
	bootstrap BootstrapBundle

	// Per-test paths.
	tmpDir         string
	walPath        string
	tesseraDir     string
	antispamDir    string
	bytestorePrefix string

	// Process binding.
	addr    string
	port    int
	binary  string
	process *Process

	// Bytestore connection env (read from harness env at
	// construction). Same prefix used across Start/Restart.
	bytestoreEnv []string
}

// New constructs the harness without spawning the ledger.
// Provisions Postgres, witnesses, bootstrap, temp dirs, and
// builds the binary. Use Start to launch the subprocess.
//
// Caller's TestMain MUST have called EnsureLedgerBinary with the
// module root path; otherwise New calls t.Fatalf.
//
// Skips the test (t.Skip) when prerequisites (Postgres DSN,
// bytestore env) are not configured.
func New(t *testing.T, cfg Config) *Harness {
	t.Helper()
	applyConfigDefaults(&cfg)

	h := &Harness{
		t:      t,
		cfg:    cfg,
		binary: LedgerBinaryPath(t),
	}

	// Set up isolated state directories. t.TempDir auto-cleans.
	h.tmpDir = t.TempDir()
	h.walPath = filepath.Join(h.tmpDir, "wal")
	h.tesseraDir = filepath.Join(h.tmpDir, "tessera")
	h.antispamDir = filepath.Join(h.tmpDir, "antispam")
	for _, d := range []string{h.walPath, h.tesseraDir, h.antispamDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	// Bytestore env — reused across Start cycles. Sourcing +
	// per-test prefix isolation lives in bytestore.go.
	h.bytestoreEnv = bytestoreEnv(t)
	h.bytestorePrefix = bytestorePrefix()

	// Per-test Postgres database. The ledger's first boot runs
	// migrations against this empty DB.
	h.pg = NewPostgres(t)

	// Witnesses first — bootstrap doc needs their DIDs.
	// NetworkID is computed from the bootstrap doc; we pass it
	// into Witnesses so the cosign handler accepts inbound
	// requests with the matching NetworkID.
	//
	// Bootstrap order: build witnesses with a placeholder
	// NetworkID? No — chicken/egg. Instead: compute bootstrap
	// from witness DIDs first (which doesn't depend on
	// NetworkID), extract the resulting NetworkID, then attach
	// it to witnesses.
	// Two-phase construction: witnesses with placeholder
	// NetworkID → bootstrap from their DIDs → rebind witnesses
	// with the real NetworkID. See rebindNetworkID for rationale.
	var placeholder [32]byte
	h.witnesses = NewWitnesses(t, cfg.WitnessCount, cfg.WitnessQuorumK, placeholder)
	h.bootstrap = BuildBootstrap(t, h.tmpDir,
		cfg.ExchangeDID, cfg.NetworkName, h.witnesses.DIDs())
	h.witnesses.rebindNetworkID(t, h.bootstrap.NetworkID)

	// Address — pick a free port now so we can write it into
	// the env before subprocess Start.
	h.port = PickFreePort(t)
	h.addr = fmt.Sprintf("127.0.0.1:%d", h.port)
	return h
}

// applyConfigDefaults fills zero-valued Config fields.
func applyConfigDefaults(c *Config) {
	if c.WitnessCount == 0 {
		c.WitnessCount = 3
	}
	if c.WitnessQuorumK == 0 {
		c.WitnessQuorumK = c.WitnessCount
	}
	if c.ExchangeDID == "" {
		c.ExchangeDID = "did:web:chaos-test.example"
	}
	if c.NetworkName == "" {
		c.NetworkName = "chaos-test"
	}
	if c.LogDID == "" {
		c.LogDID = "did:attesta:ledger:chaos"
	}
	if c.ReadyTimeout == 0 {
		c.ReadyTimeout = 30 * time.Second
	}
}

// Start spawns the ledger subprocess and waits for /healthz.
// On failure (build error, env error, healthz timeout) returns
// the error; the harness remains in stopped state.
func (h *Harness) Start(ctx context.Context) error {
	return h.startWith(ctx, RestartOpts{ReadyTimeout: h.cfg.ReadyTimeout})
}

// Kill SIGKILL's the subprocess and waits for it to exit. Safe
// to call when already stopped (no-op).
func (h *Harness) Kill() error {
	if h.process == nil {
		return nil
	}
	return h.process.Kill()
}

// Restart kills the current subprocess and starts a fresh one
// against the same on-disk state. PanicAt + PanicAfterN in opts
// inject chaos triggers via LEDGER_CHAOS_PANIC_AT /
// LEDGER_CHAOS_PANIC_AFTER_N env vars in the new subprocess.
func (h *Harness) Restart(ctx context.Context, opts RestartOpts) error {
	if err := h.Kill(); err != nil {
		return fmt.Errorf("Restart: Kill: %w", err)
	}
	if opts.ReadyTimeout == 0 {
		opts.ReadyTimeout = h.cfg.ReadyTimeout
	}
	return h.startWith(ctx, opts)
}

// startWith composes the env, instantiates a Process, runs Start.
func (h *Harness) startWith(ctx context.Context, opts RestartOpts) error {
	env := h.buildEnv(opts)
	h.process = NewProcess(h.binary, env, h.addr)
	return h.process.Start(ctx, opts.ReadyTimeout)
}

// buildEnv composes the full env slice for one subprocess launch.
// Pulls from os.Environ (so PATH etc are inherited) plus all the
// LEDGER_* values + chaos triggers.
func (h *Harness) buildEnv(opts RestartOpts) []string {
	// Start from a clean inheritance of PATH, HOME, etc. but
	// strip any LEDGER_* that would override our config.
	base := make([]string, 0, 64)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LEDGER_") {
			continue
		}
		base = append(base, kv)
	}

	// Required core config.
	env := append(base,
		"LEDGER_DATABASE_URL="+h.pg.DSN,
		"LEDGER_LOG_DID="+h.cfg.LogDID,
		"LEDGER_ADDR="+h.addr,
		"LEDGER_WAL_PATH="+h.walPath,
		"LEDGER_TESSERA_STORAGE_DIR="+h.tesseraDir,
		"LEDGER_TESSERA_ANTISPAM_PATH="+h.antispamDir,
		"LEDGER_TESSERA_ORIGIN="+h.cfg.LogDID,
		// LEDGER_SIGNER_KEY_FILE intentionally unset — see
		// bootstrap.go's package comment. The ledger generates
		// an ephemeral secp256k1 signer per boot.
		"LEDGER_NETWORK_BOOTSTRAP_FILE="+h.bootstrap.BootstrapPath,
		"LEDGER_WITNESS_ENDPOINTS="+strings.Join(h.witnesses.URLs(), ","),
		"LEDGER_WITNESS_QUORUM_K="+strconv.Itoa(h.cfg.WitnessQuorumK),
		// Migrations: apply on first boot, idempotent after.
		"LEDGER_DB_MIGRATE_MODE=apply",
		// Bytestore prefix scoped per-harness.
		"LEDGER_BYTE_STORE_PREFIX="+h.bytestorePrefix,
		// Disable metrics to keep subprocess output tight.
		"LEDGER_METRICS_ENABLE=false",
	)

	// Optional sequencer concurrency override.
	if h.cfg.SequencerMaxInFlight > 0 {
		env = append(env,
			"LEDGER_SEQUENCER_MAX_INFLIGHT="+strconv.Itoa(h.cfg.SequencerMaxInFlight))
	}

	// Bytestore credentials/endpoint inherited from harness env.
	env = append(env, h.bytestoreEnv...)

	// Chaos injection — only set when non-empty so the
	// production no-op path stays exercised in clean Starts.
	if opts.PanicAt != "" {
		env = append(env, "LEDGER_CHAOS_PANIC_AT="+opts.PanicAt)
	}
	if opts.PanicAfterN > 0 {
		env = append(env,
			"LEDGER_CHAOS_PANIC_AFTER_N="+strconv.Itoa(opts.PanicAfterN))
	}

	// Caller-supplied extras last (highest precedence).
	env = append(env, h.cfg.ExtraEnv...)
	return env
}

// Address returns the host:port the ledger is bound to. Use for
// constructing HTTP URLs (combined with the submit helper).
func (h *Harness) Address() string { return h.addr }

// BaseURL returns "http://" + Address.
func (h *Harness) BaseURL() string { return "http://" + h.addr }

// Postgres returns the test's PG pool for diagnostic queries
// (gap/leapfrog/SMT reconstruction).
func (h *Harness) Postgres() *Postgres { return h.pg }

// Witnesses returns the witness fixture for fault injection.
func (h *Harness) Witnesses() *Witnesses { return h.witnesses }

// Process returns the active subprocess (or nil if stopped).
// Tests use this to grep stderr for panic markers.
func (h *Harness) Process() *Process { return h.process }

// LogDID returns the configured log DID.
func (h *Harness) LogDID() string { return h.cfg.LogDID }

// Compile-time confirmations.
var _ net.Listener = (*net.TCPListener)(nil)
