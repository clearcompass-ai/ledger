/*
FILE PATH: cmd/ledger/pool_sizing_test.go

Tests defaultPgMaxConns + validatePgPoolSizing — boot-time guards
that prevent the Sequencer from saturating the Postgres pool and
starving the HTTP admission path under load.
*/
package main

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/ledger/sequencer"
)

func TestDefaultPgMaxConns_FloorsAt20(t *testing.T) {
	cases := []struct {
		mif  int
		want int32
	}{
		{0, 20},  // zero → uses sequencer default (4) → 4*4=16, floored to 20
		{1, 20},  // 1*4=4, floored to 20
		{2, 20},  // 2*4=8, floored to 20
		{4, 20},  // 4*4=16, floored to 20
		{5, 20},  // 5*4=20, exactly at floor
		{6, 24},  // 6*4=24
		{16, 64}, // 16*4=64
		{32, 128},
	}
	for _, tc := range cases {
		got := defaultPgMaxConns(tc.mif)
		if got != tc.want {
			t.Errorf("defaultPgMaxConns(%d) = %d, want %d", tc.mif, got, tc.want)
		}
	}
}

func TestDefaultPgMaxConns_ZeroFallsBackToSequencerDefault(t *testing.T) {
	// MaxInFlight=0 must use sequencer.DefaultMaxInFlight; pinning
	// the contract here so a future tweak to DefaultMaxInFlight
	// stays consistent with ledger-side defaulting.
	got := defaultPgMaxConns(0)
	expectedFromDefault := int32(sequencer.DefaultMaxInFlight * 4)
	if expectedFromDefault < 20 {
		expectedFromDefault = 20
	}
	if got != expectedFromDefault {
		t.Errorf("defaultPgMaxConns(0) = %d, want %d (from sequencer.DefaultMaxInFlight=%d)",
			got, expectedFromDefault, sequencer.DefaultMaxInFlight)
	}
}

func TestValidatePgPoolSizing_RejectsBelowFloor(t *testing.T) {
	cases := []struct {
		maxConns int32
		mif      int
		wantErr  bool
	}{
		// MaxInFlight=4, headroom=8 → required=12.
		{maxConns: 1, mif: 4, wantErr: true},
		{maxConns: 11, mif: 4, wantErr: true},
		{maxConns: 12, mif: 4, wantErr: false},
		{maxConns: 20, mif: 4, wantErr: false},

		// MaxInFlight=16, headroom=8 → required=24.
		{maxConns: 23, mif: 16, wantErr: true},
		{maxConns: 24, mif: 16, wantErr: false},
		{maxConns: 64, mif: 16, wantErr: false},

		// MaxInFlight=0 → uses sequencer default.
		{maxConns: 0, mif: 0, wantErr: true},
		{maxConns: int32(sequencer.DefaultMaxInFlight + pgPoolHeadroom), mif: 0, wantErr: false},
	}
	for _, tc := range cases {
		err := validatePgPoolSizing(tc.maxConns, tc.mif)
		if (err != nil) != tc.wantErr {
			t.Errorf("validatePgPoolSizing(maxConns=%d, mif=%d): err=%v, wantErr=%v",
				tc.maxConns, tc.mif, err, tc.wantErr)
		}
	}
}

func TestValidatePgPoolSizing_ErrorMessageActionable(t *testing.T) {
	err := validatePgPoolSizing(1, 16)
	if err == nil {
		t.Fatal("expected error")
	}
	// The error must point at the env var to set so an ledger
	// reading the boot log can fix the misconfig without spelunking.
	for _, want := range []string{
		"LEDGER_PG_MAX_CONNS",
		"LEDGER_SEQUENCER_MAX_INFLIGHT",
		"headroom",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

// Defaults from defaultPgMaxConns must always satisfy
// validatePgPoolSizing — i.e. the ledger never refuses to start
// when no env override is set.
func TestDefaultPgMaxConns_AlwaysPassesValidation(t *testing.T) {
	cases := []int{0, 1, 2, 4, 8, 16, 32, 64, 128}
	for _, mif := range cases {
		got := defaultPgMaxConns(mif)
		if err := validatePgPoolSizing(got, mif); err != nil {
			t.Errorf("default for MaxInFlight=%d (=%d) fails validation: %v",
				mif, got, err)
		}
	}
}

// pgPoolHeadroom is the load-bearing safety margin. Pin its
// invariants so accidental tightening (which would create false-
// negative startup failures) is caught.
func TestPgPoolHeadroom_Invariants(t *testing.T) {
	if pgPoolHeadroom <= 0 {
		t.Errorf("pgPoolHeadroom must be positive, got %d", pgPoolHeadroom)
	}
	// Headroom must cover the at-least-one-each consumers we
	// know hold connections concurrent with the sequencer:
	//   1) HTTP admission (deductCreditModeA tx)
	//   2) Auth middleware (token lookup)
	//   3) Builder loop (SMT updates)
	//   4) Shipper loop (entry_index updates)
	//   5) Hash-lookup queries (FetchByHash)
	//   6) Range-scan queries
	//   7) Commitment lookups
	//   8) Headroom for transient reconnection bursts
	if pgPoolHeadroom < 8 {
		t.Errorf("pgPoolHeadroom = %d, want >= 8 (one per known concurrent consumer)", pgPoolHeadroom)
	}
}
