//go:build soak
// +build soak

/*
FILE PATH: tests/soak_helpers_test.go

Unit tests for the small env-parsing helpers in soak_test.go.
Build-tag-isolated alongside soak_test.go; runs in CI under
`go test -tags=soak ./tests/` without needing Postgres or
SeaweedFS containers.

WHY HERE: envSampleCount is the parser that lets operators choose
sample sizes by absolute count ("100") or percentage of N ("5%").
The parsing logic must round consistently, reject malformed
input, and fall back to def on unparseable values. A regression
that silently floors a percentage to 0 would cause the soak's
cryptographic-integrity assertions to skip silently — exactly
the failure mode the parser exists to prevent. Test coverage
makes the rounding contract auditable.
*/
package tests

import (
	"os"
	"testing"
)

func TestEnvSampleCount(t *testing.T) {
	const envName = "ATTESTA_SOAK_TEST_HELPER_SAMPLE_COUNT"

	tests := []struct {
		name  string
		raw   string
		def   int
		total uint64
		want  int
	}{
		// Absolute counts.
		{"unset_falls_back", "", 100, 1000, 100},
		{"absolute_100", "100", 100, 1000, 100},
		{"absolute_1", "1", 100, 1000, 1},
		{"absolute_negative_falls_back", "-5", 100, 1000, 100},
		{"absolute_zero_falls_back", "0", 100, 1000, 100},
		{"absolute_garbage_falls_back", "abc", 100, 1000, 100},
		{"absolute_with_spaces", " 50 ", 100, 1000, 50},

		// Percentages.
		{"percent_1", "1%", 100, 1_000_000, 10_000},
		{"percent_5", "5%", 100, 1000, 50},
		{"percent_0p5", "0.5%", 100, 1000, 5},
		{"percent_10p0", "10.0%", 100, 1000, 100},
		{"percent_100", "100%", 100, 1000, 1000},

		// Percentage edge cases.
		{"percent_with_inner_space", "5 %", 100, 1000, 50},
		{"percent_round_half_up", "0.05%", 100, 1000, 1}, // 0.5 → 1
		{"percent_underflow_falls_back", "0.001%", 100, 1000, 100},
		{"percent_zero_falls_back", "0%", 100, 1000, 100},
		{"percent_negative_falls_back", "-1%", 100, 1000, 100},
		{"percent_garbage_falls_back", "x%", 100, 1000, 100},
		{"percent_over_100_allowed", "200%", 100, 1000, 2000},

		// Total = 0 edge case (matters for verify-mode runs that
		// somehow get called with no submissions). Percentage of
		// zero should fall back to def, not return 0.
		{"percent_total_zero_falls_back", "5%", 100, 0, 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.raw == "" {
				_ = os.Unsetenv(envName)
			} else {
				_ = os.Setenv(envName, tc.raw)
				defer os.Unsetenv(envName)
			}
			got := envSampleCount(envName, tc.def, tc.total)
			if got != tc.want {
				t.Errorf("envSampleCount(%q, def=%d, total=%d) = %d, want %d",
					tc.raw, tc.def, tc.total, got, tc.want)
			}
		})
	}
}
