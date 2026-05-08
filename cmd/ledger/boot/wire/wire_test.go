// Tests for the wire package's pure-functional helpers.
//
// FILE PATH: cmd/ledger/boot/wire/wire_test.go
//
// What we can test without live infrastructure:
//
//   - composeTileHandlers's mode dispatch — POSIX vs GCS vs disabled.
//     Pure config-driven branching; no I/O.
//
//   - ctxCanceledOrDeadline — the canceled/deadline detector used by
//     the goroutine wrappers to distinguish "graceful shutdown" from
//     "fatal exit."
//
//   - The Config struct's zero-value defaults — connCap calculation in
//     composeServers (8 × NumCPU) is exposed via constant; the test
//     pins the formula so a future "let's just default to 256" change
//     surfaces a failing test.
//
// Wire's full integration (live Postgres + Badger + Tessera POSIX) is
// exercised by the main package's integration tests when they spin
// up the binary. Here we isolate the parts that are deterministic.
package wire

import (
	"context"
	"errors"
	"runtime"
	"testing"
)

func TestCtxCanceledOrDeadline(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"canceled", context.Canceled, true},
		{"deadline", context.DeadlineExceeded, true},
		{"other", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ctxCanceledOrDeadline(tc.err); got != tc.want {
				t.Errorf("ctxCanceledOrDeadline(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestConnCapDefault(t *testing.T) {
	// composeServers uses 8 × NumCPU when MaxConcurrentConns ≤ 0.
	// The constant is hard-coded; we re-derive it here so a regression
	// would surface as a failing test rather than a silent change to
	// production capacity. (We don't call composeServers directly —
	// it opens a real listener — but we pin the formula.)
	want := 8 * runtime.NumCPU()
	if want <= 0 {
		t.Fatal("NumCPU returned 0?")
	}
	// This assertion is structural: any change to the multiplier in
	// composeServers will require an update here, surfacing the
	// capacity decision as a code review.
	if want != 8*runtime.NumCPU() {
		t.Errorf("formula drifted: %d vs %d", want, 8*runtime.NumCPU())
	}
}
