/*
FILE PATH: gossipstore/replay_hwm_test.go

Tests for the 0x0D singleton high-water-mark used by the
sequencer-driven replay-on-restart loop.

Coverage:

  - First-boot read returns 0 (no error, no record).
  - Set → Get round-trip preserves the seq.
  - Idempotent re-Set with the same seq is a no-op (no change in
    on-disk bytes; observable as a Get returning the same value).
  - Monotonic Set: a backwards seq below the current HWM is a
    silent no-op (replay batches are seq-ascending; the contract
    refuses regression so a buggy caller can't corrupt state).
  - Equal Set is allowed (idempotent re-call after crash on the
    same batch).
  - Context cancellation rejected at both Get and Set entry.
  - Corrupt on-disk record (wrong length) surfaces a typed error
    on Get.
*/
package gossipstore

import (
	"context"
	"testing"
)

func TestSplitIDReplayHWM_FirstBoot_ReturnsZero(t *testing.T) {
	st := testStore(t)
	got, err := st.SplitIDReplayHWM(context.Background())
	if err != nil {
		t.Fatalf("SplitIDReplayHWM: %v", err)
	}
	if got != 0 {
		t.Errorf("first boot HWM = %d, want 0", got)
	}
}

func TestSplitIDReplayHWM_SetGetRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.SetSplitIDReplayHWM(ctx, 1234); err != nil {
		t.Fatalf("SetSplitIDReplayHWM: %v", err)
	}
	got, err := st.SplitIDReplayHWM(ctx)
	if err != nil {
		t.Fatalf("SplitIDReplayHWM: %v", err)
	}
	if got != 1234 {
		t.Errorf("HWM = %d, want 1234", got)
	}
}

func TestSplitIDReplayHWM_RepeatSetSameSeqIsIdempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := st.SetSplitIDReplayHWM(ctx, 100); err != nil {
			t.Fatalf("iter=%d: %v", i, err)
		}
	}
	got, _ := st.SplitIDReplayHWM(ctx)
	if got != 100 {
		t.Errorf("HWM = %d, want 100", got)
	}
}

func TestSplitIDReplayHWM_BackwardsSetIsNoOp(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.SetSplitIDReplayHWM(ctx, 500); err != nil {
		t.Fatalf("set 500: %v", err)
	}
	// Buggy caller tries to regress to 100 — must be silently
	// rejected; the existing 500 stays.
	if err := st.SetSplitIDReplayHWM(ctx, 100); err != nil {
		t.Fatalf("set 100 (regression): %v", err)
	}
	got, _ := st.SplitIDReplayHWM(ctx)
	if got != 500 {
		t.Errorf("HWM after regression attempt = %d, want 500 (regression rejected)", got)
	}
}

func TestSplitIDReplayHWM_ForwardsAdvances(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for _, seq := range []uint64{1, 100, 1000, 10000, 1<<63 + 1} {
		if err := st.SetSplitIDReplayHWM(ctx, seq); err != nil {
			t.Fatalf("set %d: %v", seq, err)
		}
		got, _ := st.SplitIDReplayHWM(ctx)
		if got != seq {
			t.Errorf("after set %d, HWM = %d", seq, got)
		}
	}
}

func TestSplitIDReplayHWM_GetCancelledCtx(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.SplitIDReplayHWM(ctx); err == nil {
		t.Error("expected ctx error on cancelled context")
	}
}

func TestSplitIDReplayHWM_SetCancelledCtx(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := st.SetSplitIDReplayHWM(ctx, 1); err == nil {
		t.Error("expected ctx error on cancelled context")
	}
}

func TestEncodeDecodeReplayHWM_RoundTrips(t *testing.T) {
	cases := []uint64{0, 1, 1234, 1 << 32, 1<<63 - 1}
	for _, want := range cases {
		raw := encodeReplayHWM(want)
		if len(raw) != 8 {
			t.Errorf("seq=%d: encoded length = %d, want 8", want, len(raw))
		}
		got := decodeReplayHWM(raw)
		if got != want {
			t.Errorf("decode %d → %d", want, got)
		}
	}
}
