// Tests for the closeStack discipline of AppDeps.
//
// FILE PATH: cmd/ledger/boot/deps/deps_test.go
//
// These tests pin the contract every boot phase relies on:
//
//   - AppendCloser preserves registration order.
//   - UnwindReverse calls closers in REVERSE registration order
//     (newest opened first; oldest opened last).
//   - UnwindReverse logs but does not abort on individual errors.
//   - UnwindReverse resets the stack — a subsequent TakeClosers
//     returns empty.
//   - TakeClosers returns in REGISTRATION order (the order
//     teardown.Register transcribes into the ShutdownChain).
//   - TakeClosers resets the stack — subsequent calls return empty.
//
// The closer-stack is the single piece of state shared across all
// three lifecycle phases. Wrong ordering or a missed reset would
// produce double-closes or skipped closes — both class-of-bug we
// designed the phase split to eliminate. Tests pin the contract.
package deps

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// recordingCloser produces a NamedCloser that appends its name to a
// shared slice on each call, so tests can assert the call order.
func recordingCloser(name string, calls *[]string, returnErr error) NamedCloser {
	return NamedCloser{
		Name:    name,
		Timeout: 10 * time.Millisecond,
		Close: func(_ context.Context) error {
			*calls = append(*calls, name)
			return returnErr
		},
	}
}

func TestAppendCloser_PreservesOrder(t *testing.T) {
	d := &AppDeps{}
	d.AppendCloser(NamedCloser{Name: "first"})
	d.AppendCloser(NamedCloser{Name: "second"})
	d.AppendCloser(NamedCloser{Name: "third"})

	got := d.TakeClosers()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	want := []string{"first", "second", "third"}
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("got[%d].Name = %q, want %q", i, got[i].Name, w)
		}
	}
}

func TestUnwindReverse_CallsInReverse(t *testing.T) {
	var calls []string
	d := &AppDeps{}
	d.AppendCloser(recordingCloser("postgres", &calls, nil))
	d.AppendCloser(recordingCloser("wal-db", &calls, nil))
	d.AppendCloser(recordingCloser("bytestore", &calls, nil))

	d.UnwindReverse(context.Background())

	want := []string{"bytestore", "wal-db", "postgres"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want len %d", calls, len(want))
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("calls[%d] = %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestUnwindReverse_LogsButContinuesOnError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	var calls []string
	d := &AppDeps{Logger: logger}
	d.AppendCloser(recordingCloser("postgres", &calls, errors.New("boom")))
	d.AppendCloser(recordingCloser("wal-db", &calls, nil))

	d.UnwindReverse(context.Background())

	// Both closers ran despite postgres returning an error.
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want both", calls)
	}
	if calls[0] != "wal-db" || calls[1] != "postgres" {
		t.Errorf("order = %v, want [wal-db postgres]", calls)
	}
	// The log carries the failing step's name.
	if !strings.Contains(buf.String(), "postgres") || !strings.Contains(buf.String(), "boom") {
		t.Errorf("log missing diagnostic; got %s", buf.String())
	}
}

func TestUnwindReverse_NilLoggerIsSilent(t *testing.T) {
	// A boot panic before Logger is set must not panic in
	// UnwindReverse's logging path.
	var calls []string
	d := &AppDeps{}
	d.AppendCloser(recordingCloser("postgres", &calls, errors.New("boom")))
	// Must not panic with Logger == nil.
	d.UnwindReverse(context.Background())
	if len(calls) != 1 {
		t.Fatalf("close not called: %v", calls)
	}
}

func TestUnwindReverse_ResetsStack(t *testing.T) {
	var calls []string
	d := &AppDeps{}
	d.AppendCloser(recordingCloser("a", &calls, nil))
	d.UnwindReverse(context.Background())

	// Subsequent TakeClosers returns empty — preventing
	// double-close if a defensive teardown fires after unwind.
	got := d.TakeClosers()
	if len(got) != 0 {
		t.Errorf("stack not reset; got %d closers", len(got))
	}
}

func TestTakeClosers_ResetsStack(t *testing.T) {
	d := &AppDeps{}
	d.AppendCloser(NamedCloser{Name: "a"})
	d.AppendCloser(NamedCloser{Name: "b"})

	first := d.TakeClosers()
	second := d.TakeClosers()

	if len(first) != 2 {
		t.Errorf("first take len = %d, want 2", len(first))
	}
	if len(second) != 0 {
		t.Errorf("second take len = %d, want 0 (stack should be reset)", len(second))
	}
}

func TestUnwindReverse_PerComponentTimeout(t *testing.T) {
	// The closer should observe a ctx with the per-component
	// timeout set on the NamedCloser. We assert by reading the
	// deadline.
	d := &AppDeps{}
	var observed time.Duration
	d.AppendCloser(NamedCloser{
		Name:    "delayed",
		Timeout: 250 * time.Millisecond,
		Close: func(ctx context.Context) error {
			if dl, ok := ctx.Deadline(); ok {
				observed = time.Until(dl)
			}
			return nil
		},
	})

	d.UnwindReverse(context.Background())
	// Allow some scheduling slack: the deadline must be at least
	// 200ms in the future when observed.
	if observed < 200*time.Millisecond {
		t.Errorf("per-component timeout not applied; observed remaining = %v", observed)
	}
}
