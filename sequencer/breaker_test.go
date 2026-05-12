// FILE PATH: sequencer/breaker_test.go
//
// Unit tests for the identical-batch circuit breaker.
//
// The breaker is the safety belt against a poison-pill batch
// looping the committer forever: three consecutive failures with
// the SAME first_seq and the SAME error fingerprint trip a fatal
// channel signal so the supervisor terminates the process. These
// tests pin:
//
//	(1) Streak counting — same (seq, error) consecutively bumps
//	    the counter; a different seq OR a different error resets.
//	(2) Threshold — exactly 3 consecutive matches trips, not 2.
//	(3) Fatal-channel signal — on trip, an error is sent.
//	(4) Idempotent trip — the trip fires once even if the breaker
//	    re-enters after the fatal send.
//	(5) Nil fatal channel — breaker still trips (returns true)
//	    so the committer can stop re-pushing, but does not panic.
package sequencer

import (
	"errors"
	"testing"
	"time"
)

func TestIdenticalBatchBreaker_StreakIncrementsOnIdenticalFailure(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	fatalCh := make(chan error, 1)
	s.WithFatalChannel(fatalCh)

	err := errors.New("duplicate key value violates unique constraint \"entry_index_canonical_hash_primary_idx\"")
	if tripped := s.checkIdenticalBatchBreaker(16, err); tripped {
		t.Fatal("first failure must not trip the breaker")
	}
	if tripped := s.checkIdenticalBatchBreaker(16, err); tripped {
		t.Fatal("second failure must not trip the breaker")
	}
	// Third failure MUST trip.
	if tripped := s.checkIdenticalBatchBreaker(16, err); !tripped {
		t.Fatal("third identical failure must trip the breaker")
	}
	select {
	case fe := <-fatalCh:
		if fe == nil {
			t.Fatal("fatal channel got nil error")
		}
	case <-time.After(time.Second):
		t.Fatal("fatal channel did not receive on trip")
	}
}

func TestIdenticalBatchBreaker_DifferentSeqResetsStreak(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	s.WithFatalChannel(make(chan error, 1))

	err := errors.New("constraint violation")
	_ = s.checkIdenticalBatchBreaker(16, err)
	_ = s.checkIdenticalBatchBreaker(16, err)
	// Now a DIFFERENT first_seq — streak resets to 1.
	if tripped := s.checkIdenticalBatchBreaker(20, err); tripped {
		t.Fatal("streak with a fresh first_seq should NOT inherit the prior streak")
	}
	// Continue with seq=16 — streak should still be at 2 from before...
	// actually wait: the seq-20 call replaced the tracker. Now seq-16
	// is a "new" tracker too.
	if tripped := s.checkIdenticalBatchBreaker(16, err); tripped {
		t.Fatal("new tracker for seq=16 after seq=20 reset should not trip")
	}
}

func TestIdenticalBatchBreaker_DifferentErrorResetsStreak(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	s.WithFatalChannel(make(chan error, 1))

	first := errors.New("error A")
	second := errors.New("error B")
	_ = s.checkIdenticalBatchBreaker(16, first)
	_ = s.checkIdenticalBatchBreaker(16, first)
	// Same seq but DIFFERENT error fingerprint — streak resets.
	if tripped := s.checkIdenticalBatchBreaker(16, second); tripped {
		t.Fatal("different error fingerprint should reset the streak")
	}
}

func TestIdenticalBatchBreaker_ResetClearsStreak(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	s.WithFatalChannel(make(chan error, 1))

	err := errors.New("transient blip")
	_ = s.checkIdenticalBatchBreaker(16, err)
	_ = s.checkIdenticalBatchBreaker(16, err)
	// Simulate a successful flush — streak should reset.
	s.resetIdenticalBatchBreaker()
	if tripped := s.checkIdenticalBatchBreaker(16, err); tripped {
		t.Fatal("reset before threshold should clear the streak — third failure not yet a trip")
	}
}

func TestIdenticalBatchBreaker_TripIsIdempotent(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	fatalCh := make(chan error, 2)
	s.WithFatalChannel(fatalCh)

	err := errors.New("poisoned batch")
	_ = s.checkIdenticalBatchBreaker(16, err)
	_ = s.checkIdenticalBatchBreaker(16, err)
	if tripped := s.checkIdenticalBatchBreaker(16, err); !tripped {
		t.Fatal("third call must trip")
	}
	// Fourth call: still tripped, but the fatal channel should
	// not receive a duplicate signal.
	if tripped := s.checkIdenticalBatchBreaker(16, err); !tripped {
		t.Fatal("fourth identical call must remain tripped")
	}
	// Drain the first fatal send; the second call must not have
	// queued a duplicate.
	<-fatalCh
	select {
	case fe := <-fatalCh:
		t.Errorf("fatal channel got a duplicate trip send: %v", fe)
	case <-time.After(100 * time.Millisecond):
		// Pass: only one send, as required.
	}
}

func TestIdenticalBatchBreaker_NilFatalChannelDoesNotPanic(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	// Deliberately do NOT wire a fatal channel.
	err := errors.New("constraint failure")
	for i := 0; i < identicalBatchBreakerThreshold-1; i++ {
		_ = s.checkIdenticalBatchBreaker(16, err)
	}
	tripped := s.checkIdenticalBatchBreaker(16, err)
	if !tripped {
		t.Fatal("breaker must trip even without a fatal channel")
	}
	// Test passes if we got here without a panic on the nil-channel
	// send path.
}
