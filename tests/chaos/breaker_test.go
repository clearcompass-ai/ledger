//go:build chaos
// +build chaos

/*
FILE PATH:
    tests/chaos/breaker_test.go

DESCRIPTION:
    J4 — Chaos test placeholder for the Postgres circuit breaker
    (B3) under real PG outage. Skipped without ATTESTA_TEST_DSN
    because driving the breaker's state machine requires either:

      (a) ATTESTA_TEST_DSN pointing at a Postgres the test can
          stop/start (requires Docker socket + privileged ops);
          OR
      (b) iptables-based connection blocking (Linux-specific,
          requires CAP_NET_ADMIN in the runner).

    The breaker's state machine is exhaustively unit-tested in
    store/breaker_test.go (9 tests covering closed → open →
    half-open → closed/re-open paths with synthetic time
    progression). This file exists to document the chaos
    follow-up and reserve the test name.
*/
package chaos

import (
	"os"
	"testing"
)

// TestChaos_BreakerUnderRealPGOutage is a documented placeholder.
// Skipped unless the administrator opts in via env vars that confirm
// the runner has the privileged operations available.
func TestChaos_BreakerUnderRealPGOutage(t *testing.T) {
	if os.Getenv("ATTESTA_TEST_DSN") == "" {
		t.Skip("ATTESTA_TEST_DSN unset; breaker chaos requires a real PG with stop/start capability")
	}
	if os.Getenv("ATTESTA_TEST_CHAOS_PG_OUTAGE") != "1" {
		t.Skip("ATTESTA_TEST_CHAOS_PG_OUTAGE != 1; this test requires privileged PG control")
	}
	// TODO: full implementation — requires runtime ability to
	// stop the postgres container OR pg_terminate_backend the
	// breaker's holding connection. Reserved for the J4
	// follow-up commit that wires
	// scripts/local/docker-compose.testharness.yml's
	// chaos profile.
	t.Log("breaker chaos: real PG outage simulation deferred (see header comment)")
}
