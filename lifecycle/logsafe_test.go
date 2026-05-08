/*
FILE PATH:

	lifecycle/logsafe_test.go

DESCRIPTION:

	Tests for the slog redaction helpers. Pin the privacy
	contract: HashHex one-way, PresenceFlag binary, NetworkIDHex
	handles all-zero correctly.
*/
package lifecycle

import (
	"strings"
	"testing"
)

// -------------------------------------------------------------------------------------------------
// 1) HashHex
// -------------------------------------------------------------------------------------------------

func TestHashHex_DeterministicAndShort(t *testing.T) {
	t.Parallel()
	got := HashHex([]byte("hello world"))
	if len(got) != HashHexPrefixBytes*2 {
		t.Errorf("HashHex length = %d, want %d", len(got), HashHexPrefixBytes*2)
	}
	again := HashHex([]byte("hello world"))
	if got != again {
		t.Errorf("HashHex non-deterministic: %q vs %q", got, again)
	}
}

func TestHashHex_DifferentInputsDifferentHashes(t *testing.T) {
	t.Parallel()
	a := HashHex([]byte("a"))
	b := HashHex([]byte("b"))
	if a == b {
		t.Errorf("HashHex collision on trivial inputs: %q == %q", a, b)
	}
}

func TestHashHex_EmptyReturnsEmpty(t *testing.T) {
	t.Parallel()
	if got := HashHex(nil); got != "" {
		t.Errorf("HashHex(nil) = %q, want empty", got)
	}
	if got := HashHex([]byte{}); got != "" {
		t.Errorf("HashHex(empty) = %q, want empty", got)
	}
}

func TestHashHex_DoesNotLeakOriginalBytes(t *testing.T) {
	t.Parallel()
	src := []byte("super-secret-payload-bytes")
	got := HashHex(src)
	if strings.Contains(got, "secret") || strings.Contains(got, "payload") {
		t.Errorf("HashHex leaked source content: %q", got)
	}
}

// -------------------------------------------------------------------------------------------------
// 2) PresenceFlag
// -------------------------------------------------------------------------------------------------

func TestPresenceFlag(t *testing.T) {
	t.Parallel()
	if PresenceFlag("") != "unset" {
		t.Errorf("PresenceFlag empty != unset")
	}
	if PresenceFlag("anything") != "set" {
		t.Errorf("PresenceFlag non-empty != set")
	}
	if got := PresenceFlag("super-secret-dsn"); strings.Contains(got, "secret") {
		t.Errorf("PresenceFlag leaked content: %q", got)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) NetworkIDHex
// -------------------------------------------------------------------------------------------------

func TestNetworkIDHex_AllZeroReturnsEmpty(t *testing.T) {
	t.Parallel()
	zero := make([]byte, 32)
	if got := NetworkIDHex(zero); got != "" {
		t.Errorf("NetworkIDHex(all-zero) = %q, want empty", got)
	}
}

func TestNetworkIDHex_NonZeroReturnsPrefix(t *testing.T) {
	t.Parallel()
	id := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	got := NetworkIDHex(id)
	if got != "deadbeef01020304" {
		t.Errorf("NetworkIDHex prefix = %q, want %q", got, "deadbeef01020304")
	}
}

// -------------------------------------------------------------------------------------------------
// 4) HexShort
// -------------------------------------------------------------------------------------------------

func TestHexShort(t *testing.T) {
	t.Parallel()
	long := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 chars
	got := HexShort(long)
	want := "0123456789abcdef" // first 16
	if got != want {
		t.Errorf("HexShort(long) = %q, want %q", got, want)
	}
	if HexShort("") != "" {
		t.Error("HexShort(empty) should be empty")
	}
	if HexShort("abc") != "abc" {
		t.Error("HexShort(short) should pass through")
	}
}
