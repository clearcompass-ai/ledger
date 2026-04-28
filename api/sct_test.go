/*
FILE PATH: api/sct_test.go

Round-trip + tamper-reject coverage for api/sct.go. The SCT is
the operator's binding promise on POST /v2/entries — every field
that's signed-over MUST invalidate the signature when mutated, and
the JSON-only LogTime field MUST NOT (it's derived).

WHAT'S COVERED:

  Encoding determinism:
    - SCTSigningPayload produces identical bytes for identical
      inputs.
    - LogDIDs of every length up to the 65535 limit pack
      correctly; >65535 errors out.

  Sign / Verify round-trip:
    - SignSCT then VerifySCT against the same key passes.
    - VerifySCT rejects nil pub or nil sct.
    - VerifySCT rejects unsupported version.

  Tamper resistance:
    - Mutating CanonicalHash invalidates signature.
    - Mutating LogTimeMicros invalidates signature.
    - Mutating LogDID invalidates signature.
    - Mutating Version invalidates signature (SCTVersion mismatch).
    - Mutating LogTime (JSON-only) does NOT invalidate (it's
      derived; not part of the signing payload).
    - Wrong-key verification fails.
*/
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// ─────────────────────────────────────────────────────────────────────
// SCTSigningPayload
// ─────────────────────────────────────────────────────────────────────

func TestSCTSigningPayload_Deterministic(t *testing.T) {
	hash := sha256.Sum256([]byte("payload determinism"))
	a, err := SCTSigningPayload("did:test:log", hash, 1234567890)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := SCTSigningPayload("did:test:log", hash, 1234567890)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("non-deterministic packing:\n  a=%x\n  b=%x", a, b)
	}
}

func TestSCTSigningPayload_LengthMath(t *testing.T) {
	hash := sha256.Sum256([]byte("len math"))
	for _, did := range []string{"", "a", "did:test:abc", strings.Repeat("x", 1000)} {
		buf, err := SCTSigningPayload(did, hash, 0)
		if err != nil {
			t.Fatalf("did=%q: %v", did, err)
		}
		want := 1 + 2 + len(did) + 32 + 8
		if len(buf) != want {
			t.Errorf("did=%q: payload size %d, want %d", did, len(buf), want)
		}
	}
}

func TestSCTSigningPayload_LogDIDOverflowRejects(t *testing.T) {
	hash := sha256.Sum256([]byte("overflow"))
	huge := strings.Repeat("x", 0xFFFF+1)
	if _, err := SCTSigningPayload(huge, hash, 0); err == nil {
		t.Error("expected error for >65535-byte LogDID")
	}
}

func TestSCTSigningPayload_LayoutBytewise(t *testing.T) {
	// Pin the wire layout: version(1) | logDIDLen(2) | logDID | hash(32) | micros(8)
	hash := sha256.Sum256([]byte("layout"))
	buf, err := SCTSigningPayload("ab", hash, 0x0102030405060708)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	// Expected layout:
	//   buf[0]   = SCTVersion (1)
	//   buf[1:3] = 0x00 0x02 (LogDID length)
	//   buf[3:5] = "ab"
	//   buf[5:37] = hash
	//   buf[37:45] = 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08
	if buf[0] != SCTVersion {
		t.Errorf("buf[0] = %d, want %d", buf[0], SCTVersion)
	}
	if buf[1] != 0x00 || buf[2] != 0x02 {
		t.Errorf("buf[1:3] = %x, want 00 02", buf[1:3])
	}
	if string(buf[3:5]) != "ab" {
		t.Errorf("buf[3:5] = %q, want ab", buf[3:5])
	}
	if string(buf[5:37]) != string(hash[:]) {
		t.Errorf("buf[5:37] != hash")
	}
	wantTs := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if string(buf[37:45]) != string(wantTs) {
		t.Errorf("buf[37:45] = %x, want %x", buf[37:45], wantTs)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Sign / Verify round-trip
// ─────────────────────────────────────────────────────────────────────

func TestSignSCT_RoundTripVerifies(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := sha256.Sum256([]byte("round-trip"))
	sct, err := SignSCT(priv, "did:test:log", hash, time.Now().UTC())
	if err != nil {
		t.Fatalf("SignSCT: %v", err)
	}
	if err := VerifySCT(&priv.PublicKey, sct); err != nil {
		t.Errorf("VerifySCT: %v", err)
	}
}

func TestSignSCT_NilPrivErrors(t *testing.T) {
	hash := sha256.Sum256([]byte("nil-priv"))
	if _, err := SignSCT(nil, "did:test:log", hash, time.Now()); err == nil {
		t.Error("expected error for nil priv")
	}
}

func TestVerifySCT_NilGuards(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("nils"))
	sct, _ := SignSCT(priv, "did:test:log", hash, time.Now())
	if err := VerifySCT(nil, sct); err == nil {
		t.Error("expected error for nil pub")
	}
	if err := VerifySCT(&priv.PublicKey, nil); err == nil {
		t.Error("expected error for nil sct")
	}
}

func TestVerifySCT_UnsupportedVersionRejects(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("ver"))
	sct, _ := SignSCT(priv, "did:test:log", hash, time.Now())
	sct.Version = SCTVersion + 1
	if err := VerifySCT(&priv.PublicKey, sct); err == nil {
		t.Error("expected version-mismatch rejection")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tamper resistance
// ─────────────────────────────────────────────────────────────────────

func TestVerifySCT_TamperedCanonicalHashRejects(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("orig"))
	sct, _ := SignSCT(priv, "did:test:log", hash, time.Now())
	// Flip the first hex pair.
	sct.CanonicalHash = "ff" + sct.CanonicalHash[2:]
	if err := VerifySCT(&priv.PublicKey, sct); err == nil {
		t.Error("expected rejection on tampered canonical_hash")
	}
}

func TestVerifySCT_TamperedLogTimeMicrosRejects(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("ts"))
	sct, _ := SignSCT(priv, "did:test:log", hash, time.Now())
	sct.LogTimeMicros++
	if err := VerifySCT(&priv.PublicKey, sct); err == nil {
		t.Error("expected rejection on tampered log_time_micros")
	}
}

func TestVerifySCT_TamperedLogDIDRejects(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("did"))
	sct, _ := SignSCT(priv, "did:test:log", hash, time.Now())
	sct.LogDID = "did:test:other"
	if err := VerifySCT(&priv.PublicKey, sct); err == nil {
		t.Error("expected rejection on tampered log_did")
	}
}

func TestVerifySCT_LogTimeJSONIsNotSignedOver(t *testing.T) {
	// LogTime (RFC-3339) is derived for human consumption only;
	// mutating it must NOT invalidate the signature. LogTimeMicros
	// is the signed-over canonical timestamp.
	priv, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("rfc"))
	sct, _ := SignSCT(priv, "did:test:log", hash, time.Now())
	sct.LogTime = "1970-01-01T00:00:00Z"
	if err := VerifySCT(&priv.PublicKey, sct); err != nil {
		t.Errorf("LogTime mutation should not affect signature: %v", err)
	}
}

func TestVerifySCT_WrongKeyRejects(t *testing.T) {
	priv1, _ := signatures.GenerateKey()
	priv2, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("wrong-key"))
	sct, _ := SignSCT(priv1, "did:test:log", hash, time.Now())
	if err := VerifySCT(&priv2.PublicKey, sct); err == nil {
		t.Error("expected rejection when verifying with wrong key")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Decode-side robustness
// ─────────────────────────────────────────────────────────────────────

func TestVerifySCT_BadHexInCanonicalHashErrors(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("bad hex"))
	sct, _ := SignSCT(priv, "did:test:log", hash, time.Now())
	sct.CanonicalHash = "not-hex"
	if err := VerifySCT(&priv.PublicKey, sct); err == nil {
		t.Error("expected error on bad hex")
	}
}

func TestVerifySCT_WrongHashLengthErrors(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	hash := sha256.Sum256([]byte("short"))
	sct, _ := SignSCT(priv, "did:test:log", hash, time.Now())
	// 16 bytes (32 hex chars) instead of 32.
	sct.CanonicalHash = hex.EncodeToString(hash[:16])
	if err := VerifySCT(&priv.PublicKey, sct); err == nil {
		t.Error("expected length error for 16-byte hash")
	}
}
