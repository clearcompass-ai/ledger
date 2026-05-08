/*
FILE PATH:

	lifecycle/logsafe.go

DESCRIPTION:

	D6 — Slog redaction policy + helpers. Establishes the
	privacy contract for the entire ledger:

	    NEVER LOG:
	        - raw entry payloads (user-supplied bytes)
	        - signatures, MACs, witness keys, signer keys
	        - bearer tokens, session tokens, API keys
	        - the `secret_data` field of any envelope

	    ALWAYS LOGGABLE (per ledger principles):
	        - canonical hashes (SHA-256 hex prefix)
	        - signer DIDs (public)
	        - sequence numbers
	        - log_time (admission timestamp)
	        - tree_size, root_hash hex prefix
	        - public NetworkID hex prefix
	        - error_class taxonomy values

KEY ARCHITECTURAL DECISIONS:
  - Helpers are pure (no side effects, no allocation beyond
    output strings) so they're safe to call from hot paths.
  - HashHex returns the first 16 hex chars of SHA-256(bytes) —
    enough entropy for log-correlation, not enough to recover
    the source bytes. A full 64-char hex is overkill in logs.
  - PresenceFlag returns "set" or "unset" so the administrator can
    confirm a secret-shaped field was supplied without
    exposing content (used by the LogInfo handler in api/info.go).
  - These helpers are the SOLE sanctioned way for production
    code to log byte-shaped material. A grep for "raw" or
    "signature" or "secret" in non-test source code that ALSO
    passes a byte slice or string of plausible secret content
    to slog is a code-review red flag.

OVERVIEW:

	Use HashHex when correlating logs to a specific entry:

	    logger.Info("entry admitted",
	        "hash", logsafe.HashHex(canonicalHash[:]),
	        "signer_did", entry.SignerDID,
	        "seq", seq,
	    )

	Use PresenceFlag when reporting on the existence of a
	configured secret without exposing its content:

	    logger.Info("postgres pool ready",
	        "database_url", logsafe.PresenceFlag(cfg.DatabaseURL),
	    )

	Use NetworkIDHex for the deployment's NetworkID prefix:

	    logger.Info("ledger booting",
	        "network_id_hex", logsafe.NetworkIDHex(networkID[:]),
	    )

KEY DEPENDENCIES:
  - crypto/sha256: domain-separated hashing for HashHex.
  - encoding/hex: hex encoding (a hot-path-safe primitive).
*/
package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// HashHexPrefixBytes is the byte length of the SHA-256 prefix
// returned by HashHex. 8 bytes (16 hex chars) is enough entropy
// for log-correlation across millions of entries — collision
// probability ~1 in 2^32 at 1 M entries, which is acceptable for
// log-correlation (not for cryptographic uniqueness).
const HashHexPrefixBytes = 8

// -------------------------------------------------------------------------------------------------
// 2) Helpers
// -------------------------------------------------------------------------------------------------

// HashHex returns the first HashHexPrefixBytes (default 8 bytes
// = 16 hex chars) of SHA-256(b). Use this when correlating logs
// to a specific entry / payload without exposing the source bytes.
//
// Length-extension safe: SHA-256 prefix is one-way, an attacker
// reading the log cannot recover the source bytes from the
// 16-char prefix.
//
// Returns "" for empty input so the field is empty rather than
// hashing-the-empty-string in logs.
func HashHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:HashHexPrefixBytes])
}

// PresenceFlag returns "set" if s is non-empty, "unset" otherwise.
// Use this when reporting on the existence of a secret-shaped
// configuration field (DSN, key file path, access key) without
// exposing the content. Same pattern as the api.LogInfo handler.
func PresenceFlag(s string) string {
	if s == "" {
		return "unset"
	}
	return "set"
}

// NetworkIDHex returns the first HashHexPrefixBytes hex chars of
// a NetworkID — the deployment-correlation prefix that pairs
// across administrators / auditors / witnesses. Returns "" for an
// all-zero NetworkID so a fresh-boot ledger doesn't log a
// misleading hex prefix.
//
// Operates on []byte (not [32]byte) so callers don't need a
// type-specific helper for each cosign.NetworkID variation.
func NetworkIDHex(networkID []byte) string {
	allZero := true
	for _, b := range networkID {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	if len(networkID) <= HashHexPrefixBytes {
		return hex.EncodeToString(networkID)
	}
	return hex.EncodeToString(networkID[:HashHexPrefixBytes])
}

// HexShort returns the first HashHexPrefixBytes hex chars of
// already-hex-encoded data. Use when the input is itself a hex
// string (e.g., a fully-hex-encoded canonical hash from
// store/entries.go). Returns "" for empty input.
func HexShort(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= HashHexPrefixBytes*2 {
		return s
	}
	return s[:HashHexPrefixBytes*2]
}
