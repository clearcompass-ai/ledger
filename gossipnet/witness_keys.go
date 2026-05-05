/*
FILE PATH: gossipnet/witness_keys.go

WitnessKeysFromBootstrap resolves the GenesisWitnessSet (a slice
of did:key DIDs in the network bootstrap document) into the
[]types.WitnessPublicKey shape consumed by witness.DetectEquivocation
and EquivocationMonitor.

# WHY THIS HELPER EXISTS

network.BootstrapDocument carries witness identities as DIDs
(did:key form). The cosign verifier wants WitnessPublicKey
records (32-byte ID + raw public-key bytes). Bridging the two is
mechanical (parse the did:key, extract pub-key bytes, compute
SHA-256 of the uncompressed bytes for the ID) but error-prone
without a single canonical helper.

# DERIVATION

Per witness DID:

	pubBytes, _ = did.ParseDIDKey(witnessDID)
	pubKeyID    = SHA-256(pubBytes)            // matches signatures.PubKeyBytes hash form

For ECDSA secp256k1 keys: ParseDIDKey returns the COMPRESSED
33-byte form. The witness signing path (cosign.NewECDSAWitnessSigner)
hashes the UNCOMPRESSED 65-byte form via signatures.PubKeyBytes.
We must match that derivation exactly so the PubKeyID resolved
here matches the PubKeyID embedded in incoming signatures.

# UNSUPPORTED METHODS

Only did:key witnesses are supported here. did:web witnesses
require an HTTP fetch + JSON-LD verification document parse
that is out of scope for this helper. Production deployments
using did:web witnesses pass an explicit []types.WitnessPublicKey
slice constructed from their own DID resolver.
*/
package gossipnet

import (
	"crypto/sha256"
	"fmt"

	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/types"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// WitnessKeysFromDIDs resolves a slice of witness DIDs into the
// flat WitnessPublicKey form. Returns an error on the first
// unresolvable DID; partial results are not surfaced (a
// half-resolved witness set is worse than a hard failure at
// startup).
//
// Each DID's resolved public key bytes are hashed (SHA-256 of the
// uncompressed form) to populate WitnessPublicKey.ID — matching
// the derivation cosign.NewECDSAWitnessSigner uses for its own
// PubKeyID. Without this match, signatures from honest witnesses
// would be rejected as "unknown public key".
func WitnessKeysFromDIDs(dids []string) ([]types.WitnessPublicKey, error) {
	if len(dids) == 0 {
		return nil, fmt.Errorf("gossipnet/witness_keys: empty DID list")
	}
	out := make([]types.WitnessPublicKey, 0, len(dids))
	seen := make(map[[32]byte]bool, len(dids))
	for _, witnessDID := range dids {
		if witnessDID == "" {
			return nil, fmt.Errorf("gossipnet/witness_keys: empty DID in list")
		}
		pubBytes, _, err := did.ParseDIDKey(witnessDID)
		if err != nil {
			return nil, fmt.Errorf("gossipnet/witness_keys: ParseDIDKey(%s): %w",
				witnessDID, err)
		}
		uncompressed, err := uncompressSecp256k1(pubBytes)
		if err != nil {
			return nil, fmt.Errorf(
				"gossipnet/witness_keys: uncompress %s: %w", witnessDID, err)
		}
		id := sha256.Sum256(uncompressed)
		if seen[id] {
			return nil, fmt.Errorf("gossipnet/witness_keys: duplicate witness key id (DID %s)",
				witnessDID)
		}
		seen[id] = true
		out = append(out, types.WitnessPublicKey{
			ID:        id,
			PublicKey: uncompressed,
		})
	}
	return out, nil
}

// uncompressSecp256k1 converts a 33-byte compressed secp256k1
// pubkey to the 65-byte uncompressed form (0x04 || X || Y) so
// the SHA-256 ID derivation matches signatures.PubKeyBytes —
// the form NewECDSAWitnessSigner.PubKeyID hashes.
//
// Accepts already-uncompressed 65-byte input as a passthrough
// (ledgers with explicit public-key files can supply either
// form via WitnessKeysFromDIDs's parsing path).
func uncompressSecp256k1(b []byte) ([]byte, error) {
	switch len(b) {
	case 65:
		if b[0] != 0x04 {
			return nil, fmt.Errorf("expected 0x04 prefix on uncompressed form, got 0x%02x", b[0])
		}
		return b, nil
	case 33:
		// fallthrough — decompress below
	default:
		return nil, fmt.Errorf("expected 33-byte compressed or 65-byte uncompressed, got %d", len(b))
	}
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("ParsePubKey: %w", err)
	}
	x, y := pub.X(), pub.Y()
	// secp256k1's custom curve doesn't ship via crypto/elliptic,
	// so we marshal the uncompressed form manually with the same
	// fixed-width 0x04 || X(32B) || Y(32B) layout as
	// signatures.PubKeyBytes uses for the std ecdsa.PublicKey
	// path. Matching that derivation byte-for-byte is what makes
	// the resulting SHA-256 PubKeyID equal across the witness's
	// own signer-side hash and our verifier-side hash.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	xb := x.Bytes()
	yb := y.Bytes()
	copy(uncompressed[1+(32-len(xb)):33], xb)
	copy(uncompressed[33+(32-len(yb)):65], yb)
	return uncompressed, nil
}
