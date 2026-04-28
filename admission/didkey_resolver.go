/*
FILE PATH: admission/didkey_resolver.go

DIDKeyResolver — local-only resolver for did:key:... identifiers.
Satisfies the DIDResolver interface admission's signature verifier
consumes (ResolvePublicKey(ctx, did) → *ecdsa.PublicKey, error).

Supported curves (ECDSA only — admission's verifier uses
*ecdsa.PublicKey):
  - secp256k1 (multicodec 0xe7 0x01)
  - P-256     (multicodec 0x12 0x00)

Ed25519 keys (multicodec 0xed 0x01) are explicitly rejected: they
are EdDSA, not ECDSA, and would never satisfy
signatures.VerifyEntry. A signer that needs Ed25519 must use a
different DID method or a different verifier path.

NETWORK: none. did:key is self-contained — the public key is
embedded in the identifier and recovered by base58 + multicodec
decoding. No HTTP fetches, no DNS, no caching needed.

WIRING: cmd/operator/main.go installs this as the default
Identity.DIDResolver. Operators that need richer methods
(did:web, did:pkh) compose a multi-method resolver in main.go and
this adapter remains the secp256k1 / P-256 leaf.
*/
package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// DIDKeyResolver resolves did:key:... identifiers to *ecdsa.PublicKey.
// Stateless; safe to share across goroutines.
type DIDKeyResolver struct{}

// NewDIDKeyResolver returns a resolver for the did:key method.
func NewDIDKeyResolver() *DIDKeyResolver { return &DIDKeyResolver{} }

// ResolvePublicKey decodes the did:key identifier and returns the
// embedded ECDSA public key. Returns an error for unsupported
// methods, unsupported curves, or malformed identifiers.
func (r *DIDKeyResolver) ResolvePublicKey(_ context.Context, didStr string) (*ecdsa.PublicKey, error) {
	pubBytes, vmType, err := did.ParseDIDKey(didStr)
	if err != nil {
		return nil, fmt.Errorf("admission/didkey: %w", err)
	}
	switch vmType {
	case did.VerificationMethodSecp256k1:
		// SDK helper handles both 33-byte compressed and 65-byte
		// uncompressed forms; did:key always carries compressed.
		return signatures.ParsePubKey(pubBytes)
	case did.VerificationMethodP256:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubBytes)
		if x == nil {
			return nil, errors.New("admission/didkey: P-256 unmarshal failed (point not on curve)")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case did.VerificationMethodEd25519:
		return nil, errors.New("admission/didkey: Ed25519 keys cannot be resolved as ECDSA — use secp256k1 or P-256")
	default:
		return nil, fmt.Errorf("admission/didkey: unsupported verification method %q", vmType)
	}
}
