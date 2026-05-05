/*
FILE PATH: admission/static_witness_key_set.go

StaticWitnessKeySet — minimal WitnessKeySet implementation
backed by an immutable slice of types.WitnessPublicKey + a
fixed K threshold. Constructed once at ledger startup from
the network bootstrap document's GenesisWitnessSet (resolved
to public keys by gossipnet.WitnessKeysFromDIDs) and shared
across every admission request.

# WHY STATIC

The genesis witness set is fixed at NetworkID derivation —
changing it would change the NetworkID and break every signed
event ever produced under it. Witness rotation lives at a
different layer (KindOriginatorRotation gossip events for
ledger DIDs; witness key rotation is a v0.10.0+ concern).
Static suffices for the v0.9.6 admission verifier.

# THREAD SAFETY

The keys slice is created at startup and never mutated. Active()
returns a defensive shallow copy so the caller can't mutate the
authoritative slice through the returned reference.
*/
package admission

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/types"
)

// StaticWitnessKeySet implements the WitnessKeySet interface with
// a fixed list of witness public keys + a constant K-of-N threshold.
type StaticWitnessKeySet struct {
	keys []types.WitnessPublicKey
	quorumK int
}

// NewStaticWitnessKeySet constructs the provider. Returns an
// error when keys is empty or quorumK is out of range
// (1 <= K <= len(keys)).
func NewStaticWitnessKeySet(
	keys []types.WitnessPublicKey, quorumK int,
) (*StaticWitnessKeySet, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf(
			"admission/static_witness_key_set: keys must be non-empty")
	}
	if quorumK <= 0 {
		return nil, fmt.Errorf(
			"admission/static_witness_key_set: quorumK must be > 0, got %d", quorumK)
	}
	if quorumK > len(keys) {
		return nil, fmt.Errorf(
			"admission/static_witness_key_set: quorumK %d > len(keys) %d (impossible quorum)",
			quorumK, len(keys))
	}
	return &StaticWitnessKeySet{
		keys:    append([]types.WitnessPublicKey{}, keys...),
		quorumK: quorumK,
	}, nil
}

// Active implements WitnessKeySet. Returns a defensive shallow
// copy of the keys slice so callers can't mutate the
// authoritative state through the returned reference.
func (s *StaticWitnessKeySet) Active() (
	keys []types.WitnessPublicKey, quorumK int, err error,
) {
	out := make([]types.WitnessPublicKey, len(s.keys))
	copy(out, s.keys)
	return out, s.quorumK, nil
}

// Static interface check.
var _ WitnessKeySet = (*StaticWitnessKeySet)(nil)
