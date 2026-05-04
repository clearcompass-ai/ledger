/*
FILE PATH: witness/serve.go

Witness cosignature endpoint. Accepts tree head cosign requests from
peer operators and returns a signature over the tree head.

Deployed when this operator acts as a witness for another log.
The signing key is the witness private key (not the operator's log key).

KEY ARCHITECTURAL DECISIONS:
  - Signs the cosign-canonical tree-head message via cosign.SignECDSA
    (universal signing surface; binds the signature to the deployment's
    NetworkID and the PurposeTreeHead domain).
  - Validates tree head is monotonically non-decreasing (no rollback).
  - Rate limited per-peer (not implemented here — middleware concern).
  - Key injected via config, never hardcoded.
  - Returns types.WitnessSignature JSON with SchemeTag=SchemeECDSA —
    the cosign verifier rejects SchemeTag==0.
*/
package witness

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/cosign"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ServeConfig configures the witness cosign endpoint.
type ServeConfig struct {
	// WitnessKey is the private key used to sign tree heads.
	// Injected from HSM/config. Never persisted in plaintext.
	WitnessKey *ecdsa.PrivateKey

	// NetworkID is the deployment's 32-byte cosign-domain identifier,
	// derived at boot from the operator's network bootstrap document
	// via network.MustNetworkID. Witnesses for the same network share
	// the same value; signatures produced under one NetworkID never
	// verify under another.
	NetworkID cosign.NetworkID

	Logger *slog.Logger
}

// CosignHandler handles POST /v1/cosign requests from peer operators.
// Implements http.Handler. Registered in api/server.go when witness
// mode is enabled (Handlers.WitnessCosign != nil).
type CosignHandler struct {
	key       *ecdsa.PrivateKey
	pubID     [32]byte // SHA-256 of uncompressed public key bytes
	networkID cosign.NetworkID
	logger    *slog.Logger

	mu             sync.Mutex
	lastSignedSize uint64 // monotonicity guard: never sign a smaller tree
}

// NewCosignHandler creates a witness cosign endpoint handler.
func NewCosignHandler(cfg ServeConfig) *CosignHandler {
	pubBytes := signatures.PubKeyBytes(&cfg.WitnessKey.PublicKey)
	pubID := sha256.Sum256(pubBytes)
	return &CosignHandler{
		key:       cfg.WitnessKey,
		pubID:     pubID,
		networkID: cfg.NetworkID,
		logger:    cfg.Logger,
	}
}

// ServeHTTP handles the cosign request.
//
// Request body (JSON):
//
//	{ "tree_size": 1000, "root_hash": "abcdef0123..." }
//
// Response body (JSON): types.WitnessSignature
//
//	{ "pub_key_id": "...", "sig_bytes": "..." }
//
// Error responses:
//
//	405 — wrong HTTP method
//	400 — malformed JSON, missing fields, bad hex
//	409 — tree_size rollback rejected (monotonicity guard)
//	500 — signing failure
func (h *CosignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		TreeSize uint64 `json:"tree_size"`
		RootHash string `json:"root_hash"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.TreeSize == 0 {
		http.Error(w, `{"error":"tree_size must be positive"}`, http.StatusBadRequest)
		return
	}

	// Parse root hash — must be exactly 64 hex characters (32 bytes).
	var rootHash [32]byte
	rootBytes, err := hexDecodeExact(req.RootHash, 32)
	if err != nil {
		http.Error(w, `{"error":"root_hash must be 64 hex chars"}`, http.StatusBadRequest)
		return
	}
	copy(rootHash[:], rootBytes)

	// Monotonicity guard: never sign a smaller tree than previously signed.
	// This prevents a malicious operator from requesting cosignatures on
	// rolled-back state. The guard is per-process (resets on restart).
	h.mu.Lock()
	if req.TreeSize < h.lastSignedSize {
		h.mu.Unlock()
		h.logger.Warn("cosign: rejected rollback attempt",
			"requested", req.TreeSize, "last_signed", h.lastSignedSize)
		http.Error(w, `{"error":"tree_size rollback rejected"}`, http.StatusConflict)
		return
	}
	h.lastSignedSize = req.TreeSize
	h.mu.Unlock()

	// Sign the cosign-canonical tree-head message via cosign.SignECDSA.
	// The canonical bytes are [purpose-prefix][NUL][NetworkID][HashAlgo]
	// [RootHash][TreeSize-BE]; cosign hashes them with SHA-256 and
	// signs the digest with secp256k1 ECDSA. Binding to NetworkID +
	// PurposeTreeHead is what makes the signature non-replayable
	// across networks or against a rotation message.
	head := types.TreeHead{TreeSize: req.TreeSize, RootHash: rootHash}
	payload := cosign.NewTreeHeadPayload(head)
	sigBytes, err := cosign.SignECDSA(payload, h.networkID, cosign.HashAlgoSHA256, h.key)
	if err != nil {
		h.logger.Error("cosign: signing failed", "error", err)
		http.Error(w, `{"error":"signing failed"}`, http.StatusInternalServerError)
		return
	}

	// Return WitnessSignature as JSON. SchemeTag is mandatory: the
	// cosign verifier rejects SchemeTag==0 with ErrSchemeUnspecified.
	resp := types.WitnessSignature{
		PubKeyID:  h.pubID,
		SchemeTag: signatures.SchemeECDSA,
		SigBytes:  sigBytes,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	h.logger.Info("cosigned tree head",
		"tree_size", req.TreeSize,
		"root_hash", req.RootHash[:min(16, len(req.RootHash))])
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex helpers (no encoding/hex import needed for this simple case)
// ─────────────────────────────────────────────────────────────────────────────

// hexDecodeExact decodes a hex string and verifies exact byte length.
func hexDecodeExact(s string, expectedLen int) ([]byte, error) {
	if len(s) != expectedLen*2 {
		return nil, fmt.Errorf("expected %d hex chars, got %d", expectedLen*2, len(s))
	}
	b := make([]byte, expectedLen)
	for i := 0; i < expectedLen; i++ {
		hi := unhex(s[i*2])
		lo := unhex(s[i*2+1])
		if hi == 0xFF || lo == 0xFF {
			return nil, fmt.Errorf("invalid hex at position %d", i*2)
		}
		b[i] = hi<<4 | lo
	}
	return b, nil
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xFF
	}
}
