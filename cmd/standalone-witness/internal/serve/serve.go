/*
FILE PATH: cmd/standalone-witness/internal/serve/serve.go

Witness cosignature endpoint construction. Wraps the SDK's universal
cosign handler (cosign.NewWitnessHandler) with the witness daemon's
local monotonicity guard that refuses to cosign a tree head smaller
than the largest tree head this process has previously signed.

# WHY THIS LIVES INSIDE cmd/standalone-witness/internal

Per the architectural separation: this is witness-daemon application
state and middleware. It is not a library the Ledger consumes — the
Ledger does not act as a witness. Placing the code under
cmd/standalone-witness/internal/ has two effects:

  1. Go's compiler refuses imports of internal/ packages from outside
     cmd/standalone-witness/. The Ledger's cmd/ledger/ tree
     physically cannot reach this code.

  2. cmd/standalone-witness/ has its OWN go.mod (Go-workspace
     governed at the repo root). This module never imports
     github.com/clearcompass-ai/ledger; the boundary is enforced
     before linting can even run.

# WHAT THE WRAPPER ADDS OVER cosign.NewWitnessHandler

The SDK ships a wire-complete cosign handler — JSON parsing,
network/purpose/hash-algo validation, payload decoding, signing,
response encoding. It does not encode WITNESS-DEPLOYMENT-LOCAL rules
like "refuse rollbacks", because such rules are deployment-specific
and the SDK is the universal contract.

This file adds:

  - Monotonicity middleware: never cosign a tree_size strictly
    smaller than this process's lastSignedSize. Per-process state;
    resets on restart by design — the wraparound risk on restart is
    accepted in exchange for not depending on persistent state for
    a defense-in-depth check. The authoritative non-rollback
    guarantee is upstream (the Ledger's per-originator hash chain +
    Tessera log layer; the witness's local guard is belt-and-braces).

# MONOTONICITY MIDDLEWARE

A pre-handler middleware reads the request body once (capped at
the SDK's MaxRequestBytes), peeks at the cosign.WireRequest's
purpose field, and for PurposeTreeHead extracts the embedded
tree_size. On rollback the response is 409 Conflict + a
WireError-shaped JSON body. On non-tree-head purposes (rotation,
escrow override) the middleware passes through unchanged.

Body re-injection: the middleware replaces r.Body with a
bytes.Reader over the buffered bytes so the SDK handler reads the
same content. No mutation of headers or method.

State semantics: lastSignedSize advances at middleware entry on
the optimistic assumption that the SDK handler will accept the
request. If the SDK rejects for a downstream reason (bad network,
malformed payload), lastSignedSize stays advanced — a rollback
attempt at exactly the rejected size becomes a no-op next time.
*/
package serve

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
)

// Config configures the witness cosign endpoint.
type Config struct {
	// WitnessKey is the ECDSA private key used to sign tree heads.
	// Injected from HSM/config. Never persisted in plaintext.
	// BLS witnesses inject a different signer via BuildSigner.
	WitnessKey *ecdsa.PrivateKey

	// NetworkID is the deployment's 32-byte cosign-domain identifier,
	// derived at boot from the network bootstrap document. Witnesses
	// for the same network share the same value; signatures produced
	// under one NetworkID never verify under another.
	NetworkID cosign.NetworkID

	// AllowedPurposes optionally narrows the signing surface. nil ⇒
	// accept any registered Purpose. Witnesses wishing to deploy a
	// "tree-head-only" role pass {cosign.PurposeTreeHead: {}}.
	AllowedPurposes map[cosign.Purpose]struct{}

	// MaxRequestBytes caps request body size. <= 0 ⇒
	// cosign.DefaultMaxRequestBytes (64 KiB).
	MaxRequestBytes int64

	Logger *slog.Logger
}

// Build constructs the witness cosign handler ready to mount at
// POST /v1/cosign. Wraps cosign.NewWitnessHandler with the
// monotonicity guard.
//
// Returns an error if the SDK handler factory rejects the config
// (zero NetworkID, missing signer, etc.).
func Build(cfg Config) (http.Handler, error) {
	if cfg.WitnessKey == nil {
		return nil, fmt.Errorf("standalone-witness/serve: WitnessKey required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	signer := cosign.NewECDSAWitnessSigner(cfg.WitnessKey)
	return BuildSigner(signer, cfg)
}

// BuildSigner is the BLS-or-custom-signer variant. Witnesses with
// HSM-backed BLS keys construct a custom cosign.WitnessSigner and
// pass it here.
func BuildSigner(signer cosign.WitnessSigner, cfg Config) (http.Handler, error) {
	if signer == nil {
		return nil, fmt.Errorf("standalone-witness/serve: signer required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	maxBytes := cfg.MaxRequestBytes
	if maxBytes <= 0 {
		maxBytes = cosign.DefaultMaxRequestBytes
	}

	inner, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
		Signer:          signer,
		AllowedNetworks: map[cosign.NetworkID]struct{}{cfg.NetworkID: {}},
		AllowedPurposes: cfg.AllowedPurposes,
		MaxRequestBytes: maxBytes,
		Logger:          cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("standalone-witness/serve: build SDK handler: %w", err)
	}
	guard := newMonotonicityGuard(maxBytes, cfg.Logger)
	return guard(inner), nil
}

// newMonotonicityGuard returns middleware that rejects tree-head
// rollbacks with 409 Conflict before the inner handler sees the
// request. Per-process state. Other purposes pass through.
func newMonotonicityGuard(maxBytes int64, logger *slog.Logger) func(http.Handler) http.Handler {
	var (
		mu             sync.Mutex
		lastSignedSize uint64
	)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes))
			if err != nil {
				writeError(w, http.StatusBadRequest, "read body failed")
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))

			var req cosign.WireRequest
			if jsonErr := json.Unmarshal(body, &req); jsonErr != nil {
				next.ServeHTTP(w, r)
				return
			}

			if req.Purpose != cosign.PurposeTreeHead {
				next.ServeHTTP(w, r)
				return
			}

			var th cosign.WireTreeHeadPayload
			if jsonErr := json.Unmarshal(req.Payload, &th); jsonErr != nil {
				next.ServeHTTP(w, r)
				return
			}

			mu.Lock()
			if th.TreeSize < lastSignedSize {
				prev := lastSignedSize
				mu.Unlock()
				logger.Warn("cosign: rejected rollback attempt",
					"requested", th.TreeSize, "last_signed", prev)
				writeError(w, http.StatusConflict,
					fmt.Sprintf("tree_size rollback rejected: requested=%d last_signed=%d",
						th.TreeSize, prev))
				return
			}
			lastSignedSize = th.TreeSize
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

// writeError emits a WireError-shaped JSON response so callers
// parse a single error envelope across SDK + monotonicity
// rejections.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(cosign.WireError{Error: message})
}
