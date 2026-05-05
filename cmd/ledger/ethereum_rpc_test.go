/*
FILE PATH: cmd/ledger/ethereum_rpc_test.go

DESCRIPTION:

	Tests LoadEthereumRPCConfig and BuildEthereumRPCClient. Covers:
	  - default-disabled (zero env vars).
	  - enable + endpoint contract.
	  - https-only enforcement (refuse http:// without explicit opt-in).
	  - timeout default and override.
	  - construction returns nil when disabled.
	  - construction succeeds and returns a non-nil client when enabled.
	  - the constructed client satisfies the SDK's
	    EthereumRPCClient interface (compile-time + structural check).
	  - SDK-level URL-scheme rejection bubbles up wrapped (defense-
	    in-depth: even if the ledger-side check is bypassed, the
	    SDK refuses an http:// endpoint).

NOTES:

	Each test sets and unsets the four env vars explicitly. We avoid
	t.Setenv only because the helper functions live in package main
	and we want the env-isolation semantics to be obvious to the
	reader.
*/
package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	sdkcryptosigs "github.com/clearcompass-ai/attesta/crypto/signatures"
)

// withEthEnv sets all four LEDGER_ETH_RPC_* env vars and returns a
// cleanup. Empty values set the var to "" (Setenv "" still defines
// the var; for our parser that's equivalent to unset because we test
// for "true" / non-empty explicitly).
func withEthEnv(t *testing.T, enabled, endpoint, timeoutMS, allowHTTP string) {
	t.Helper()
	t.Setenv("LEDGER_ETH_RPC_ENABLED", enabled)
	t.Setenv("LEDGER_ETH_RPC_ENDPOINT", endpoint)
	t.Setenv("LEDGER_ETH_RPC_TIMEOUT_MS", timeoutMS)
	t.Setenv("LEDGER_ETH_RPC_ALLOW_HTTP", allowHTTP)
}

// ─── LoadEthereumRPCConfig ─────────────────────────────────────

func TestLoadEthereumRPCConfig_DefaultDisabled(t *testing.T) {
	withEthEnv(t, "", "", "", "")
	cfg, err := LoadEthereumRPCConfig()
	if err != nil {
		t.Fatalf("default (no env) MUST succeed and yield disabled; got err=%v", err)
	}
	if cfg.Enabled {
		t.Error("default Enabled MUST be false")
	}
}

func TestLoadEthereumRPCConfig_EnabledRequiresEndpoint(t *testing.T) {
	withEthEnv(t, "true", "", "", "")
	_, err := LoadEthereumRPCConfig()
	if !errors.Is(err, ErrEthereumRPCEndpointRequired) {
		t.Fatalf("ENABLED=true with empty ENDPOINT MUST surface ErrEthereumRPCEndpointRequired; got %v", err)
	}
}

func TestLoadEthereumRPCConfig_HTTPSAccepted(t *testing.T) {
	withEthEnv(t, "true", "https://eth-mainnet.g.alchemy.com/v2/keytoken", "", "")
	cfg, err := LoadEthereumRPCConfig()
	if err != nil {
		t.Fatalf("https endpoint MUST succeed; got %v", err)
	}
	if !cfg.Enabled {
		t.Error("Enabled MUST be true after parsing")
	}
	if !strings.HasPrefix(cfg.Endpoint, "https://") {
		t.Errorf("Endpoint round-trip mismatch: %q", cfg.Endpoint)
	}
}

func TestLoadEthereumRPCConfig_HTTPRejectedByDefault(t *testing.T) {
	withEthEnv(t, "true", "http://127.0.0.1:8545", "", "")
	_, err := LoadEthereumRPCConfig()
	if !errors.Is(err, ErrEthereumRPCInsecureEndpoint) {
		t.Fatalf("http:// without ALLOW_HTTP=true MUST surface ErrEthereumRPCInsecureEndpoint; got %v", err)
	}
}

func TestLoadEthereumRPCConfig_HTTPAcceptedWithExplicitOptIn(t *testing.T) {
	withEthEnv(t, "true", "http://127.0.0.1:8545", "", "true")
	cfg, err := LoadEthereumRPCConfig()
	if err != nil {
		t.Fatalf("http:// with ALLOW_HTTP=true MUST succeed (local-dev only); got %v", err)
	}
	if !cfg.AllowInsecureHTTP {
		t.Error("AllowInsecureHTTP MUST be true after explicit opt-in")
	}
}

func TestLoadEthereumRPCConfig_HTTPSchemeIsCaseInsensitive(t *testing.T) {
	// "HTTP://..." is still http; check the lowercase comparison.
	withEthEnv(t, "true", "HTTP://127.0.0.1:8545", "", "")
	_, err := LoadEthereumRPCConfig()
	if !errors.Is(err, ErrEthereumRPCInsecureEndpoint) {
		t.Fatalf("uppercase HTTP:// MUST also reject without ALLOW_HTTP; got %v", err)
	}
}

func TestLoadEthereumRPCConfig_DefaultTimeout(t *testing.T) {
	withEthEnv(t, "true", "https://example.com", "", "")
	cfg, err := LoadEthereumRPCConfig()
	if err != nil {
		t.Fatalf("LoadEthereumRPCConfig: %v", err)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("default timeout: want 5s, got %v", cfg.Timeout)
	}
}

func TestLoadEthereumRPCConfig_TimeoutOverride(t *testing.T) {
	withEthEnv(t, "true", "https://example.com", "12345", "")
	cfg, err := LoadEthereumRPCConfig()
	if err != nil {
		t.Fatalf("LoadEthereumRPCConfig: %v", err)
	}
	if cfg.Timeout != 12345*time.Millisecond {
		t.Errorf("timeout override: want 12345ms, got %v", cfg.Timeout)
	}
}

func TestLoadEthereumRPCConfig_DisabledIgnoresOtherFields(t *testing.T) {
	// When ENABLED is false, the other env vars are irrelevant —
	// not even an "endpoint required" check fires. The ledger
	// runs in EOA-only mode regardless of the noise.
	withEthEnv(t, "false", "", "", "")
	cfg, err := LoadEthereumRPCConfig()
	if err != nil {
		t.Fatalf("disabled MUST succeed regardless of endpoint absence; got %v", err)
	}
	if cfg.Enabled {
		t.Error("disabled MUST yield Enabled=false")
	}
}

// ─── BuildEthereumRPCClient ────────────────────────────────────

func TestBuildEthereumRPCClient_DisabledReturnsNil(t *testing.T) {
	rpc, err := BuildEthereumRPCClient(EthereumRPCConfig{Enabled: false})
	if err != nil {
		t.Fatalf("disabled config MUST NOT error; got %v", err)
	}
	if rpc != nil {
		t.Error("disabled config MUST return nil client")
	}
}

func TestBuildEthereumRPCClient_HTTPSConstructsClient(t *testing.T) {
	rpc, err := BuildEthereumRPCClient(EthereumRPCConfig{
		Enabled:  true,
		Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("https endpoint MUST succeed; got %v", err)
	}
	if rpc == nil {
		t.Fatal("rpc client MUST be non-nil after successful construction")
	}
	// Compile-time: rpc satisfies sdkcryptosigs.EthereumRPCClient.
	var _ sdkcryptosigs.EthereumRPCClient = rpc
}

func TestBuildEthereumRPCClient_HTTPWithoutOptInRejectedBySDK(t *testing.T) {
	// Defense-in-depth: even if a misconfigured test bypasses the
	// ledger-side gate (e.g., constructs the config struct
	// directly with Enabled=true, http endpoint, AllowInsecureHTTP
	// false), the SDK's own NewHTTPEthereumRPC enforces the
	// http-or-explicit-opt-in invariant.
	rpc, err := BuildEthereumRPCClient(EthereumRPCConfig{
		Enabled:           true,
		Endpoint:          "http://127.0.0.1:8545",
		Timeout:           5 * time.Second,
		AllowInsecureHTTP: false,
	})
	if err == nil {
		t.Fatal("SDK-level check MUST reject http:// without ALLOW_HTTP")
	}
	if rpc != nil {
		t.Error("rpc client MUST be nil on error")
	}
	if !errors.Is(err, sdkcryptosigs.ErrInsecureURL) {
		t.Errorf("error MUST wrap sdkcryptosigs.ErrInsecureURL; got %v", err)
	}
}

func TestBuildEthereumRPCClient_HTTPWithOptInAccepted(t *testing.T) {
	rpc, err := BuildEthereumRPCClient(EthereumRPCConfig{
		Enabled:           true,
		Endpoint:          "http://127.0.0.1:8545",
		Timeout:           5 * time.Second,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("http:// with AllowInsecureHTTP MUST succeed (local-dev); got %v", err)
	}
	if rpc == nil {
		t.Fatal("rpc client MUST be non-nil")
	}
}

// ─── End-to-end: env -> config -> client ───────────────────────

func TestEthereumRPC_EndToEnd_HappyPath(t *testing.T) {
	withEthEnv(t, "true", "https://example.com/v2/key", "3000", "")
	cfg, err := LoadEthereumRPCConfig()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rpc, err := BuildEthereumRPCClient(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rpc == nil {
		t.Fatal("end-to-end happy path MUST yield non-nil client")
	}
	if cfg.Timeout != 3*time.Second {
		t.Errorf("timeout round-trip: want 3s, got %v", cfg.Timeout)
	}
}

func TestEthereumRPC_EndToEnd_DisabledYieldsNilClient(t *testing.T) {
	withEthEnv(t, "false", "https://example.com", "", "")
	cfg, err := LoadEthereumRPCConfig()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rpc, err := BuildEthereumRPCClient(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rpc != nil {
		t.Error("disabled end-to-end MUST yield nil client (no network surface)")
	}
}
