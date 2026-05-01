/*
FILE PATH: cmd/operator/ethereum_rpc.go

DESCRIPTION:
    Operator-side configuration and construction for the SDK's
    EthereumRPCClient. Used to enable EIP-1271 (smart-contract-wallet)
    signature verification end-to-end. When EIP-1271 is enabled the
    operator constructs an HTTP JSON-RPC client at startup and passes
    it to did.DefaultVerifierRegistryWithRPC; when disabled the
    operator runs in EOA-only mode (the existing behavior, no network
    surface added).

KEY ARCHITECTURAL DECISIONS:
  - Strict three-tier env-var contract:
      OPERATOR_ETH_RPC_ENABLED        (true/false; default false)
      OPERATOR_ETH_RPC_ENDPOINT       (https URL; required when enabled)
      OPERATOR_ETH_RPC_TIMEOUT_MS     (int ms; default 5000)
      OPERATOR_ETH_RPC_ALLOW_HTTP     (true/false; default false)
    "enabled" is the master switch — flipping it on without
    OPERATOR_ETH_RPC_ENDPOINT is a startup error, not a silent
    degrade-to-disabled.
  - HTTPS-only by default. http:// endpoints are rejected at startup
    unless OPERATOR_ETH_RPC_ALLOW_HTTP=true is set explicitly. This
    is the same default the SDK's NewHTTPEthereumRPC enforces; the
    operator surfaces the gate at config-load time so misconfigured
    deployments fail fast (not after the first EIP-1271 traffic).
  - Production endpoints (Alchemy, Infura, QuickNode) embed an API
    key in the URL path. The operator NEVER logs the endpoint; the
    SDK's NewHTTPEthereumRPC redacts it from error messages too.
    Operators audit the configured endpoint via secret-management,
    not stdout.

OVERVIEW:
    EthereumRPCConfig          — the parsed env-var config
    LoadEthereumRPCConfig      — populate from environment
    BuildEthereumRPCClient     — construct *HTTPEthereumRPC; returns
                                 (nil, nil) when disabled, (rpc, nil)
                                 on success, (nil, err) on misconfig

KEY DEPENDENCIES:
  - github.com/clearcompass-ai/ortholog-sdk/crypto/signatures:
    EthereumRPCClient + HTTPEthereumRPC + options.
*/
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	sdkcryptosigs "github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// defaultEthereumRPCTimeoutMS is the default per-request timeout in
// milliseconds when OPERATOR_ETH_RPC_TIMEOUT_MS is unset. 5000ms is
// the SDK default and a reasonable middle ground for live signature
// verification against any major provider.
const defaultEthereumRPCTimeoutMS = 5000

// -------------------------------------------------------------------------------------------------
// 2) Config
// -------------------------------------------------------------------------------------------------

// EthereumRPCConfig is the parsed environment-variable configuration
// for the operator's EthereumRPCClient construction at startup.
//
// Disabled-by-default: a freshly-deployed operator with NO eth-RPC
// env vars set runs in EOA-only mode and pulls zero network surface.
type EthereumRPCConfig struct {
	// Enabled is the master switch. When false (the default), the
	// operator does NOT construct an EthereumRPCClient and EIP-1271
	// verification is unsupported. Production deployments that
	// accept smart-contract-wallet signers MUST set this to true.
	Enabled bool

	// Endpoint is the JSON-RPC endpoint URL. Required when Enabled
	// is true. https:// is required unless AllowInsecureHTTP is set.
	Endpoint string

	// Timeout is the per-request timeout. Applies to the full
	// JSON-RPC request lifecycle (dial + write + read). Default:
	// 5 seconds.
	Timeout time.Duration

	// AllowInsecureHTTP opts in to http:// endpoints. Local-dev
	// only. Production MUST keep this false.
	AllowInsecureHTTP bool
}

// -------------------------------------------------------------------------------------------------
// 3) Errors
// -------------------------------------------------------------------------------------------------

// ErrEthereumRPCEndpointRequired is returned when
// OPERATOR_ETH_RPC_ENABLED=true but OPERATOR_ETH_RPC_ENDPOINT is
// empty. Operators that want EIP-1271 must supply an endpoint.
var ErrEthereumRPCEndpointRequired = errors.New(
	"OPERATOR_ETH_RPC_ENABLED=true requires OPERATOR_ETH_RPC_ENDPOINT (a JSON-RPC URL)")

// ErrEthereumRPCInsecureEndpoint is returned when an http:// endpoint
// is configured without OPERATOR_ETH_RPC_ALLOW_HTTP=true. The SDK
// would reject this in NewHTTPEthereumRPC; we surface it earlier so
// startup fails fast with a clear operator-facing error.
var ErrEthereumRPCInsecureEndpoint = errors.New(
	"OPERATOR_ETH_RPC_ENDPOINT is http:// but OPERATOR_ETH_RPC_ALLOW_HTTP is not true (set ALLOW_HTTP=true for local-dev only; production MUST use https://)")

// -------------------------------------------------------------------------------------------------
// 4) LoadEthereumRPCConfig — env → struct
// -------------------------------------------------------------------------------------------------

// LoadEthereumRPCConfig reads the four OPERATOR_ETH_RPC_* env vars
// and returns a populated EthereumRPCConfig. Validation of
// "endpoint required when enabled" and "https-or-explicit-opt-in"
// happens here so misconfiguration aborts startup before any
// further operator wiring occurs.
//
// Returns:
//   - the populated config and nil on success.
//   - the zero-valued config and a typed error on misconfig.
func LoadEthereumRPCConfig() (EthereumRPCConfig, error) {
	cfg := EthereumRPCConfig{
		Enabled:           os.Getenv("OPERATOR_ETH_RPC_ENABLED") == "true",
		Endpoint:          os.Getenv("OPERATOR_ETH_RPC_ENDPOINT"),
		AllowInsecureHTTP: os.Getenv("OPERATOR_ETH_RPC_ALLOW_HTTP") == "true",
		Timeout: time.Duration(envIntOr(
			"OPERATOR_ETH_RPC_TIMEOUT_MS", defaultEthereumRPCTimeoutMS)) * time.Millisecond,
	}
	if !cfg.Enabled {
		// Disabled mode. Endpoint/Timeout/AllowInsecureHTTP are
		// ignored; the operator runs EOA-only.
		return cfg, nil
	}
	if cfg.Endpoint == "" {
		return EthereumRPCConfig{}, ErrEthereumRPCEndpointRequired
	}
	if strings.HasPrefix(strings.ToLower(cfg.Endpoint), "http://") && !cfg.AllowInsecureHTTP {
		return EthereumRPCConfig{}, ErrEthereumRPCInsecureEndpoint
	}
	return cfg, nil
}

// -------------------------------------------------------------------------------------------------
// 5) BuildEthereumRPCClient — config → client
// -------------------------------------------------------------------------------------------------

// BuildEthereumRPCClient constructs the SDK's HTTPEthereumRPC from
// the parsed config. Returns:
//   - (nil, nil)  when cfg.Enabled == false (disabled mode is the
//     default and is NOT an error).
//   - (rpc, nil)  on successful construction.
//   - (nil, err)  on SDK-side construction failure (e.g., the SDK
//     applies its own URL-scheme check redundantly).
//
// The operator passes the returned client to
// did.DefaultVerifierRegistryWithRPC. The function never logs the
// endpoint URL — operators audit it via secret-management.
func BuildEthereumRPCClient(cfg EthereumRPCConfig) (sdkcryptosigs.EthereumRPCClient, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := []sdkcryptosigs.HTTPRPCOption{
		sdkcryptosigs.WithTimeout(cfg.Timeout),
	}
	if cfg.AllowInsecureHTTP {
		opts = append(opts, sdkcryptosigs.WithAllowInsecureHTTP(true))
	}
	rpc, err := sdkcryptosigs.NewHTTPEthereumRPC(cfg.Endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("ethereum rpc client: %w", err)
	}
	return rpc, nil
}
