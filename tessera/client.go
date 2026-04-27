/*
FILE PATH:
    tessera/client.go

DESCRIPTION:
    Tessera personality HTTP client. Communicates with the Ortholog Tessera
    personality to append entry hashes and retrieve tree state via the
    c2sp.org/tlog-tiles checkpoint format (signed note, not JSON).

    Internal to the tessera package — the builder interacts only with
    TesseraAdapter (proof_adapter.go) via the MerkleAppender interface.

KEY ARCHITECTURAL DECISIONS:
    - Hash-only append: POST /add accepts exactly 32 bytes (SHA-256 of wire_bytes).
      Full entry bytes stay in the operator's own storage. Tessera never sees
      full entry data — preserves SDK-D11 1MB limit within tlog-tiles 64KB spec.
    - Signed note checkpoint: GET /checkpoint returns the c2sp.org/tlog-tiles
      format (origin, tree_size decimal, base64 root_hash, Ed25519 signature).
      Parsed via line splitting — no JSON. The operator reads root_hash + tree_size
      and independently produces ECDSA secp256k1 cosigned tree heads.
    - Strict validation: 32-byte body assertion on Append, exact checkpoint format
      parsing. No silent fallbacks.

OVERVIEW:
    Append(ctx, hash) → POST /add with 32-byte body → personality returns {"index": N}.
    TreeHead(ctx) → GET /checkpoint → parse signed note → extract tree_size + root_hash.

KEY DEPENDENCIES:
    - tessera-personality/main.go: The HTTP server this client talks to.
    - builder/loop.go: Calls Append via TesseraAdapter.AppendLeaf.
    - witness/head_sync.go: Calls TreeHead via TesseraAdapter.Head.
*/
package tessera

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Configuration
// -------------------------------------------------------------------------------------------------

// ClientConfig configures the Tessera personality client.
type ClientConfig struct {
	BaseURL string
	Timeout time.Duration
}

// -------------------------------------------------------------------------------------------------
// 2) Client
// -------------------------------------------------------------------------------------------------

// Client communicates with the Ortholog Tessera personality via HTTP.
// Append sends 32-byte SHA-256 hashes. TreeHead parses signed note checkpoints.
type Client struct {
	baseURL string
	client  *http.Client
	logger  *slog.Logger
}

// NewClient creates a Tessera personality client.
func NewClient(cfg ClientConfig, logger *slog.Logger) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		client:  &http.Client{Timeout: cfg.Timeout},
		logger:  logger,
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Append — POST /add with 32-byte SHA-256 hash
// -------------------------------------------------------------------------------------------------

// Append submits a 32-byte SHA-256 entry hash to the Tessera personality.
// The personality sequences it into the Merkle tree and returns the assigned index.
//
// STRICT: data must be exactly 32 bytes. Any other length is a programming error
// in the caller (builder/loop.go step 6) and is rejected immediately without
// making the HTTP call.
func (c *Client) Append(ctx context.Context, data []byte) (uint64, error) {
	if len(data) != 32 {
		return 0, fmt.Errorf("tessera/client: Append requires exactly 32 bytes (SHA-256 hash), got %d", len(data))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/add", bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("tessera/client: build append request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("tessera/client: append request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("tessera/client: append HTTP %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Index uint64 `json:"index"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("tessera/client: decode append response: %w", err)
	}
	return result.Index, nil
}

// -------------------------------------------------------------------------------------------------
// 4) TreeHead — GET /checkpoint (c2sp.org/tlog-tiles signed note format)
// -------------------------------------------------------------------------------------------------

// TreeHead retrieves the current Merkle tree state from the Tessera personality's
// checkpoint endpoint. The checkpoint follows the c2sp.org/tlog-tiles signed note
// format:
//
//	<origin line>
//	<tree_size decimal>
//	<base64 root_hash>
//
//	— <signer_name> <base64 Ed25519 signature>
//
// The operator extracts tree_size and root_hash. The Ed25519 signature is for the
// tlog-tiles ecosystem (monitors, mirrors). The operator independently produces
// ECDSA secp256k1 cosigned tree heads for Ortholog consumers (light clients,
// smart contract bridges).
func (c *Client) TreeHead(ctx context.Context) (types.TreeHead, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/checkpoint", nil)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("tessera/client: build checkpoint request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("tessera/client: checkpoint request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return types.TreeHead{}, fmt.Errorf("tessera/client: checkpoint HTTP %d: %s", resp.StatusCode, respBody)
	}

	// Read the full checkpoint body (capped at 64KB — checkpoints are small).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("tessera/client: read checkpoint: %w", err)
	}

	return parseSignedNoteCheckpoint(body)
}

// -------------------------------------------------------------------------------------------------
// 4b) AppenderBackend forwarders — let *Client satisfy proof_adapter.go's interface
// -------------------------------------------------------------------------------------------------

// AppendLeaf is a context.TODO()-flavored forwarder over Append so
// *Client satisfies proof_adapter.go's AppenderBackend interface.
// The forwarder exists so the Phase 1B refactor (which lifted
// TesseraAdapter onto an interface so *EmbeddedAppender can plug
// in) keeps *Client working as the legacy backend during the
// cutover. *Client itself is slated for deletion when
// tessera-personality goes away — see commit 7/7 of the embed
// series.
func (c *Client) AppendLeaf(data []byte) (uint64, error) {
	return c.Append(context.TODO(), data)
}

// Head is the parallel forwarder over TreeHead. Same rationale as
// AppendLeaf — keeps *Client satisfying AppenderBackend during
// the embed cutover.
func (c *Client) Head() (types.TreeHead, error) {
	return c.TreeHead(context.TODO())
}

// Compile-time pin: *Client satisfies AppenderBackend so
// NewTesseraAdapter accepts it. If proof_adapter.go's interface
// drifts, this fails at build time before any cmd-side wiring
// breaks.
var _ AppenderBackend = (*Client)(nil)

// -------------------------------------------------------------------------------------------------
// 5) Signed Note Checkpoint Parser
// -------------------------------------------------------------------------------------------------

// parseSignedNoteCheckpoint parses a c2sp.org/tlog-tiles checkpoint.
//
// Format:
//
//	line 0: origin string (e.g., "ortholog-local-dev")
//	line 1: tree size as decimal (e.g., "1234")
//	line 2: base64-encoded root hash (32 bytes decoded)
//	line 3: empty (separator before signature block)
//	line 4+: "— <signer> <base64 sig>" (optional, ignored by operator)
//
// The operator extracts only tree_size and root_hash. The Ed25519 signature
// is verified by tlog-tiles ecosystem consumers, not by the operator.
func parseSignedNoteCheckpoint(data []byte) (types.TreeHead, error) {
	text := string(data)
	lines := strings.Split(text, "\n")

	// Minimum: origin + tree_size + root_hash = 3 lines.
	if len(lines) < 3 {
		return types.TreeHead{}, fmt.Errorf(
			"tessera/client: checkpoint has %d lines, need at least 3 (origin, size, hash)", len(lines))
	}

	// Line 0: origin (informational, not validated here).
	origin := strings.TrimSpace(lines[0])
	if origin == "" {
		return types.TreeHead{}, fmt.Errorf("tessera/client: checkpoint line 0 (origin) is empty")
	}

	// Line 1: tree size as decimal integer.
	treeSizeStr := strings.TrimSpace(lines[1])
	treeSize, err := strconv.ParseUint(treeSizeStr, 10, 64)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf(
			"tessera/client: checkpoint line 1 (tree_size) not a valid uint64: %q: %w", treeSizeStr, err)
	}

	// Line 2: base64 root hash (standard encoding, 32 bytes decoded).
	rootHashB64 := strings.TrimSpace(lines[2])
	rootBytes, err := base64.StdEncoding.DecodeString(rootHashB64)
	if err != nil {
		// Fallback: try raw standard (no padding).
		rootBytes, err = base64.RawStdEncoding.DecodeString(rootHashB64)
		if err != nil {
			return types.TreeHead{}, fmt.Errorf(
				"tessera/client: checkpoint line 2 (root_hash) not valid base64: %q: %w", rootHashB64, err)
		}
	}
	if len(rootBytes) != 32 {
		return types.TreeHead{}, fmt.Errorf(
			"tessera/client: checkpoint root hash is %d bytes, expected 32", len(rootBytes))
	}

	var head types.TreeHead
	head.TreeSize = treeSize
	copy(head.RootHash[:], rootBytes)
	return head, nil
}
