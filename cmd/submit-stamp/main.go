/*
FILE PATH: cmd/submit-stamp/main.go

submit-stamp — local-dev / CI client that submits a single signed
entry to the operator. Handles both admission modes:

  Mode A (authenticated): -token "tok-dev"
    Adds Authorization: Bearer <token>; admission deducts one
    credit from the seeded session's balance.

  Mode B (anonymous): no -token
    Brute-forces a Mode B PoW stamp at the difficulty advertised
    by GET /v1/admission/difficulty (or the supplied -difficulty
    flag), embeds it in the entry header, signs, POSTs.

A fresh did:key:z... keypair is generated per invocation and used
both as the SignerDID and as the signing key. With the operator
wired to admission.NewDIDKeyResolver, the signature verifies
cryptographically — no test-mode shortcuts.

Usage:

	go run ./cmd/submit-stamp \
	    -url http://localhost:8080 \
	    -log-did "did:ortholog:operator:001" \
	    -payload "hello world"

	go run ./cmd/submit-stamp \
	    -url http://localhost:8080 \
	    -log-did "did:ortholog:operator:001" \
	    -token "tok-dev" \
	    -payload @/path/to/payload.json

Mode B at difficulty 16 typically takes ~65 ms on commodity
hardware. At difficulty 24 (the default ceiling) it can take
seconds. The brute-force loop signs every iteration because the
SDK's stamp-target hash is envelope.EntryIdentity, which
includes the signature section under v7.75 — so changing the
nonce changes the hash that needs to be matched.
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	sdksigs "github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	sdkdid "github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func main() {
	var (
		operatorURL = flag.String("url", "http://localhost:8080", "operator base URL")
		logDID      = flag.String("log-did", "did:ortholog:operator:001", "destination log DID (admission rejects mismatched Header.Destination)")
		token       = flag.String("token", "", "Mode A Bearer token; empty → Mode B")
		difficulty  = flag.Int("difficulty", 0, "Mode B difficulty; 0 → query /v1/admission/difficulty")
		epochSec    = flag.Int("epoch-window", 3600, "epoch window seconds (must match OPERATOR_EPOCH_WINDOW_SECONDS)")
		payload     = flag.String("payload", "hello world", `payload bytes; "@/path" reads from a file`)
		dryRun      = flag.Bool("dry-run", false, "build and print the entry without POSTing")
	)
	flag.Parse()

	payloadBytes, err := readPayload(*payload)
	if err != nil {
		log.Fatalf("submit-stamp: -payload: %v", err)
	}

	// Fresh signing identity per run.
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		log.Fatalf("submit-stamp: generate did:key: %v", err)
	}
	fmt.Printf("signer did:key = %s\n", kp.DID)

	header := envelope.ControlHeader{
		SignerDID:   kp.DID,
		Destination: *logDID,
		// EventTime: SDK's exchange/policy.CheckFreshness reads
		// this via time.UnixMicro despite the field's doc comment
		// claiming Unix seconds. Until the SDK is reconciled, we
		// follow the actually-implemented unit so freshness
		// (default 5min interactive tolerance) accepts the
		// submission instead of stale-rejecting it as 56 years
		// old.
		EventTime:   time.Now().UTC().UnixMicro(),
	}

	var wire []byte
	switch {
	case *token != "":
		// Mode A — sign once, no stamp.
		wire, err = buildModeAWire(header, payloadBytes, kp.PrivateKey, kp.DID)
	default:
		// Mode B — query difficulty if not supplied, brute-force.
		diff := uint32(*difficulty)
		if diff == 0 {
			diff, err = queryDifficulty(*operatorURL)
			if err != nil {
				log.Fatalf("submit-stamp: query difficulty: %v", err)
			}
			fmt.Printf("difficulty (live) = %d\n", diff)
		}
		wire, err = buildModeBWire(header, payloadBytes, kp.PrivateKey, kp.DID, *logDID, diff, uint64(*epochSec))
	}
	if err != nil {
		log.Fatalf("submit-stamp: build entry: %v", err)
	}

	if *dryRun {
		fmt.Printf("dry-run wire bytes: %d bytes\n", len(wire))
		return
	}

	if err := postEntry(*operatorURL+"/v1/entries", *token, wire); err != nil {
		log.Fatalf("submit-stamp: %v", err)
	}
}

// readPayload returns the raw payload bytes. A leading '@' treats the
// remainder as a filesystem path; otherwise the literal string is used.
func readPayload(spec string) ([]byte, error) {
	if strings.HasPrefix(spec, "@") {
		return os.ReadFile(strings.TrimPrefix(spec, "@"))
	}
	return []byte(spec), nil
}

// queryDifficulty asks the operator's GET /v1/admission/difficulty for
// the live Mode B difficulty. The endpoint returns
// {"difficulty": N, "hash_function": "sha256"} per api/queries.go.
func queryDifficulty(operatorURL string) (uint32, error) {
	resp, err := http.Get(operatorURL + "/v1/admission/difficulty")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var body struct {
		Difficulty uint32 `json:"difficulty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode: %w", err)
	}
	return body.Difficulty, nil
}

// buildModeAWire constructs a signed entry with no AdmissionProof.
// Admission's Mode A path validates the Bearer token and deducts a
// credit; the entry must still be signed end-to-end so the resolver
// returns the matching public key for sig verification.
func buildModeAWire(
	header envelope.ControlHeader,
	payload []byte,
	priv *ecdsa.PrivateKey,
	signerDID string,
) ([]byte, error) {
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		return nil, fmt.Errorf("NewUnsignedEntry: %w", err)
	}
	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := sdksigs.SignEntry(signingHash, priv)
	if err != nil {
		return nil, fmt.Errorf("SignEntry: %w", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("Validate: %w", err)
	}
	return envelope.Serialize(entry), nil
}

// buildModeBWire brute-forces a valid Mode B PoW stamp. The signing
// loop is "for nonce: set, sign, serialize, VerifyStamp; if ok break".
// At difficulty 16 with SHA-256 the loop expects ~65k iterations
// (~65ms typical). difficulty 24 is ~16M iterations (~seconds).
func buildModeBWire(
	header envelope.ControlHeader,
	payload []byte,
	priv *ecdsa.PrivateKey,
	signerDID string,
	logDID string,
	difficulty uint32,
	epochWindowSec uint64,
) ([]byte, error) {
	header.AdmissionProof = &envelope.AdmissionProofBody{
		Mode:       types.WireByteModeB,
		Difficulty: uint8(difficulty),
		HashFunc:   sdkadmission.WireByteHashSHA256,
		Epoch:      sdkadmission.CurrentEpoch(epochWindowSec),
	}
	const maxIter uint64 = 1 << 30 // 1 billion — guard against runaway difficulty.
	for nonce := uint64(0); nonce < maxIter; nonce++ {
		header.AdmissionProof.Nonce = nonce
		entry, err := envelope.NewUnsignedEntry(header, payload)
		if err != nil {
			return nil, fmt.Errorf("NewUnsignedEntry: %w", err)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(entry))
		sig, err := sdksigs.SignEntry(signingHash, priv)
		if err != nil {
			return nil, fmt.Errorf("SignEntry: %w", err)
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: signerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		}}
		canonical := envelope.Serialize(entry)
		entryHash := sha256.Sum256(canonical)
		apiProof := sdkadmission.ProofFromWire(header.AdmissionProof, logDID)
		err = sdkadmission.VerifyStamp(
			apiProof,
			entryHash,
			logDID,
			difficulty,
			sdkadmission.HashSHA256,
			nil, // argon2id params
			sdkadmission.CurrentEpoch(epochWindowSec),
			1, // acceptance window
		)
		if err == nil {
			fmt.Printf("found stamp at nonce=%d\n", nonce)
			return canonical, nil
		}
	}
	return nil, fmt.Errorf("submit-stamp: nonce exhausted at %d iterations (difficulty=%d too high?)", maxIter, difficulty)
}

// postEntry POSTs wire bytes to /v1/entries and prints the response.
// Returns an error iff the HTTP status is not 202 Accepted.
func postEntry(url, token string, wire []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	fmt.Printf("HTTP %d %s\n%s\n", resp.StatusCode, resp.Status, body)
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("not accepted")
	}
	return nil
}
