/*
FILE PATH: cmd/submit-stamp/main.go

submit-stamp — local-dev / CI client that submits a single signed
entry to the ledger. Handles both admission modes:

	Mode A (authenticated): -token "tok-dev"
	  Adds Authorization: Bearer <token>; admission deducts one
	  credit from the seeded session's balance.

	Mode B (anonymous): no -token
	  Brute-forces a Mode B PoW stamp at the difficulty advertised
	  by GET /v1/admission/difficulty (or the supplied -difficulty
	  flag), embeds it in the entry header, signs, POSTs.

A fresh did:key:z... keypair is generated per invocation and used
both as the SignerDID and as the signing key. With the ledger
wired to did.NewECDSAKeyResolver (SDK), the signature verifies
cryptographically — no test-mode shortcuts.

Usage:

	go run ./cmd/submit-stamp \
	    -url http://localhost:8080 \
	    -log-did "did:attesta:ledger:001" \
	    -payload "hello world"

	go run ./cmd/submit-stamp \
	    -url http://localhost:8080 \
	    -log-did "did:attesta:ledger:001" \
	    -token "tok-dev" \
	    -payload @/path/to/payload.json

Mode B at difficulty 16 typically takes ~65 ms on commodity
hardware. At difficulty 24 (the default ceiling) it can take
seconds. The brute-force loop signs every iteration because the
SDK's stamp-target hash is envelope.EntryIdentity, which
includes the signature section under — so changing the
nonce changes the hash that needs to be matched.
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkadmission "github.com/clearcompass-ai/attesta/crypto/admission"
	sdksigs "github.com/clearcompass-ai/attesta/crypto/signatures"
	sdkdid "github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/types"
)

func main() {
	var (
		ledgerURL  = flag.String("url", "http://localhost:8080", "ledger base URL")
		logDID     = flag.String("log-did", "did:attesta:ledger:001", "destination log DID (admission rejects mismatched Header.Destination)")
		token      = flag.String("token", "", "Mode A Bearer token; empty → Mode B")
		difficulty = flag.Int("difficulty", 0, "Mode B difficulty; 0 → query /v1/admission/difficulty")
		epochSec   = flag.Int("epoch-window", 3600, "epoch window seconds (must match LEDGER_EPOCH_WINDOW_SECONDS)")
		payload    = flag.String("payload", "hello world", `payload bytes; "@/path" reads from a file`)
		dryRun     = flag.Bool("dry-run", false, "build and print the entry without POSTing")
		ledgerDID  = flag.String("ledger-did", "", "ledger's did:key:z... — when set, the SCT signature is cryptographically verified against the resolved public key. Empty → SCT is decoded but not verified.")
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
		EventTime: time.Now().UTC().UnixMicro(),
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
			diff, err = queryDifficulty(*ledgerURL)
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

	body, status, err := postAndRead(*ledgerURL+"/v1/entries", *token, wire)
	if err != nil {
		log.Fatalf("submit-stamp: %v", err)
	}
	fmt.Printf("HTTP %d %s\n", status, http.StatusText(status))
	if status != http.StatusAccepted {
		fmt.Printf("body: %s\n", body)
		os.Exit(1)
	}
	printSCTResponse(body, *ledgerDID)
}

// printSCTResponse decodes the SCT and (when ledgerDID is
// supplied) verifies the signature against the resolved public
// key. The exit code stays 0 even on verification failure — the
// SCT was decoded; the ledger's DID may not be configured.
func printSCTResponse(body []byte, ledgerDID string) {
	var sct apiSCT
	if err := json.Unmarshal(body, &sct); err != nil {
		fmt.Printf("could not parse SCT: %v\nraw: %s\n", err, body)
		return
	}
	fmt.Printf("SCT.version = %d\n", sct.Version)
	fmt.Printf("SCT.signer_did = %s\n", sct.SignerDID)
	fmt.Printf("SCT.sig_algo_id = %s\n", sct.SigAlgoID)
	fmt.Printf("SCT.log_did = %s\n", sct.LogDID)
	fmt.Printf("SCT.canonical_hash = %s\n", sct.CanonicalHash)
	fmt.Printf("SCT.log_time = %s\n", sct.LogTime)
	fmt.Printf("SCT.log_time_micros = %d\n", sct.LogTimeMicros)
	fmt.Printf("SCT.signature[:32]     = %.32s...\n", sct.Signature)

	if ledgerDID == "" {
		fmt.Println("(SCT signature NOT verified — pass -ledger-did did:key:z... to verify)")
		return
	}
	pub, _, err := sdkdid.ParseDIDKey(ledgerDID)
	if err != nil {
		fmt.Printf("(SCT signature NOT verified — could not parse -ledger-did: %v)\n", err)
		return
	}
	pk, err := sdksigs.ParsePubKey(pub)
	if err != nil {
		fmt.Printf("(SCT signature NOT verified — non-secp256k1 ledger key: %v)\n", err)
		return
	}
	if err := verifyClientSCT(pk, &sct); err != nil {
		fmt.Printf("SCT signature DOES NOT VERIFY: %v\n", err)
		return
	}
	fmt.Println("SCT signature VERIFIED against ledger did:key")
}

// apiSCT mirrors api.SignedCertificateTimestamp's JSON shape so
// this CLI doesn't need to import the api package (avoids a
// reverse dep from cmd to api).
type apiSCT struct {
	Version       uint8  `json:"version"`
	SignerDID     string `json:"signer_did"`
	SigAlgoID     string `json:"sig_algo_id"`
	LogDID        string `json:"log_did"`
	CanonicalHash string `json:"canonical_hash"`
	LogTimeMicros int64  `json:"log_time_micros"`
	LogTime       string `json:"log_time"`
	Signature     string `json:"signature"`
}

// verifyClientSCT recomputes the canonical signing payload from
// the SCT's JSON fields and verifies the signature. Mirrors
// api.VerifySCT byte-for-byte; kept here so this binary stays
// self-contained.
func verifyClientSCT(pub *ecdsa.PublicKey, sct *apiSCT) error {
	if sct.Version != 1 {
		return fmt.Errorf("unsupported SCT version %d", sct.Version)
	}
	if sct.SignerDID == "" {
		return fmt.Errorf("missing signer_did")
	}
	if sct.SigAlgoID != "ecdsa-secp256k1-sha256" {
		return fmt.Errorf("unsupported sig_algo_id %q", sct.SigAlgoID)
	}
	expectedLogTime := time.UnixMicro(sct.LogTimeMicros).UTC().Format(time.RFC3339Nano)
	if sct.LogTime != expectedLogTime {
		return fmt.Errorf("log_time mismatch (got %q want %q)", sct.LogTime, expectedLogTime)
	}
	canonicalHashBytes, err := hex.DecodeString(sct.CanonicalHash)
	if err != nil {
		return fmt.Errorf("canonical_hash decode: %w", err)
	}
	if len(canonicalHashBytes) != 32 {
		return fmt.Errorf("canonical_hash length %d (want 32)", len(canonicalHashBytes))
	}
	sigBytes, err := hex.DecodeString(sct.Signature)
	if err != nil {
		return fmt.Errorf("signature decode: %w", err)
	}
	// Match the packing in api/sct.go::SCTSigningPayload exactly.
	const domainSep = "ATTESTA_SCT_V1\x00"
	buf := make([]byte, 0, len(domainSep)+1+2+len(sct.SignerDID)+2+len(sct.SigAlgoID)+2+len(sct.LogDID)+32+8)
	buf = append(buf, domainSep...)
	buf = append(buf, sct.Version)
	buf = append(buf, byte(len(sct.SignerDID)>>8), byte(len(sct.SignerDID)))
	buf = append(buf, sct.SignerDID...)
	buf = append(buf, byte(len(sct.SigAlgoID)>>8), byte(len(sct.SigAlgoID)))
	buf = append(buf, sct.SigAlgoID...)
	if len(sct.LogDID) > 0xFFFF {
		return fmt.Errorf("logDID too long")
	}
	buf = append(buf, byte(len(sct.LogDID)>>8), byte(len(sct.LogDID)))
	buf = append(buf, sct.LogDID...)
	buf = append(buf, canonicalHashBytes...)
	micros := uint64(sct.LogTimeMicros)
	buf = append(buf,
		byte(micros>>56), byte(micros>>48), byte(micros>>40), byte(micros>>32),
		byte(micros>>24), byte(micros>>16), byte(micros>>8), byte(micros),
	)
	hash := sha256.Sum256(buf)
	return sdksigs.VerifyEntry(hash, sigBytes, pub)
}

// readPayload returns the raw payload bytes. A leading '@' treats the
// remainder as a filesystem path; otherwise the literal string is used.
func readPayload(spec string) ([]byte, error) {
	if strings.HasPrefix(spec, "@") {
		return os.ReadFile(strings.TrimPrefix(spec, "@"))
	}
	return []byte(spec), nil
}

// queryDifficulty asks the ledger's GET /v1/admission/difficulty for
// the live Mode B difficulty. The endpoint returns
// {"difficulty": N, "hash_function": "sha256"} per api/queries.go.
func queryDifficulty(ledgerURL string) (uint32, error) {
	resp, err := http.Get(ledgerURL + "/v1/admission/difficulty")
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
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
	if vErr := entry.Validate(); vErr != nil {
		return nil, fmt.Errorf("validate: %w", vErr)
	}
	wire, err := envelope.Serialize(entry)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	return wire, nil
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
		canonical, err := envelope.Serialize(entry)
		if err != nil {
			return nil, fmt.Errorf("serialize: %w", err)
		}
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

// postAndRead POSTs wire bytes and returns the response body and
// status. Returns a transport error only on actual transport failure;
// the caller decides what to do with non-2xx statuses.
func postAndRead(url, token string, wire []byte) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return body, resp.StatusCode, nil
}
