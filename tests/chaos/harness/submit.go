/*
FILE PATH: tests/chaos/harness/submit.go

HTTP submission helpers + session seeding for chaos tests. The
subprocess ledger accepts POST /v1/entries with a Bearer auth
token; this file (a) seeds a session + credits in the test PG
database, (b) constructs signed envelope entries with fresh keys,
(c) POSTs them and parses the SCT response.

Pattern derived from the soak's submitter goroutine plus the
shared helpers in tests/helpers_test.go (makeAdmissibleEntry,
mustSerialize). The chaos harness duplicates the subset it
needs rather than importing _test.go files from package tests
(Go forbids cross-package _test.go imports).
*/
package harness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkcryptosigs "github.com/clearcompass-ai/attesta/crypto/signatures"

	"github.com/clearcompass-ai/ledger/store"
)

// Submitter holds the per-test signing identity + auth token.
// Construct one via Harness.NewSubmitter(); use Submit to POST.
type Submitter struct {
	h           *Harness
	client      *http.Client
	signerDID   string
	signerPriv  *ecdsa.PrivateKey
	authToken   string
	exchangeDID string

	submitted atomic.Int64
	failed    atomic.Int64
}

// NewSubmitter seeds a session in the test PG database with the
// configured credits and returns a Submitter ready to POST. The
// signing key is freshly generated; the corresponding did:key
// becomes the SignerDID on every entry submitted by this
// submitter (admission verifies signatures via the SDK DID
// resolver).
//
// authToken can be any string — the ledger looks it up in the
// sessions table by token. Match must be exact.
//
// On any failure, t.Fatalf.
func (h *Harness) NewSubmitter(t *testing.T, authToken, exchangeDID string, credits int64) *Submitter {
	t.Helper()
	if authToken == "" {
		t.Fatal("NewSubmitter: empty authToken")
	}
	if exchangeDID == "" {
		t.Fatal("NewSubmitter: empty exchangeDID")
	}

	// Generate a fresh signing key.
	priv, err := sdkcryptosigs.GenerateKey()
	if err != nil {
		t.Fatalf("NewSubmitter: GenerateKey: %v", err)
	}
	signerDID, err := didKeyFromPriv(priv)
	if err != nil {
		t.Fatalf("NewSubmitter: derive signer did:key: %v", err)
	}

	// Seed session + credits in PG via the harness's pool.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = h.pg.Pool.Exec(ctx,
		`INSERT INTO sessions (token, exchange_did, expires_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (token) DO NOTHING`,
		authToken, exchangeDID, time.Now().UTC().Add(24*time.Hour),
	)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if credits > 0 {
		cs := store.NewCreditStore(h.pg.Pool)
		if _, err := cs.BulkPurchase(ctx, exchangeDID, credits); err != nil {
			t.Fatalf("seed credits: %v", err)
		}
	}

	return &Submitter{
		h:           h,
		client:      &http.Client{Timeout: 15 * time.Second},
		signerDID:   signerDID,
		signerPriv:  priv,
		authToken:   authToken,
		exchangeDID: exchangeDID,
	}
}

// Submit constructs a signed envelope entry with payload and
// POSTs it to /v1/entries. Returns the canonical hash (extracted
// from the SCT body) on success. On HTTP non-202, returns the
// status + body in the error.
//
// Caller controls the AuthorityPath via the opts; the harness
// uses AuthoritySameSigner by default so every entry produces an
// SMT mutation (matching the soak's workload pattern).
func (s *Submitter) Submit(ctx context.Context, payload []byte, opts SubmitOpts) (SubmitResult, error) {
	wire, err := s.buildWire(payload, opts)
	if err != nil {
		return SubmitResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		s.h.BaseURL()+"/v1/entries", bytes.NewReader(wire))
	if err != nil {
		return SubmitResult{}, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.authToken)

	start := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		s.failed.Add(1)
		return SubmitResult{}, fmt.Errorf("client.Do: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	result := SubmitResult{
		StatusCode: resp.StatusCode,
		Body:       body,
		Latency:    time.Since(start),
		RetryAfter: resp.Header.Get("Retry-After"),
	}

	if resp.StatusCode != http.StatusAccepted {
		s.failed.Add(1)
		return result, fmt.Errorf("non-202: status=%d body=%s",
			resp.StatusCode, string(body))
	}

	hash, ok := parseSCTCanonicalHash(body)
	if !ok {
		s.failed.Add(1)
		return result, fmt.Errorf("parse SCT body: %s", body)
	}
	result.CanonicalHash = hash
	s.submitted.Add(1)
	return result, nil
}

// SubmitN fires N submissions in parallel up to concurrency.
// Returns the (submitted, failed) counts + the first error seen.
// Used by chaos tests to drive load before injecting a kill.
func (s *Submitter) SubmitN(ctx context.Context, n, concurrency int) (int, int, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > n {
		concurrency = n
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	var submitted, failed atomic.Int64
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return int(submitted.Load()), int(failed.Load()), err
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			payload := []byte(fmt.Sprintf("chaos-%010d", idx))
			_, err := s.Submit(ctx, payload, SubmitOpts{})
			if err != nil {
				failed.Add(1)
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			submitted.Add(1)
		}(i)
	}
	wg.Wait()
	return int(submitted.Load()), int(failed.Load()), firstErr
}

// SubmitOpts controls the entry's envelope ControlHeader. Zero-
// value sets sane defaults (AuthoritySameSigner so the entry
// produces an SMT mutation).
type SubmitOpts struct {
	// AuthorityPath — defaults to AuthoritySameSigner. Set
	// explicitly only when testing alternative paths.
	AuthorityPath *envelope.AuthorityPath
}

// SubmitResult is the outcome of a Submit call.
type SubmitResult struct {
	StatusCode    int
	Body          []byte
	Latency       time.Duration
	CanonicalHash [32]byte
	// RetryAfter is the Retry-After response header value (empty
	// if not present). For 503/429 responses chaos tests assert
	// this is set.
	RetryAfter string
}

// Stats returns the running submitted/failed counts.
func (s *Submitter) Stats() (submitted, failed int64) {
	return s.submitted.Load(), s.failed.Load()
}

// buildWire constructs a signed envelope entry with this
// submitter's signing key.
func (s *Submitter) buildWire(payload []byte, opts SubmitOpts) ([]byte, error) {
	// Default authority path: AuthoritySameSigner sentinel — the
	// builder routes through the NewLeaf path producing exactly
	// one SMT mutation per sequence. Matches the soak's pattern.
	authPath := opts.AuthorityPath
	if authPath == nil {
		ap := envelope.AuthoritySameSigner
		authPath = &ap
	}
	header := envelope.ControlHeader{
		SignerDID:     s.signerDID,
		Destination:   s.h.cfg.LogDID,
		EventTime:     time.Now().UTC().UnixMicro(),
		AuthorityPath: authPath,
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		return nil, fmt.Errorf("NewUnsignedEntry: %w", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := sdkcryptosigs.SignEntry(hash, s.signerPriv)
	if err != nil {
		return nil, fmt.Errorf("SignEntry: %w", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: s.signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("entry.Validate: %w", err)
	}
	return envelope.Serialize(entry)
}

// parseSCTCanonicalHash extracts the canonical_hash hex string
// from a 202 SCT response and decodes it to bytes. Returns
// (hash, true) on success.
func parseSCTCanonicalHash(body []byte) ([32]byte, bool) {
	var resp struct {
		CanonicalHash string `json:"canonical_hash"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return [32]byte{}, false
	}
	decoded, err := hex.DecodeString(resp.CanonicalHash)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], decoded)
	return out, true
}
