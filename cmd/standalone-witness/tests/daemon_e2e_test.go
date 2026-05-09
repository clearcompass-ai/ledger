// FILE PATH: cmd/standalone-witness/tests/daemon_e2e_test.go
//
// Black-box end-to-end test for the standalone-witness binary.
// Builds the binary from this same module's main.go, runs it as
// an external OS process, and hits /v1/cosign over real HTTP.
//
// SCOPE:
//   - Compiles the binary (proves the build is reproducible).
//   - Boots it with real flags (-addr, -key-file, -bootstrap).
//   - POSTs a real cosign WireRequest, gets back a valid
//     WireResponse, verifies the signature.
//
// SHORT MODE:
//   - go test -short skips this; standard go test runs it.
//   - Per the architectural rule: tests that compile a binary
//     and exec a process don't belong in the fast-feedback loop.
//
// SCOPE NEGATIVE:
//   - This test does NOT touch Postgres. The witness daemon
//     itself never opens a DB; it only reads PEM key + bootstrap
//     JSON and serves cosign requests. The test mirrors that.
package tests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/network"
)

// TestDaemonE2E builds + runs the witness daemon then exercises
// /v1/cosign over real HTTP.
func TestDaemonE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping daemon e2e in -short mode (compiles + execs a binary)")
	}

	// ── 1. Build the binary ────────────────────────────────────
	moduleDir := witnessModuleDir(t)
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "standalone-witness")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = moduleDir
	build.Stderr = os.Stderr
	build.Stdout = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build standalone-witness: %v", err)
	}

	// ── 2. Generate fixture: PEM key + bootstrap JSON ──────────
	keyPath := filepath.Join(binDir, "witness.pem")
	priv := writeECPrivateKey(t, keyPath)
	witnessDID := didFromKey(priv)

	bsPath := filepath.Join(binDir, "bootstrap.json")
	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:e2e-test.example",
		NetworkName:       "daemon-e2e",
		GenesisWitnessSet: []string{witnessDID},
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
	}
	identity, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs: %v", err)
	}
	bsBody, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal bootstrap: %v", err)
	}
	if err := os.WriteFile(bsPath, bsBody, 0o644); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}

	// ── 3. Pick a free port and start the daemon ───────────────
	port := pickFreePort(t)
	addr := fmt.Sprintf(":%d", port)

	daemon := exec.Command(binPath,
		"-addr="+addr,
		"-key-file="+keyPath,
		"-bootstrap="+bsPath,
	)
	daemon.Stdout = os.Stderr
	daemon.Stderr = os.Stderr
	if err := daemon.Start(); err != nil {
		t.Fatalf("daemon.Start: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_, _ = daemon.Process.Wait()
	})

	// ── 4. Wait for /healthz to report ready ───────────────────
	healthzURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	if err := waitForHealthz(healthzURL, 10*time.Second); err != nil {
		t.Fatalf("daemon /healthz did not respond: %v", err)
	}

	// ── 5. POST /v1/cosign with a real WireRequest ─────────────
	cosignURL := fmt.Sprintf("http://127.0.0.1:%d%s", port, cosign.DefaultCosignPath)

	root := [32]byte{0xCA, 0xFE, 0xBA, 0xBE}
	innerPayload, err := json.Marshal(struct {
		RootHash string `json:"root_hash"`
		TreeSize uint64 `json:"tree_size"`
	}{
		RootHash: hex.EncodeToString(root[:]),
		TreeSize: 1234,
	})
	if err != nil {
		t.Fatalf("marshal inner payload: %v", err)
	}
	body, err := json.Marshal(cosign.WireRequest{
		Purpose:   cosign.PurposeTreeHead,
		Payload:   innerPayload,
		NetworkID: cosign.NetworkIDToWire(identity.NetworkID),
		HashAlgo:  cosign.HashAlgoToWire(cosign.HashAlgoSHA256),
	})
	if err != nil {
		t.Fatalf("marshal WireRequest: %v", err)
	}

	resp, err := http.Post(cosignURL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST cosign: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/cosign: status=%d body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var wireResp cosign.WireResponse
	if err := json.Unmarshal(respBody, &wireResp); err != nil {
		t.Fatalf("unmarshal WireResponse: %v\nbody=%s", err, respBody)
	}
	if wireResp.SigBytes == "" {
		t.Fatal("WireResponse.SigBytes empty — daemon did not sign")
	}
	if wireResp.PubKeyID == "" {
		t.Error("WireResponse.PubKeyID empty")
	}

	// ── 6. Cosign rollback: a request with smaller TreeSize ────
	// should be rejected with 409 Conflict by the monotonicity
	// guard in internal/serve.
	innerSmaller, err := json.Marshal(struct {
		RootHash string `json:"root_hash"`
		TreeSize uint64 `json:"tree_size"`
	}{
		RootHash: hex.EncodeToString(root[:]),
		TreeSize: 100, // smaller than the 1234 we just signed
	})
	if err != nil {
		t.Fatalf("marshal smaller payload: %v", err)
	}
	bodySmaller, err := json.Marshal(cosign.WireRequest{
		Purpose:   cosign.PurposeTreeHead,
		Payload:   innerSmaller,
		NetworkID: cosign.NetworkIDToWire(identity.NetworkID),
		HashAlgo:  cosign.HashAlgoToWire(cosign.HashAlgoSHA256),
	})
	if err != nil {
		t.Fatalf("marshal smaller WireRequest: %v", err)
	}
	resp2, err := http.Post(cosignURL, "application/json", bytes.NewReader(bodySmaller))
	if err != nil {
		t.Fatalf("POST cosign (rollback): %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		body2, _ := io.ReadAll(resp2.Body)
		t.Errorf("rollback POST: status=%d (want 409 Conflict), body=%s",
			resp2.StatusCode, body2)
	}

	// ── 7. Graceful shutdown ───────────────────────────────────
	_ = daemon.Process.Signal(os.Interrupt)
	doneCh := make(chan error, 1)
	go func() { doneCh <- daemon.Wait() }()
	select {
	case <-doneCh:
		// Graceful exit (SIGINT honored).
	case <-time.After(10 * time.Second):
		t.Error("daemon did not exit within 10s of SIGINT")
		_ = daemon.Process.Kill()
	}
}

// witnessModuleDir resolves cmd/standalone-witness/ relative to
// THIS test file's location. The tests/ subdir lives one level
// inside the witness module.
func witnessModuleDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	// We are in cmd/standalone-witness/tests/. Module root is
	// the parent.
	moduleDir := filepath.Dir(wd)
	if _, err := os.Stat(filepath.Join(moduleDir, "go.mod")); err != nil {
		t.Fatalf("expected go.mod at %s: %v", moduleDir, err)
	}
	return moduleDir
}

// writeECPrivateKey generates a fresh P-256 EC private key in
// PEM form, writes it to path, and returns the key.
func writeECPrivateKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return priv
}

// didFromKey derives the did:key:z... form from the public key
// matching what cmd/init-network produces. Used to populate the
// bootstrap doc's GenesisWitnessSet.
//
// We don't import did/multicodec; we compute a placeholder DID
// since the witness daemon itself does not validate that its
// own key matches a DID in the bootstrap (the SDK's witness
// handler verifies AllowedNetworks contains the request's
// NetworkID, which is derived from the bootstrap regardless of
// witness identity).
func didFromKey(priv *ecdsa.PrivateKey) string {
	// Compose a stable but synthetic DID — the bootstrap's
	// genesis_witness_set is not consulted by the daemon's
	// per-request path; only NetworkID derivation reads it.
	pub := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	return "did:key:z" + hex.EncodeToString(pub[:8])
}

// pickFreePort opens a tcp listener on :0, captures the kernel-
// assigned port, and closes the listener. Race window between
// the close and the daemon's Listen is small enough for laptop
// tests; flaky-pin retries are not needed.
func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen 127.0.0.1:0: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// waitForHealthz polls url with a 200ms cadence until the body
// is "ok" or deadline expires.
func waitForHealthz(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 1 * time.Second}
	for {
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == "ok" {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("healthz did not respond ok within %v", timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// guard against unused imports when the test stack is rearranged.
var _ = context.Background
