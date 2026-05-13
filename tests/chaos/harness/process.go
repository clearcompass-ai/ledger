/*
FILE PATH: tests/chaos/harness/process.go

Subprocess lifecycle: build the cmd/ledger binary once per test
binary (TestMain), spawn it with env vars + isolated dirs, wait
for /healthz, expose SIGKILL + Restart against the same on-disk
state.

REAL SIGKILL SEMANTICS

Go's os.Process.Kill on Unix sends SIGKILL — no stack unwinding,
no defers, no graceful shutdown hooks. This is what production
operators see when k8s OOM-kills a pod, when a kernel panic
takes down the node, when the operator runs `kill -9`. Every
chaos test in this suite asserts the recovery code path
survives that exact failure mode.

BINARY BUILD CACHING

Building cmd/ledger takes ~3s. To keep chaos test suites fast,
the binary is built once per `go test` invocation via the
exported Build* helpers; tests obtain the cached path via
LedgerBinaryPath(t). The test binary's TestMain hook (in each
chaos package) invokes EnsureLedgerBinary at startup.

PORT ALLOCATION

Each Process gets a unique TCP port via net.Listen(":0") — the
OS picks a free port. The listener is closed immediately;
there's a small TOCTOU window where another process could grab
the same port before the ledger binds, but in practice this is
the standard Go pattern (used by httptest.NewServer and similar
test harnesses elsewhere in the ecosystem).

LOG CAPTURE

stdout + stderr are piped to a tee'd buffer + the test's stderr.
The buffer is searchable for chaos.Trigger panic markers (the
Marker constant from chaos/trigger_chaos.go) so tests can assert
the panic fired at the intended injection point — not from some
unrelated production panic.
*/
package harness

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Process is a managed ledger subprocess. After Start the binary
// is running and /healthz is returning 200; the caller can submit
// requests, then Kill (SIGKILL) and Start again to test restart
// against the same on-disk state.
type Process struct {
	binaryPath string
	env        []string
	addr       string // host:port the ledger is bound to
	cmd        *exec.Cmd
	stderrBuf  *threadSafeBuffer
	stdoutBuf *threadSafeBuffer

	// state machine: 0=stopped, 1=running. Used by Kill +
	// Start to detect misuse.
	running atomic.Int32
}

// NewProcess returns a Process ready to Start. env is the
// process's full environment slice (KEY=VALUE strings). addr is
// the host:port the ledger will bind to (must match LEDGER_ADDR
// in env). binaryPath is the absolute path to the built binary.
func NewProcess(binaryPath string, env []string, addr string) *Process {
	return &Process{
		binaryPath: binaryPath,
		env:        append([]string(nil), env...),
		addr:       addr,
		stderrBuf:  &threadSafeBuffer{},
		stdoutBuf: &threadSafeBuffer{},
	}
}

// Start launches the binary as a subprocess. Blocks until
// /healthz returns 200 or readyTimeout elapses. On readyTimeout,
// the subprocess is killed before returning the error.
func (p *Process) Start(ctx context.Context, readyTimeout time.Duration) error {
	if !p.running.CompareAndSwap(0, 1) {
		return fmt.Errorf("Process.Start: already running")
	}
	cmd := exec.Command(p.binaryPath)
	cmd.Env = p.env

	// On Unix, put the subprocess in its own process group so
	// Kill terminates the entire tree if the ledger spawns
	// children. Go's syscall.SysProcAttr.Setpgid achieves this
	// portably across linux + darwin (not windows; chaos tests
	// don't target windows).
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	// Pipe stdout + stderr to thread-safe buffers AND to the
	// test runner's stderr, so the operator sees logs during
	// long tests AND can grep the buffer for panic markers.
	cmd.Stdout = io.MultiWriter(p.stdoutBuf, os.Stderr)
	cmd.Stderr = io.MultiWriter(p.stderrBuf, os.Stderr)

	if err := cmd.Start(); err != nil {
		p.running.Store(0)
		return fmt.Errorf("cmd.Start: %w", err)
	}
	p.cmd = cmd

	// Wait for /healthz. If it doesn't come up within
	// readyTimeout, kill and return the error.
	healthURL := fmt.Sprintf("http://%s/healthz", p.addr)
	if err := waitForHealthz(ctx, healthURL, readyTimeout); err != nil {
		_ = p.kill()
		_ = p.wait()
		p.running.Store(0)
		return fmt.Errorf("healthz wait: %w (stderr: %s)",
			err, p.stderrBuf.String())
	}
	return nil
}

// Kill sends SIGKILL to the subprocess and its process group.
// Returns when the process has exited. Idempotent — safe to call
// on an already-stopped process.
//
// The Unix wait(2) convention is that a signal-terminated process
// produces a non-zero exit status; Go surfaces that as
// *exec.ExitError from cmd.Wait. When WE'RE the ones who sent the
// signal (this method just did) the resulting "error" is the
// expected, successful outcome — not an actual failure. We
// inspect the exit code and treat the specific case of "exited
// because of the signal we just sent" as success, while still
// reporting genuine pre-signal crash exits as errors.
func (p *Process) Kill() error {
	if !p.running.CompareAndSwap(1, 0) {
		return nil // already stopped
	}
	if err := p.kill(); err != nil {
		return err
	}
	waitErr := p.wait()
	if waitErr == nil {
		return nil
	}
	if isExpectedKillExit(waitErr) {
		return nil
	}
	return waitErr
}

// isExpectedKillExit reports whether err is the *exec.ExitError
// produced by cmd.Wait when our own SIGKILL terminates the
// subprocess. Other exit causes (chaos panic, OOM, etc.) return
// false so the caller still surfaces them.
//
// Detection on Unix: ExitError.ProcessState.Sys() returns
// syscall.WaitStatus; Signaled() reports a signal-terminated
// child; Signal() returns the specific signal. SIGKILL is the
// match.
func isExpectedKillExit(err error) bool {
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	if runtime.GOOS == "windows" {
		// Windows doesn't surface signals. Treat any exit
		// after our Kill() call as expected — we already
		// guarded with running.CompareAndSwap so we only get
		// here once per process.
		return true
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return false
	}
	if !status.Signaled() {
		// Process exited via exit(2), not from a signal. Not
		// our kill — return the error.
		return false
	}
	// We only treat SIGKILL as "expected". A SIGTERM or SIGSEGV
	// here would mean something else killed the process before
	// our SIGKILL landed; surface that to the caller.
	return status.Signal() == syscall.SIGKILL
}

// kill sends SIGKILL without state-check. Internal helper.
func (p *Process) kill() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	// Kill the entire process group (negative PID), then the
	// process itself for redundancy. On most platforms one of
	// the two succeeds.
	if runtime.GOOS != "windows" {
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	}
	_ = p.cmd.Process.Kill()
	return nil
}

// wait blocks until the process exits + collects the exit
// status. Returns the cmd.Wait error; nil on clean exit, a
// *exec.ExitError on signal-killed.
func (p *Process) wait() error {
	if p.cmd == nil {
		return nil
	}
	err := p.cmd.Wait()
	p.cmd = nil
	return err
}

// PanicMarkerObserved reports whether stderr contains the chaos
// panic marker. Tests assert this after a kill to confirm the
// process died at the intended injection point, not from some
// unrelated panic.
func (p *Process) PanicMarkerObserved(marker string) bool {
	return strings.Contains(p.stderrBuf.String(), marker)
}

// StderrSnapshot returns the captured stderr content. Useful for
// diagnostic dumps in failed tests.
func (p *Process) StderrSnapshot() string {
	return p.stderrBuf.String()
}

// ResetCapture clears the stdout + stderr buffers. Call between
// Start cycles so panic-marker assertions after the second Start
// don't see the first start's logs.
func (p *Process) ResetCapture() {
	p.stderrBuf.Reset()
	p.stdoutBuf.Reset()
}

// Running reports whether Start has been called and Kill has
// not yet completed.
func (p *Process) Running() bool {
	return p.running.Load() == 1
}

// ─────────────────────────────────────────────────────────────────────
// Binary build + cache (per-process TestMain)
// ─────────────────────────────────────────────────────────────────────

var (
	binaryMu   sync.Mutex
	cachedPath string
	cachedErr  error
)

// EnsureLedgerBinary builds the cmd/ledger binary with -tags=chaos
// (so the injection points compile in) and caches the path for
// the rest of the test binary's lifetime. Subsequent calls return
// the same path. Concurrency-safe. Returns error on build failure.
//
// Call once from each chaos package's TestMain. Tests obtain the
// path via LedgerBinaryPath(t).
func EnsureLedgerBinary(modulePath string) (string, error) {
	binaryMu.Lock()
	defer binaryMu.Unlock()
	if cachedPath != "" || cachedErr != nil {
		return cachedPath, cachedErr
	}
	dir, err := os.MkdirTemp("", "chaos-ledger-bin-*")
	if err != nil {
		cachedErr = fmt.Errorf("mkdir chaos bin: %w", err)
		return "", cachedErr
	}
	binPath := filepath.Join(dir, "ledger")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	// -tags=chaos so chaos.Trigger uses the panic-on-match impl.
	build := exec.Command("go", "build", "-tags=chaos", "-o", binPath, "./cmd/ledger")
	build.Dir = modulePath
	var buildStderr bytes.Buffer
	build.Stderr = &buildStderr
	build.Stdout = &buildStderr
	if err := build.Run(); err != nil {
		cachedErr = fmt.Errorf("go build -tags=chaos cmd/ledger: %w\n%s",
			err, buildStderr.String())
		return "", cachedErr
	}
	cachedPath = binPath
	return cachedPath, nil
}

// LedgerBinaryPath returns the cached binary path, calling
// t.Fatalf if EnsureLedgerBinary was never called or failed.
func LedgerBinaryPath(t *testing.T) string {
	t.Helper()
	binaryMu.Lock()
	defer binaryMu.Unlock()
	if cachedPath == "" {
		t.Fatalf("ledger binary not built — TestMain must call EnsureLedgerBinary")
	}
	return cachedPath
}

// ─────────────────────────────────────────────────────────────────────
// Port allocation + /healthz polling
// ─────────────────────────────────────────────────────────────────────

// PickFreePort returns a TCP port that was free at the instant
// of the call. The standard "ask the kernel for :0, close,
// reuse" pattern; small TOCTOU window but matches what
// httptest.NewServer does.
func PickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("PickFreePort: %v", err)
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr)
	return addr.Port
}

// waitForHealthz polls url until it returns 200 or ctx/timeout
// expires. Used internally by Process.Start.
func waitForHealthz(ctx context.Context, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Timeout: 1 * time.Second}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			// 503 or other — keep polling; the server is up but
			// not ready yet.
			_ = body
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("healthz never returned 200 within %v: %w",
				timeout, ctx.Err())
		case <-ticker.C:
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// threadSafeBuffer — captures subprocess stdio for grep
// ─────────────────────────────────────────────────────────────────────

type threadSafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *threadSafeBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}
