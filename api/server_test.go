/*
FILE PATH: api/server_test.go

Locks the server's route table after the /v2/entries removal:

  - POST /v2/entries returns 404 (route is not mounted).
  - POST /v1/entries reaches the configured submission handler.
  - GET  /v1/admission/mmd reaches the configured MMD handler.
  - GET  /healthz and /readyz remain wired.

Thin tests — only the routing surface, not handler internals.
*/
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestServer wires the minimum Handlers needed to assert
// routing without touching Postgres. Server.NewServer registers
// several read endpoints unconditionally, so we populate them with
// noops to prevent the mux from panicking on a nil HandlerFunc.
func newTestServer(t *testing.T, h Handlers) *Server {
	t.Helper()
	cfg := DefaultServerConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.MaxEntrySize = 1 << 20
	if h.Submission == nil {
		h.Submission = noop
	}
	if h.TreeHead == nil {
		h.TreeHead = noop
	}
	if h.TreeInclusion == nil {
		h.TreeInclusion = noop
	}
	if h.TreeConsistency == nil {
		h.TreeConsistency = noop
	}
	if h.SMTProof == nil {
		h.SMTProof = noop
	}
	if h.SMTBatchProof == nil {
		h.SMTBatchProof = noop
	}
	if h.SMTRoot == nil {
		h.SMTRoot = noop
	}
	if h.CosignatureOf == nil {
		h.CosignatureOf = noop
	}
	if h.TargetRoot == nil {
		h.TargetRoot = noop
	}
	if h.SignerDID == nil {
		h.SignerDID = noop
	}
	if h.SchemaRef == nil {
		h.SchemaRef = noop
	}
	if h.Scan == nil {
		h.Scan = noop
	}
	if h.Difficulty == nil {
		h.Difficulty = noop
	}
	return NewServer(cfg, nil, h, discardLogger())
}

func TestServer_V2EntriesRouteNotMounted(t *testing.T) {
	called := false
	submission := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}
	srv := newTestServer(t, Handlers{Submission: submission})

	req := httptest.NewRequest(http.MethodPost, "/v2/entries", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("POST /v2/entries status = %d, want 404", rr.Code)
	}
	if called {
		t.Error("submission handler should not be called for /v2/entries")
	}
}

func TestServer_V1EntriesRouteReachesSubmissionHandler(t *testing.T) {
	called := false
	submission := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}
	srv := newTestServer(t, Handlers{Submission: submission})

	req := httptest.NewRequest(http.MethodPost, "/v1/entries", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if !called {
		t.Errorf("submission handler not invoked; status=%d", rr.Code)
	}
}

func TestServer_MMDRouteWired(t *testing.T) {
	mmd := NewMMDHandler(time.Hour)
	srv := newTestServer(t, Handlers{MMD: mmd})

	req := httptest.NewRequest(http.MethodGet, "/v1/admission/mmd", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /v1/admission/mmd status = %d, want 200", rr.Code)
	}
}

func TestServer_HealthAndReadyWired(t *testing.T) {
	srv := newTestServer(t, Handlers{})

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", path, rr.Code)
		}
	}
}

func noop(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }
