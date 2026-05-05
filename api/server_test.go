/*
FILE PATH: api/server_test.go

Locks the server's route table after the /v2/entries removal +
asynchronous batch-submission wiring:

  - POST /v2/entries returns 404 (route is not mounted).
  - POST /v1/entries reaches the configured submission handler.
  - POST /v1/entries/batch reaches the configured batch handler
    when wired; returns 404 when not.
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

func TestServer_BatchEntriesRouteReachesBatchHandler(t *testing.T) {
	called := false
	batch := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}
	srv := newTestServer(t, Handlers{BatchSubmission: batch})

	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if !called {
		t.Errorf("batch handler not invoked; status=%d", rr.Code)
	}
}

// When BatchSubmission is unset the route must not be mounted —
// returning 404 (not 500 or panicking through a nil HandlerFunc).
func TestServer_BatchEntriesRouteNotMountedWhenNil(t *testing.T) {
	srv := newTestServer(t, Handlers{})

	req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("POST /v1/entries/batch with nil handler: status = %d, want 404", rr.Code)
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

// TestServer_GossipFeedRoutes_Mounted pins all five v1
// gossip feed routes — including /by-binding/{hash}, the
// v0.9.6 zero-trust audit endpoint added by Tier 1 P9.
//
// Without this test, /by-binding/{hash} could regress to 404
// (the SDK FeedHandler internally dispatches the path; the
// operator-side gap is the mux Handle call).
func TestServer_GossipFeedRoutes_Mounted(t *testing.T) {
	called := 0
	feed := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	srv := newTestServer(t, Handlers{GossipFeed: feed})

	const splitID32 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	cases := []struct {
		path string
	}{
		{"/v1/gossip/sth/latest"},
		{"/v1/gossip/since"},
		{"/v1/gossip/by-kind"},
		{"/v1/gossip/event/" + splitID32},
		{"/v1/gossip/by-binding/" + splitID32},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200 (route not mounted?)",
				tc.path, rr.Code)
		}
	}
	if called != len(cases) {
		t.Errorf("GossipFeed handler invocations = %d, want %d",
			called, len(cases))
	}
}

// TestServer_GossipFeedByBinding_NotMountedWhenFeedNil pins
// the nil-tolerance contract for the new /by-binding route:
// when GossipFeed is nil, /by-binding/{hash} returns 404
// (not 500 or a nil-handler panic).
func TestServer_GossipFeedByBinding_NotMountedWhenFeedNil(t *testing.T) {
	srv := newTestServer(t, Handlers{}) // GossipFeed nil

	req := httptest.NewRequest(http.MethodGet,
		"/v1/gossip/by-binding/0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("GET /v1/gossip/by-binding/{hash} with nil GossipFeed: status = %d, want 404",
			rr.Code)
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
