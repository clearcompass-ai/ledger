/*
FILE PATH: api/mmd_test.go

Unit-level coverage for NewMMDHandler. Asserts:
  - Configured MMD round-trips through the JSON response in both
    seconds and human form, across a range of durations.
  - Content-Type is application/json.
  - Status is 200 OK.
  - The handler is method-agnostic (matches the mux's permissive
    GET binding — the route registration filters method, not the
    handler).
*/
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMMDHandler_RoundsToConfiguredValue(t *testing.T) {
	for _, mmd := range []time.Duration{
		time.Second, 30 * time.Second, 24 * time.Hour, 7 * 24 * time.Hour,
	} {
		h := NewMMDHandler(mmd)
		req := httptest.NewRequest(http.MethodGet, "/v1/admission/mmd", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("mmd=%v: status = %d, want 200", mmd, rr.Code)
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("mmd=%v: Content-Type = %q, want application/json", mmd, got)
		}
		var body struct {
			MMDSeconds float64 `json:"mmd_seconds"`
			MMDHuman   string  `json:"mmd_human"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
			t.Errorf("mmd=%v: decode: %v", mmd, err)
			continue
		}
		if body.MMDSeconds != mmd.Seconds() {
			t.Errorf("mmd=%v: mmd_seconds = %v, want %v", mmd, body.MMDSeconds, mmd.Seconds())
		}
		if body.MMDHuman != mmd.String() {
			t.Errorf("mmd=%v: mmd_human = %q, want %q", mmd, body.MMDHuman, mmd.String())
		}
	}
}

// Sub-second MMDs round-trip cleanly. Pinned because mmd.Seconds()
// returns a float64 and ms-scale values previously raised concern
// about precision drift through JSON.
func TestMMDHandler_SubSecondMMD(t *testing.T) {
	mmd := 250 * time.Millisecond
	h := NewMMDHandler(mmd)
	req := httptest.NewRequest(http.MethodGet, "/v1/admission/mmd", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var body struct {
		MMDSeconds float64 `json:"mmd_seconds"`
		MMDHuman   string  `json:"mmd_human"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.MMDSeconds != 0.25 {
		t.Errorf("mmd_seconds = %v, want 0.25", body.MMDSeconds)
	}
	if body.MMDHuman != "250ms" {
		t.Errorf("mmd_human = %q, want %q", body.MMDHuman, "250ms")
	}
}

// Zero-duration MMD is a degenerate but representable input — the
// handler must not crash, must serialize cleanly. It is the
// composition root's job (cmd/ledger) to refuse to start with
// MMD=0; the handler is permissive by design.
func TestMMDHandler_ZeroDuration(t *testing.T) {
	h := NewMMDHandler(0)
	req := httptest.NewRequest(http.MethodGet, "/v1/admission/mmd", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	var body struct {
		MMDSeconds float64 `json:"mmd_seconds"`
		MMDHuman   string  `json:"mmd_human"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.MMDSeconds != 0 {
		t.Errorf("mmd_seconds = %v, want 0", body.MMDSeconds)
	}
	if body.MMDHuman != "0s" {
		t.Errorf("mmd_human = %q, want %q", body.MMDHuman, "0s")
	}
}

// Method-agnostic: the handler itself does not enforce method (the
// route registration does). A POST gets a 200 for the same payload
// as a GET. Locks the handler's behavior in case the mux ever
// changes how it filters.
func TestMMDHandler_MethodAgnostic(t *testing.T) {
	h := NewMMDHandler(time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/v1/admission/mmd", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}
