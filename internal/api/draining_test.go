package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Once the pod is told to stop, readiness must fail at once so traffic moves
// to the other replica while this one keeps serving what it already has.
func TestHandleReady_FailsWhileDraining(t *testing.T) {
	h, _ := testHandler(t)
	h.StartDraining()

	rr := httptest.NewRecorder()
	h.handleReady(rr, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	// The test handler has no relays, so readiness is 503 regardless; only
	// the body proves the drain flag is what failed it.
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "shutting down") {
		t.Fatalf("readiness while draining = %d %s, want 503 \"not ready - shutting down\"", rr.Code, rr.Body.String())
	}

	// Liveness and ordinary health stay 200: the pod is still serving.
	rr = httptest.NewRecorder()
	h.handleLive(rr, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("liveness while draining = %d, want 200", rr.Code)
	}
}
