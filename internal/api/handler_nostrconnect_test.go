package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleNostrConnect_RequiresAuth verifies the /nostrconnect endpoint
// rejects unauthenticated callers. Approving a nostrconnect:// URI grants an
// app signing authority over a key, so an unauthenticated request must not
// reach that logic (the endpoint was previously open with CORS *).
func TestHandleNostrConnect_RequiresAuth(t *testing.T) {
	h, _ := testHandler(t)
	body := `{"uri":"nostrconnect://00?relay=wss://relay.cloistr.xyz&secret=s","key_id":"deadbeefdeadbeef"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", strings.NewReader(body))
	// Deliberately no Authorization header.
	rr := httptest.NewRecorder()

	h.handleNostrConnect(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("handleNostrConnect() without auth = %d, want %d (endpoint must require a session)", rr.Code, http.StatusUnauthorized)
	}
}

// TestHandleNostrConnect_MethodNotAllowed verifies only POST is accepted.
func TestHandleNostrConnect_MethodNotAllowed(t *testing.T) {
	h, _ := testHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nostrconnect", nil)
	rr := httptest.NewRecorder()

	h.handleNostrConnect(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleNostrConnect() GET = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}
