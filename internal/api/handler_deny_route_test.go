package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The signer UI's Deny button calls /requests/{id}/reject. handleRequestByID
// only ever routed "approve" and "deny", so /reject fell through to the
// default arm and answered 405. Deny did nothing, silently. Nobody noticed
// because REQUIRE_APPROVAL is off, so the request queue is always empty and
// there has never been anything to deny. It would have surfaced on the day
// approval was switched on, which is the same day the missing auth check
// would have mattered.
func TestHandleRequestByID_DenyRouteAliases(t *testing.T) {
	for _, action := range []string{"deny", "reject"} {
		t.Run(action, func(t *testing.T) {
			h, _ := testHandler(t)

			path := "/api/v1/requests/nonexistent/" + action
			req := httptest.NewRequest(http.MethodPost, path, nil)
			rr := httptest.NewRecorder()

			h.handleRequestByID(rr, req)

			if rr.Code == http.StatusMethodNotAllowed {
				t.Fatalf("%s is not routed: status = 405, so the handler was never reached", action)
			}
			// The id does not exist, so whatever it reaches must say so.
			if rr.Code != http.StatusNotFound {
				t.Errorf("%s: status = %d, want %d (body %q)",
					action, rr.Code, http.StatusNotFound, rr.Body.String())
			}
		})
	}
}

// An action that genuinely is not supported must still be refused, so the
// test above cannot be satisfied by routing everything to deny.
func TestHandleRequestByID_UnknownActionStill405(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/requests/nonexistent/obliterate", nil)
	rr := httptest.NewRecorder()

	h.handleRequestByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("unknown action: status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}
