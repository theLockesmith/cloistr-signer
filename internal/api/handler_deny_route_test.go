package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /deny must be routed (not 405). The old UI shipped with /reject, which was
// never routed and answered 405 silently; the UI source was fixed and the
// embedded dist rebuilt so /reject is no longer called by anything. The alias
// was removed and "reject" is now asserted as 405 in the unknown-action test.
func TestHandleRequestByID_DenyRoute(t *testing.T) {
	h, _ := testHandler(t)

	path := "/api/v1/requests/nonexistent/deny"
	req := httptest.NewRequest(http.MethodPost, path, nil)
	rr := httptest.NewRecorder()

	h.handleRequestByID(rr, req)

	if rr.Code == http.StatusMethodNotAllowed {
		t.Fatalf("deny is not routed: status = 405, so the handler was never reached")
	}
	// The id does not exist, so whatever it reaches must say so.
	if rr.Code != http.StatusNotFound {
		t.Errorf("deny: status = %d, want %d (body %q)",
			rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

// Actions that are not routed must 405. "reject" is here deliberately: the old
// UI called it, the alias was removed once the embedded dist was rebuilt to
// call /deny, and this test proves it stays gone.
func TestHandleRequestByID_UnknownActionStill405(t *testing.T) {
	h, _ := testHandler(t)

	for _, action := range []string{"reject", "obliterate"} {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/requests/nonexistent/"+action, nil)
			rr := httptest.NewRecorder()

			h.handleRequestByID(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want %d", action, rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
