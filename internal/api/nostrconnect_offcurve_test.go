package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A client pubkey that is 64 hex chars but not an x coordinate on secp256k1
// can never receive an encrypted reply, so the session would be dead on
// arrival. Both nostrconnect endpoints must refuse it with 400 and store
// nothing.
func TestNostrConnect_OffCurveClientPubkeyRefused(t *testing.T) {
	offCurve := []string{
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // not on the curve
		"0000000000000000000000000000000000000000000000000000000000000005", // not on the curve
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // >= field prime
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // not hex
	}
	endpoints := []struct {
		path string
		call func(h *Handler) http.HandlerFunc
	}{
		{"/api/v1/nostrconnect", func(h *Handler) http.HandlerFunc { return h.handleNostrConnect }},
		{"/api/v1/nostrconnect/session", func(h *Handler) http.HandlerFunc { return h.handleNostrConnectSession }},
	}
	for _, ep := range endpoints {
		for _, pk := range offCurve {
			t.Run(ep.path+"/"+pk[:6], func(t *testing.T) {
				h, store := testHandler(t)
				key := seedUserAndKey(t, store)
				unlockKey(h, key)

				body, _ := json.Marshal(map[string]any{
					"uri": validNostrConnectURI(pk, "wss://relay.cloistr.xyz", "TestApp"), "key_id": key.ID, "consent": true,
				})
				req := httptest.NewRequest(http.MethodPost, ep.path, bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()
				ep.call(h)(rr, req)

				if rr.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400\nbody: %s", rr.Code, rr.Body.String())
				}
				if !strings.Contains(rr.Body.String(), "client pubkey") {
					t.Errorf("body %q does not name the client pubkey", rr.Body.String())
				}
				if perm, _ := store.GetPermission(context.Background(), key.Pubkey, pk); perm != nil {
					t.Error("a permission was stored for an off-curve client")
				}
				if ok, _ := store.HasAppConsent(context.Background(), testUserIDSess, pk); ok {
					t.Error("consent was stored for an off-curve client")
				}
			})
		}
	}
}
