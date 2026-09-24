package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// /web/api/approve and /web/api/deny must require authentication. They were
// registered without requireAuth while every neighbouring route used it.

func TestHandleAPIApprove_RejectsNoAuth(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	store.CreatePendingRequest(ctx, &storage.PendingRequest{
		ID:           "req-noauth",
		KeyPubkey:    "1111111111111111111111111111111111111111111111111111111111111111",
		ClientPubkey: "2222222222222222222222222222222222222222222222222222222222222222",
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	})

	body := `{"request_id": "req-noauth", "remember": true}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/approve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("/web/api/approve without auth returned 200 — should be blocked")
	}
}

func TestHandleAPIDeny_RejectsNoAuth(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	store.CreatePendingRequest(ctx, &storage.PendingRequest{
		ID:           "req-noauth-deny",
		KeyPubkey:    "1111111111111111111111111111111111111111111111111111111111111111",
		ClientPubkey: "2222222222222222222222222222222222222222222222222222222222222222",
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	})

	body := `{"request_id": "req-noauth-deny"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/deny", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("/web/api/deny without auth returned 200 — should be blocked")
	}
}
