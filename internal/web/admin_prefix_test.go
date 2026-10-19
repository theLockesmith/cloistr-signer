package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
)

// The web UI's admin check (getCurrentUser) trusted the "admin:" username
// prefix; only a configured admin pubkey or the stored role counts now.
func TestGetCurrentUser_UsernamePrefixIsNotAdmin(t *testing.T) {
	h, store, _ := testHandler(t)
	_, mallory := createTestUser(t, h, store, "admin:mallory")
	for _, who := range []struct{ id, name string }{{mallory.ID, mallory.Username}, {"no-such-user", "admin:ghost"}} {
		tok, _, _ := auth.GenerateJWT(h.authConfig, who.id, who.name)
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: tok})
		if u := h.getCurrentUser(req); u != nil && u.IsAdmin() {
			t.Errorf("token for %q (%s) is treated as admin", who.name, who.id)
		}
		rr := httptest.NewRecorder()
		h.handleUsers(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("/users as %q: %d, want the non-admin redirect", who.name, rr.Code)
		}
	}

	const adminPK = "ad00000000000000000000000000000000000000000000000000000000000001"
	h.config.Auth.AdminPubkeys = []string{adminPK}
	tok, _, _ := auth.GenerateJWT(h.authConfig, adminPK, "admin:"+adminPK[:8])
	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: tok})
	if u := h.getCurrentUser(req); u == nil || !u.IsAdmin() {
		t.Errorf("configured admin pubkey is not admin: %+v", u)
	}
}

func TestAPIRegister_RejectsColonInUsername(t *testing.T) {
	h, store, _ := testHandler(t)
	b, _ := json.Marshal(map[string]string{"username": "admin:mallory", "password": "correct-horse-battery"})
	rr := httptest.NewRecorder()
	h.handleAPIRegister(rr, httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(b)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("register admin:mallory: %d %s, want 400", rr.Code, rr.Body.String())
	}
	if _, err := store.GetUserByUsername(context.Background(), "admin:mallory"); err == nil {
		t.Errorf("register admin:mallory created the account")
	}
}
