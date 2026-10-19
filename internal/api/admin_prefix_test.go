package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// Admin escalation by self-registration (proved on production by cloistr-pr,
// 2026-10-19): register "admin:mallory", sign in, and every admin check
// trusted the "admin:" username prefix. Admin is now only a configured admin
// pubkey (claims.UserID) or the stored admin role, and usernames cannot
// contain ':'.

const configAdminPubkey = "ad00000000000000000000000000000000000000000000000000000000000001"

// adminRoutes is every admin route of the API, with a method each.
var adminRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/admin/users"},
	{http.MethodGet, "/api/v1/admin/services"},
	{http.MethodGet, "/api/v1/admin/users/" + configAdminPubkey},
	{http.MethodDelete, "/api/v1/admin/users/victim-user"},
	{http.MethodPut, "/api/v1/admin/users/" + configAdminPubkey + "/services/files"},
	{http.MethodDelete, "/api/v1/admin/users/" + configAdminPubkey + "/services/files"},
}

func adminRoute(t *testing.T, h *Handler, method, path, token string) int {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr.Code
}

func adminFixture(t *testing.T) (*Handler, *storage.MemoryStorage) {
	t.Helper()
	h, store := testHandler(t)
	h.config.Auth.AdminPubkeys = []string{configAdminPubkey}
	for _, u := range []*storage.User{
		{ID: "mallory-id", Username: "admin:mallory", Role: "user"},
		{ID: "victim-user", Username: "victim", Role: "user"},
		{ID: "stored-admin", Username: "boss", Role: "admin"},
	} {
		u.PasswordHash, u.CreatedAt, u.UpdatedAt = "x", time.Now(), time.Now()
		if err := store.CreateUser(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	return h, store
}

func TestAdminRoutes_UsernamePrefixIsNotAdmin(t *testing.T) {
	h, store := adminFixture(t)
	for _, who := range []struct{ id, name string }{
		{"mallory-id", "admin:mallory"},      // stored user, role "user"
		{"no-such-user", "admin:ghost"},      // no stored user at all
		{"victim-user", "admin:" + "victim"}, // real user, forged name in token
	} {
		tok, _, err := auth.GenerateJWT(h.authConfig, who.id, who.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, rt := range adminRoutes {
			if code := adminRoute(t, h, rt.method, rt.path, tok); code != http.StatusForbidden {
				t.Errorf("%s %s as %q (%s): %d, want 403", rt.method, rt.path, who.name, who.id, code)
			}
		}
		if h.isAdminClaims(context.Background(), &auth.JWTClaims{UserID: who.id, Username: who.name}) {
			t.Errorf("isAdminClaims(%q, %q) = true, want false", who.id, who.name)
		}
	}
	if _, err := store.GetUser(context.Background(), "victim-user"); err != nil {
		t.Fatalf("victim account deleted by a non-admin: %v", err)
	}
}

func TestAdminRoutes_RealAdminsStillWork(t *testing.T) {
	h, _ := adminFixture(t)
	cfgTok, _, _ := auth.GenerateJWT(h.authConfig, configAdminPubkey, "admin:"+configAdminPubkey[:8])
	roleTok, _, _ := auth.GenerateJWT(h.authConfig, "stored-admin", "boss")
	for name, tok := range map[string]string{"config admin pubkey": cfgTok, "stored admin role": roleTok} {
		for _, path := range []string{"/api/v1/admin/users", "/api/v1/admin/services"} {
			if code := adminRoute(t, h, http.MethodGet, path, tok); code != http.StatusOK {
				t.Errorf("%s GET %s: %d, want 200", name, path, code)
			}
		}
	}
}

func TestRegister_RejectsColonInUsername(t *testing.T) {
	for _, name := range []string{"admin:mallory", "Admin:x", "a:b"} {
		h, store := testHandler(t)
		b, _ := json.Marshal(RegisterRequest{Username: name, Password: "correct-horse-battery"})
		rr := httptest.NewRecorder()
		h.handleUserRegister(rr, httptest.NewRequest(http.MethodPost, "/api/v1/users/register", bytes.NewReader(b)))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("register %q: %d %s, want 400", name, rr.Code, rr.Body.String())
		}
		if _, err := store.GetUserByUsername(context.Background(), name); err == nil {
			t.Errorf("register %q created the account", name)
		}
	}
}
