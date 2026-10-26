package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// An account named in ADMIN_USER_IDS is an admin for authorization (the admin
// Users API) and is reported as one to the UI; an ordinary account is neither.
func TestAdminUserIDs_GrantAdminAuthorization(t *testing.T) {
	h, store := testHandler(t)
	h.config.Auth.AdminUserIDs = []string{"admin-acct"}
	for _, id := range []string{"admin-acct", "plain-acct"} {
		if err := store.CreateUser(context.Background(), &storage.User{ID: id, Username: id, Role: "user", PasswordHash: "x", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		id        string
		wantUsers int
		wantAdmin bool
	}{
		{"admin-acct", http.StatusOK, true},
		{"plain-acct", http.StatusForbidden, false},
	} {
		token, _, _ := auth.GenerateJWT(h.authConfig, tc.id, tc.id)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		h.handleAdminUsers(rr, req)
		if rr.Code != tc.wantUsers {
			t.Errorf("%s: GET /admin/users = %d, want %d (%s)", tc.id, rr.Code, tc.wantUsers, rr.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr = httptest.NewRecorder()
		h.handleUserMe(rr, req)
		var me map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &me); rr.Code != http.StatusOK || err != nil {
			t.Fatalf("%s: GET /users/me = %d %s", tc.id, rr.Code, rr.Body.String())
		}
		if got, _ := me["is_admin"].(bool); got != tc.wantAdmin {
			t.Errorf("%s: /users/me is_admin = %v, want %v", tc.id, me["is_admin"], tc.wantAdmin)
		}
	}
}

// The stored admin role is reported to the UI too (it never was, so the
// admin Users page redirected every account away).
func TestUserMe_ReportsStoredAdminRole(t *testing.T) {
	h, store := testHandler(t)
	if err := store.CreateUser(context.Background(), &storage.User{ID: "role-admin", Username: "role-admin", Role: "admin", PasswordHash: "x", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	token, _, _ := auth.GenerateJWT(h.authConfig, "role-admin", "role-admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.handleUserMe(rr, req)
	var me map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil || me["is_admin"] != true {
		t.Fatalf("/users/me = %d %s; want is_admin true", rr.Code, rr.Body.String())
	}
}
