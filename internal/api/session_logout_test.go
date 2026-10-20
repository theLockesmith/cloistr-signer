package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// POST /api/v1/users/logout ends EVERY session of the account (and unloads
// keys, drops seals, revokes app consents), so neither a user signing out one
// device nor a client ending its own login could do just that.
// POST /api/v1/users/session/logout ends only the presented token's session.

type twoSessions struct {
	h          *Handler
	store      *storage.MemoryStorage
	tokA, tokB string
	sidA, sidB string
	mux        *http.ServeMux
}

func newTwoSessions(t *testing.T) *twoSessions {
	t.Helper()
	h, store := testHandler(t)
	ctx := context.Background()
	if err := store.CreateUser(ctx, &storage.User{ID: testUserID, Username: "testuser", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	f := &twoSessions{h: h, store: store, mux: http.NewServeMux()}
	h.RegisterRoutes(f.mux)
	for _, s := range []struct {
		sid *string
		tok *string
		id  string
	}{{&f.sidA, &f.tokA, "sess-a"}, {&f.sidB, &f.tokB, "sess-b"}} {
		tok, exp, err := auth.GenerateJWTWithSession(h.authConfig, testUserID, "testuser", s.id)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CreateUserSession(ctx, &storage.UserSession{ID: s.id, UserID: testUserID, Token: tok[:16], ExpiresAt: exp, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := store.UpsertSessionSeal(ctx, &storage.SessionSeal{ID: "seal-" + s.id, UserID: testUserID, KeyID: "k1", Pubkey: "pk1", SessionID: s.id, Mode: "vault", Sealed: []byte("x"), ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		*s.sid, *s.tok = s.id, tok
	}
	if err := store.RecordAppConsent(ctx, testUserID, "app-pubkey", "Some App"); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *twoSessions) call(method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)
	return rr
}

func TestSessionLogout_EndsOnlyThisSession(t *testing.T) {
	f := newTwoSessions(t)
	ctx := context.Background()
	if rr := f.call(http.MethodPost, "/api/v1/users/session/logout", f.tokA); rr.Code != http.StatusOK {
		t.Fatalf("session logout: %d %s, want 200", rr.Code, rr.Body.String())
	}
	if rr := f.call(http.MethodGet, "/api/v1/users/me", f.tokA); rr.Code != http.StatusUnauthorized {
		t.Fatalf("ended session's token: %d, want 401", rr.Code)
	}
	if rr := f.call(http.MethodGet, "/api/v1/users/me", f.tokB); rr.Code != http.StatusOK {
		t.Fatalf("other session's token after one sign-out: %d %s, want 200", rr.Code, rr.Body.String())
	}
	if seals, _ := f.store.ListSessionSealsBySession(ctx, f.sidA); len(seals) != 0 {
		t.Fatalf("ended session still has %d seals", len(seals))
	}
	if seals, _ := f.store.ListSessionSealsBySession(ctx, f.sidB); len(seals) != 1 {
		t.Fatalf("other session's seals = %d, want 1 (untouched)", len(seals))
	}
	if ok, _ := f.store.HasAppConsent(ctx, testUserID, "app-pubkey"); !ok {
		t.Fatalf("one-session sign-out revoked app consents")
	}
}

// The session's own browser cookies are cleared, and a call with no or a
// dead token still succeeds (sign-out is idempotent).
func TestSessionLogout_ClearsCookiesAndIsIdempotent(t *testing.T) {
	f := newTwoSessions(t)
	rr := f.call(http.MethodPost, "/api/v1/users/session/logout", f.tokA)
	cleared := map[string]bool{}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 {
			cleared[c.Name] = true
		}
	}
	if !cleared["auth_token"] {
		t.Fatalf("auth_token cookie not cleared: %v", rr.Result().Cookies())
	}
	for _, tok := range []string{f.tokA, ""} {
		if rr := f.call(http.MethodPost, "/api/v1/users/session/logout", tok); rr.Code != http.StatusOK {
			t.Fatalf("repeat sign-out (token=%v): %d, want 200", tok != "", rr.Code)
		}
	}
	if rr := f.call(http.MethodGet, "/api/v1/users/session/logout", f.tokB); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d, want 405", rr.Code)
	}
	if rr := f.call(http.MethodGet, "/api/v1/users/me", f.tokB); rr.Code != http.StatusOK {
		t.Fatalf("other session after repeats: %d, want 200", rr.Code)
	}
}

// The existing endpoint stays "sign out everywhere".
func TestLogout_StillSignsOutEverywhere(t *testing.T) {
	f := newTwoSessions(t)
	if rr := f.call(http.MethodPost, "/api/v1/users/logout", f.tokA); rr.Code != http.StatusOK {
		t.Fatalf("logout: %d", rr.Code)
	}
	for name, tok := range map[string]string{"A": f.tokA, "B": f.tokB} {
		if rr := f.call(http.MethodGet, "/api/v1/users/me", tok); rr.Code != http.StatusUnauthorized {
			t.Fatalf("session %s after sign-out everywhere: %d, want 401", name, rr.Code)
		}
	}
	if ok, _ := f.store.HasAppConsent(context.Background(), testUserID, "app-pubkey"); ok {
		t.Fatalf("sign-out everywhere kept app consents")
	}
}
