package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// GET /api/v1/session: a side-effect-free "am I signed in?" probe for the
// shared login UI. @cloistr/ui probed /api/v1/keys instead, so every
// signed-out page logged a 401 console error. Signed out is a normal answer
// here (200 {authenticated:false}), and nothing about keys is returned.

const probeKeyPubkey = "dd00000000000000000000000000000000000000000000000000000000000004"

func probeFixture(t *testing.T) (*Handler, *storage.MemoryStorage, *http.ServeMux, string) {
	t.Helper()
	h, store := testHandler(t)
	ctx := context.Background()
	if err := store.CreateUser(ctx, &storage.User{ID: testUserID, Username: "testuser", PasswordHash: "x", Pubkey: "ee00000000000000000000000000000000000000000000000000000000000005", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateKey(ctx, &storage.Key{ID: "k-probe", Pubkey: probeKeyPubkey, OwnerID: testUserID, EncryptedNsec: "vault:v1:abc", IsPrimary: true, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tok, exp, err := auth.GenerateJWTWithSession(h.authConfig, testUserID, "testuser", "sess-probe")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUserSession(ctx, &storage.UserSession{ID: "sess-probe", UserID: testUserID, Token: tok[:16], ExpiresAt: exp, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return h, store, mux, tok
}

func probe(t *testing.T, mux *http.ServeMux, method string, set func(*http.Request)) (int, map[string]any, http.Header) {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/session", nil)
	if set != nil {
		set(req)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body, rr.Header()
}

func bodyKeys(m map[string]any) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

func TestSessionProbe_SignedOutIs200False(t *testing.T) {
	h, _, mux, _ := probeFixture(t)
	ended, _, _ := auth.GenerateJWTWithSession(h.authConfig, testUserID, "testuser", "sess-gone")
	for name, set := range map[string]func(*http.Request){
		"no token":      nil,
		"garbage token": func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-jwt") },
		"ended session": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+ended) },
		"garbage cookie": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "auth_token", Value: "not-a-jwt"})
		},
	} {
		code, body, hdr := probe(t, mux, http.MethodGet, set)
		if code != http.StatusOK || body["authenticated"] != false || len(body) != 1 {
			t.Errorf("%s: %d %v, want 200 {authenticated:false}", name, code, body)
		}
		if hdr.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", name, hdr.Get("Cache-Control"))
		}
	}
}

func TestSessionProbe_SignedInGivesPubkeyOnly(t *testing.T) {
	_, _, mux, tok := probeFixture(t)
	for name, set := range map[string]func(*http.Request){
		"bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) },
		"cookie": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "auth_token", Value: tok}) },
	} {
		code, body, _ := probe(t, mux, http.MethodGet, set)
		if code != http.StatusOK || body["authenticated"] != true || body["pubkey"] != probeKeyPubkey {
			t.Errorf("%s: %d %v, want 200 authenticated:true with the signing pubkey", name, code, body)
		}
		if got := bodyKeys(body); len(got) != 2 || got[0] != "authenticated" || got[1] != "pubkey" {
			t.Errorf("%s: response fields %v, want exactly [authenticated pubkey] (no keys listed)", name, got)
		}
	}
}

// The probe must not load or unlock keys, or touch the session.
func TestSessionProbe_NoSideEffects(t *testing.T) {
	h, store, mux, tok := probeFixture(t)
	before, _ := store.GetUserSession(context.Background(), "sess-probe")
	beforeCopy := *before
	for i := 0; i < 3; i++ {
		probe(t, mux, http.MethodGet, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) })
	}
	if h.signer.IsKeyLoaded(probeKeyPubkey) {
		t.Fatalf("probe loaded the signing key")
	}
	after, _ := store.GetUserSession(context.Background(), "sess-probe")
	if after.LastActivity != beforeCopy.LastActivity || !after.ExpiresAt.Equal(beforeCopy.ExpiresAt) {
		t.Fatalf("probe changed the session: before %+v after %+v", beforeCopy, *after)
	}
	if code, _, _ := probe(t, mux, http.MethodPost, nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d, want 405", code)
	}
}

// A signed-in account with no signing key reports its derived platform pubkey.
func TestSessionProbe_NoKeyFallsBackToAccountPubkey(t *testing.T) {
	_, store, mux, tok := probeFixture(t)
	if err := store.DeleteKey(context.Background(), "k-probe"); err != nil {
		t.Fatal(err)
	}
	_, body, _ := probe(t, mux, http.MethodGet, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) })
	if body["authenticated"] != true || body["pubkey"] != "ee00000000000000000000000000000000000000000000000000000000000005" {
		t.Fatalf("no-key account: %v, want its account pubkey", body)
	}
}
