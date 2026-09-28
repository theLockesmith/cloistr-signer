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

// Grant renewal: the key's OWNER extends a LIVE grant, bounded, without widening
// it. These tests pin both halves: the owner is admitted, and everything the
// feature must refuse is refused.

func seedGrant(t *testing.T, store *storage.MemoryStorage, key *storage.Key, expires *time.Time) {
	t.Helper()
	if err := store.SetPermission(context.Background(), &storage.Permission{
		KeyID: key.Pubkey, UserPubkey: testClientPubkey,
		Methods: []string{"connect", "get_public_key", "sign_event"}, AllowedKinds: []int{27235, 30078},
		ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("SetPermission: %v", err)
	}
}

func renew(h *Handler, keyID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/permissions/"+testClientPubkey+"/renew", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.handleRenewPermission(rr, req, keyID, testClientPubkey)
	return rr
}

func rawGrant(t *testing.T, store *storage.MemoryStorage, key *storage.Key) *storage.Permission {
	t.Helper()
	p, err := store.GetPermission(context.Background(), key.Pubkey, testClientPubkey)
	if err != nil {
		t.Fatalf("GetPermission: %v", err)
	}
	return p
}

func TestRenew_OwnerExtendsLiveGrantWithoutWideningIt(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	soon := time.Now().Add(24 * time.Hour)
	seedGrant(t, store, key, &soon)

	rr := renew(h, key.ID, makeSessionToken(t, h, testUserIDSess), `{}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rr.Code, rr.Body)
	}
	p := rawGrant(t, store, key)
	if d := time.Until(*p.ExpiresAt); d < 29*24*time.Hour || d > 30*24*time.Hour+time.Minute {
		t.Errorf("expiry now %v from now, want ~30 days", d)
	}
	if strings.Join(p.Methods, ",") != "connect,get_public_key,sign_event" || len(p.AllowedKinds) != 2 {
		t.Errorf("scope changed: methods %v kinds %v", p.Methods, p.AllowedKinds)
	}
}

func TestRenew_CappedAtThirtyDays(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	soon := time.Now().Add(time.Hour)
	seedGrant(t, store, key, &soon)
	renew(h, key.ID, makeSessionToken(t, h, testUserIDSess), `{"days":365}`)
	if d := time.Until(*rawGrant(t, store, key).ExpiresAt); d > 30*24*time.Hour+time.Minute {
		t.Errorf("renewal went %v out, cap is 30 days", d)
	}
}

func TestRenew_NeverShortens(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	far := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	seedGrant(t, store, key, &far)
	rr := renew(h, key.ID, makeSessionToken(t, h, testUserIDSess), `{"days":3}`)
	var body map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusOK || body["renewed"] != false {
		t.Errorf("status %d body %v, want 200 renewed=false", rr.Code, body)
	}
	if !rawGrant(t, store, key).ExpiresAt.Equal(far) {
		t.Error("a renewal shortened a grant")
	}
}

func TestRenew_RefusesUnauthenticated(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	soon := time.Now().Add(time.Hour)
	seedGrant(t, store, key, &soon)
	if rr := renew(h, key.ID, "", `{}`); rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestRenew_RefusesNonOwner(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	soon := time.Now().Add(time.Hour)
	seedGrant(t, store, key, &soon)
	if rr := renew(h, key.ID, makeSessionToken(t, h, "someone-else"), `{}`); rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if time.Until(*rawGrant(t, store, key).ExpiresAt) > 2*time.Hour {
		t.Error("a non-owner extended the grant")
	}
}

func TestRenew_RefusesExpiredGrant(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	past := time.Now().Add(-time.Hour)
	seedGrant(t, store, key, &past)
	if rr := renew(h, key.ID, makeSessionToken(t, h, testUserIDSess), `{}`); rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (lapsed grants need a fresh approval)", rr.Code)
	}
}

func TestRenew_RefusesRevokedGrant(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	soon := time.Now().Add(time.Hour)
	now := time.Now()
	if err := store.SetPermission(context.Background(), &storage.Permission{
		KeyID: key.Pubkey, UserPubkey: testClientPubkey, Methods: []string{"sign_event"},
		ExpiresAt: &soon, RevokedAt: &now, RevokedBy: "displacer",
	}); err != nil {
		t.Fatal(err)
	}
	if rr := renew(h, key.ID, makeSessionToken(t, h, testUserIDSess), `{}`); rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rr.Code)
	}
}

func TestRenew_RefusedOnceOwnerSessionEnds(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	soon := time.Now().Add(time.Hour)
	seedGrant(t, store, key, &soon)
	sess := &storage.UserSession{ID: "sess-renew-1", UserID: testUserIDSess, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	if err := store.CreateUserSession(context.Background(), sess); err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	token, _, err := auth.GenerateJWTWithSession(h.authConfig, testUserIDSess, "testuser", sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rr := renew(h, key.ID, token, `{}`); rr.Code != http.StatusOK {
		t.Fatalf("live session: status = %d, want 200 (control)", rr.Code)
	}
	if err := store.DeleteUserSession(context.Background(), sess.ID); err != nil {
		t.Fatal(err)
	}
	if rr := renew(h, key.ID, token, `{}`); rr.Code != http.StatusUnauthorized {
		t.Errorf("ended session: status = %d, want 401", rr.Code)
	}
}

func TestRenew_RouteIsPOSTOnly(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/"+key.ID+"/permissions/"+testClientPubkey+"/renew", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET renew: status = %d, want 405", rr.Code)
	}
}

func TestRenew_RoutedPOSTRenews(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	soon := time.Now().Add(time.Hour)
	seedGrant(t, store, key, &soon)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+key.ID+"/permissions/"+testClientPubkey+"/renew", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("routed POST renew: status = %d, want 200; body %s", rr.Code, rr.Body)
	}
}
