package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// linkKeyWriteFails: storing a linking key hits a real write error.
type linkKeyWriteFails struct{ storage.Storage }

func (linkKeyWriteFails) CreateLightningKey(context.Context, *storage.LightningKey) error {
	return errors.New("disk I/O error")
}

func linkChallenge(t *testing.T, h *Handler) (k1, sid string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/link/challenge", nil)
	addAuthHeader(t, h, req)
	return lnChallengeVia(t, h, req, h.handleLightningLinkChallenge)
}

func lnChallengeVia(t *testing.T, h *Handler, req *http.Request, handle func(http.ResponseWriter, *http.Request)) (string, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	handle(rr, req)
	var body map[string]string
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &body) != nil {
		t.Fatalf("challenge: %d %s", rr.Code, rr.Body.String())
	}
	return body["k1"], body["session_id"]
}

// A link whose key could not be stored must not be reported as linked: the
// wallet gets an error and the browser's poll stays pending, so the user is
// not told a key is linked when it is not. (The claim used to happen first,
// so the poll said "linked" after a failed write.)
func TestLightningLink_StoreFailureIsNotReportedLinked(t *testing.T) {
	a, _, store, _ := lightningReplicas(t)
	if err := store.CreateUser(context.Background(), &storage.User{ID: testUserID, Username: "linker", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(a.config, signer.New(a.config, store, nil, nil, nil, nil, nil), linkKeyWriteFails{store}, nil, nil)
	wallet := newLNWallet(t)

	k1, sid := linkChallenge(t, h)
	if cb := lnCallback(t, h, wallet.callbackQuery(t, k1)); cb["status"] != "ERROR" {
		t.Fatalf("callback after a failed key write: %v, want ERROR", cb)
	}
	if code, body, cookies := lnStatus(t, h, sid); body["success"] == true || len(cookies) != 0 {
		t.Fatalf("poll after a failed key write: %d %v cookies=%d, want not linked", code, body, len(cookies))
	}
	// The wallet may retry the same challenge once storage recovers.
	h.storage = store
	if cb := lnCallback(t, h, wallet.callbackQuery(t, k1)); cb["status"] != "OK" {
		t.Fatalf("retry after storage recovered: %v, want OK", cb)
	}
	if code, body, _ := lnStatus(t, h, sid); code != http.StatusOK || body["success"] != true {
		t.Fatalf("poll after the retry: %d %v, want linked", code, body)
	}
}

// A wallet key already linked to ANOTHER account cannot be linked here, and
// the link is not reported as done.
func TestLightningLink_KeyOfAnotherAccountRefused(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t) // wallet's key belongs to ln-user
	if err := store.CreateUser(context.Background(), &storage.User{ID: testUserID, Username: "linker", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	k1, sid := linkChallenge(t, a) // signed in as testUserID
	if cb := lnCallback(t, a, wallet.callbackQuery(t, k1)); cb["status"] != "ERROR" {
		t.Fatalf("linking another account's key: %v, want ERROR", cb)
	}
	if _, body, cookies := lnStatus(t, a, sid); body["success"] == true || len(cookies) != 0 {
		t.Fatalf("poll: %v cookies=%d, want not linked", body, len(cookies))
	}
}

// Linking a key that is already this user's own stays a no-op success.
func TestLightningLink_OwnKeyAgainIsOK(t *testing.T) {
	a, _, store, _ := lightningReplicas(t)
	if err := store.CreateUser(context.Background(), &storage.User{ID: testUserID, Username: "linker", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	wallet := newLNWallet(t)
	for i := 0; i < 2; i++ {
		k1, sid := linkChallenge(t, a)
		if cb := lnCallback(t, a, wallet.callbackQuery(t, k1)); cb["status"] != "OK" {
			t.Fatalf("link %d: %v", i+1, cb)
		}
		if code, body, _ := lnStatus(t, a, sid); code != http.StatusOK || body["success"] != true {
			t.Fatalf("poll %d: %d %v", i+1, code, body)
		}
	}
	if keys, _ := store.ListLightningKeys(context.Background(), testUserID); len(keys) != 1 {
		t.Fatalf("keys after linking twice = %d, want 1", len(keys))
	}
}
