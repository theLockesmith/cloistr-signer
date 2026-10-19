package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// sqliteLNCallback answers a challenge the way an LNURL-auth wallet does.
func sqliteLNCallback(t *testing.T, h *Handler, priv *secp256k1.PrivateKey, k1 string) map[string]string {
	t.Helper()
	b, _ := hex.DecodeString(k1)
	sum := sha256.Sum256(b)
	q := url.Values{"tag": {"login"}, "k1": {k1},
		"key": {hex.EncodeToString(priv.PubKey().SerializeCompressed())},
		"sig": {hex.EncodeToString(ecdsa.Sign(priv, sum[:]).Serialize())}}
	rr := httptest.NewRecorder()
	h.handleLNURLAuthCallback(rr, httptest.NewRequest(http.MethodGet, "/api/v1/lnurl-auth/callback?"+q.Encode(), nil))
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return body
}

func sqliteLNChallenge(t *testing.T, h *Handler, req *http.Request, handle func(http.ResponseWriter, *http.Request)) (k1, sid string) {
	t.Helper()
	rr := httptest.NewRecorder()
	handle(rr, req)
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rr.Code, rr.Body.String())
	}
	return body["k1"], body["session_id"]
}

// On a SQLite install: link a wallet key from a signed-in session, then sign
// in with that wallet. Before SQLite could store Lightning keys, the link
// callback answered "failed to link key" and login was impossible.
func TestSQLiteLightning_LinkThenLogin(t *testing.T) {
	base, _ := testHandler(t)
	store, err := storage.NewSQLiteStorage(filepath.Join(t.TempDir(), "signer.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := NewHandler(base.config, signer.New(base.config, store, nil, nil, nil, nil, nil), store, nil, nil)
	ctx := context.Background()
	if err := store.CreateUser(ctx, &storage.User{ID: testUserID, Username: "sqlite-ln", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	linkReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/link/challenge", nil)
	addAuthHeader(t, h, linkReq)
	k1, _ := sqliteLNChallenge(t, h, linkReq, h.handleLightningLinkChallenge)
	if cb := sqliteLNCallback(t, h, priv, k1); cb["status"] != "OK" {
		t.Fatalf("link callback on SQLite: %v", cb)
	}
	if keys, err := store.ListLightningKeys(ctx, testUserID); err != nil || len(keys) != 1 {
		t.Fatalf("linked keys = %v, %v; want one", keys, err)
	}

	k1, sid := sqliteLNChallenge(t, h, httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/challenge", nil), h.handleLightningChallenge)
	if cb := sqliteLNCallback(t, h, priv, k1); cb["status"] != "OK" {
		t.Fatalf("login callback on SQLite: %v", cb)
	}
	rr := httptest.NewRecorder()
	h.handleLightningStatus(rr, httptest.NewRequest(http.MethodGet, "/api/v1/users/lightning/status?session_id="+sid, nil))
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusOK || body["success"] != true || len(rr.Result().Cookies()) == 0 {
		t.Fatalf("lightning login on SQLite: %d %v, want a sign-in", rr.Code, body)
	}
}

// With confirmation on, a SQLite install stops a key's first login at the
// account check, and "yes" completes it.
func TestSQLiteLightning_ConfirmFirstLogin(t *testing.T) {
	base, _ := testHandler(t)
	store, err := storage.NewSQLiteStorage(filepath.Join(t.TempDir(), "signer.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := NewHandler(base.config, signer.New(base.config, store, nil, nil, nil, nil, nil), store, nil, nil)
	h.config.Lightning.ConfirmFirstLogin = true
	ctx := context.Background()
	if err := store.CreateUser(ctx, &storage.User{ID: testUserID, Username: "sqlite-ln", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	priv, _ := secp256k1.GeneratePrivateKey()
	linkReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/link/challenge", nil)
	addAuthHeader(t, h, linkReq)
	k1, _ := sqliteLNChallenge(t, h, linkReq, h.handleLightningLinkChallenge)
	sqliteLNCallback(t, h, priv, k1)

	k1, sid := sqliteLNChallenge(t, h, httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/challenge", nil), h.handleLightningChallenge)
	sqliteLNCallback(t, h, priv, k1)
	rr := httptest.NewRecorder()
	h.handleLightningStatus(rr, httptest.NewRequest(http.MethodGet, "/api/v1/users/lightning/status?session_id="+sid, nil))
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["status"] != "confirm_account" || body["username"] != "sqlite-ln" || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("first login on SQLite: %d %v, want confirm_account for sqlite-ln and no cookie", rr.Code, body)
	}
	b, _ := json.Marshal(map[string]any{"session_id": sid, "confirm": true})
	rr = httptest.NewRecorder()
	h.handleLightningConfirm(rr, httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/confirm", bytes.NewReader(b)))
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusOK || body["success"] != true || len(rr.Result().Cookies()) == 0 {
		t.Fatalf("confirm on SQLite: %d %v, want a sign-in", rr.Code, body)
	}
}
