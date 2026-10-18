package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// lnWallet signs LNURL-auth challenges the way a wallet does (DER, LUD-04).
type lnWallet struct{ priv *secp256k1.PrivateKey }

func newLNWallet(t *testing.T) lnWallet {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return lnWallet{priv}
}

func (w lnWallet) key() string { return hex.EncodeToString(w.priv.PubKey().SerializeCompressed()) }

func (w lnWallet) callbackQuery(t *testing.T, k1 string) string {
	t.Helper()
	b, err := hex.DecodeString(k1)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return url.Values{"tag": {"login"}, "k1": {k1}, "key": {w.key()},
		"sig": {hex.EncodeToString(ecdsa.Sign(w.priv, h[:]).Serialize())}}.Encode()
}

// Two replicas: separate handlers and signers sharing only the storage, as in
// production. Neither holds anything the other can see except the database.
func lightningReplicas(t *testing.T) (a, b *Handler, store *storage.MemoryStorage, wallet lnWallet) {
	t.Helper()
	a, store = testHandler(t)
	b = NewHandler(a.config, signer.New(a.config, store, nil, nil, nil, nil, nil), store, nil, nil)
	ctx := context.Background()
	if err := store.CreateUser(ctx, &storage.User{ID: "ln-user", Username: "ln-user", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	wallet = newLNWallet(t)
	if err := store.CreateLightningKey(ctx, &storage.LightningKey{ID: "lk1", UserID: "ln-user", LinkingKey: wallet.key(), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return a, b, store, wallet
}

func lnChallenge(t *testing.T, h *Handler) (k1, sessionID string) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.handleLightningChallenge(rr, httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/challenge", nil))
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rr.Code, rr.Body.String())
	}
	return body["k1"], body["session_id"]
}

func lnCallback(t *testing.T, h *Handler, query string) map[string]string {
	t.Helper()
	rr := httptest.NewRecorder()
	h.handleLNURLAuthCallback(rr, httptest.NewRequest(http.MethodGet, "/api/v1/lnurl-auth/callback?"+query, nil))
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return body
}

func lnStatus(t *testing.T, h *Handler, sessionID string) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.handleLightningStatus(rr, httptest.NewRequest(http.MethodGet, "/api/v1/users/lightning/status?session_id="+sessionID, nil))
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body, rr.Result().Cookies()
}

// The production failure: challenge on replica A, wallet callback on replica
// B, status poll back on A. With challenges in each pod's memory B answered
// "unknown or expired k1 challenge" and A never saw the callback. Every
// routing of the three steps now signs in.
func TestLightningLogin_StepsOnDifferentReplicas(t *testing.T) {
	a, b, _, wallet := lightningReplicas(t)
	for _, route := range []struct {
		name                  string
		issue, callback, poll *Handler
	}{
		{"A,A,A", a, a, a}, {"A,B,A", a, b, a}, {"A,A,B", a, a, b}, {"A,B,B", a, b, b}, {"B,A,B", b, a, b},
	} {
		t.Run(route.name, func(t *testing.T) {
			k1, sid := lnChallenge(t, route.issue)
			if code, body, _ := lnStatus(t, route.poll, sid); code != http.StatusOK || body["status"] != "pending" {
				t.Fatalf("poll before the wallet answers: %d %v, want 200 pending", code, body)
			}
			if cb := lnCallback(t, route.callback, wallet.callbackQuery(t, k1)); cb["status"] != "OK" {
				t.Fatalf("wallet callback: %v", cb)
			}
			code, body, cookies := lnStatus(t, route.poll, sid)
			if code != http.StatusOK || body["success"] != true || len(cookies) == 0 || cookies[0].Value == "" {
				t.Fatalf("status after callback: %d %v cookies=%d, want a sign-in", code, body, len(cookies))
			}
		})
	}
}

// Each step is single-use across replicas: a replayed callback is refused, and
// a second poll of a completed login does not sign in again.
func TestLightningLogin_SingleUseAcrossReplicas(t *testing.T) {
	a, b, _, wallet := lightningReplicas(t)
	k1, sid := lnChallenge(t, a)
	q := wallet.callbackQuery(t, k1)
	if cb := lnCallback(t, b, q); cb["status"] != "OK" {
		t.Fatalf("first callback: %v", cb)
	}
	if cb := lnCallback(t, a, q); cb["status"] != "ERROR" {
		t.Fatalf("replayed callback on the other replica: %v, want ERROR", cb)
	}
	if code, body, _ := lnStatus(t, b, sid); code != http.StatusOK || body["success"] != true {
		t.Fatalf("first poll: %d %v", code, body)
	}
	if code, body, cookies := lnStatus(t, a, sid); code != http.StatusBadRequest || body["status"] != "expired" || len(cookies) != 0 {
		t.Fatalf("second poll on the other replica: %d %v cookies=%d, want 400 expired and no sign-in", code, body, len(cookies))
	}
}

// An expired challenge is refused on every replica.
func TestLightningLogin_ExpiredChallenge(t *testing.T) {
	a, b, store, wallet := lightningReplicas(t)
	ctx := context.Background()
	if err := store.CreateLightningChallenge(ctx, &storage.LightningChallenge{
		K1: "0101010101010101010101010101010101010101010101010101010101010101", SessionID: "old-session",
		ExpiresAt: time.Now().Add(-time.Second), CreatedAt: time.Now().Add(-11 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if cb := lnCallback(t, b, wallet.callbackQuery(t, "0101010101010101010101010101010101010101010101010101010101010101")); cb["status"] != "ERROR" {
		t.Fatalf("callback on an expired challenge: %v, want ERROR", cb)
	}
	if code, body, _ := lnStatus(t, a, "old-session"); code != http.StatusBadRequest || body["status"] != "expired" {
		t.Fatalf("poll of an expired challenge: %d %v", code, body)
	}
}
