package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/seal"
)

func sessionState(t *testing.T, h *Handler, token string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/session", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.handleSessionState(rr, req)
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %q", rr.Body.String())
	}
	return rr.Code, body
}

func wantState(t *testing.T, code int, body map[string]any, state string) {
	t.Helper()
	if code != http.StatusOK || body["state"] != state {
		t.Fatalf("got %d %v, want 200 state=%s", code, body, state)
	}
}

func wantGone(t *testing.T, code int, body map[string]any, reason string) {
	t.Helper()
	if code != http.StatusUnauthorized || body["code"] != sessionGoneCode || body["reason"] != reason {
		t.Fatalf("got %d %v, want 401 session_gone reason=%s", code, body, reason)
	}
}

func TestSessionState_LiveAfterLogin(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "", false)
	code, body := sessionState(t, f.h, resp.Token)
	wantState(t, code, body, sessionStateLive)
	if body["signing_pubkey"] != f.key.Pubkey || body["expires_at"] == nil {
		t.Fatalf("body = %v, want the signing pubkey and an expiry", body)
	}
}

// A session-only sign-in on a replica that never unlocked the key: nothing can
// recover it, so the client is told key_locked rather than left waiting.
func TestSessionState_SessionOnlyOnFreshReplicaIsKeyLocked(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "", false)
	after := f.replica(t, f.keyfileSealer(t))
	code, body := sessionState(t, after, resp.Token)
	wantState(t, code, body, sessionStateKeyLocked)
	if body["signing_pubkey"] != f.key.Pubkey || body["needs_split_half"] != nil {
		t.Fatalf("body = %v, want the pubkey and no split-half hint", body)
	}
}

// A stay-signed-in session on a fresh replica: asking is enough to restore the
// key, so the answer is live, not key_locked.
func TestSessionState_RestoresFromSeal(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "30d", false)
	after := f.replica(t, f.keyfileSealer(t))
	code, body := sessionState(t, after, resp.Token)
	wantState(t, code, body, sessionStateLive)
	if !after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("live reported but the key is not loaded")
	}
}

// A seal this replica cannot open (another sealing key) is key_locked, never an error.
func TestSessionState_UnsealableIsKeyLocked(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "30d", false)
	other, err := seal.LoadKeyfile(filepath.Join(t.TempDir(), "other.key"), true)
	if err != nil {
		t.Fatal(err)
	}
	after := f.replica(t, other)
	code, body := sessionState(t, after, resp.Token)
	wantState(t, code, body, sessionStateKeyLocked)
	if after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("key loaded from a seal made under another key")
	}
}

// A split sign-in whose key is locked says the browser half can unlock it.
func TestSessionState_SplitSealHintsAtHalf(t *testing.T) {
	f := newStayFixture(t)
	f.h.SetSealer(seal.None{})
	resp, rr := f.browserLogin(t, "30d")
	if rr.Code != http.StatusOK || resp.StaySignedIn == nil || resp.StaySignedIn.Mode != seal.ModeSplit {
		t.Fatalf("login: %d %+v", rr.Code, resp.StaySignedIn)
	}
	after := f.replica(t, seal.None{})
	code, body := sessionState(t, after, resp.Token)
	wantState(t, code, body, sessionStateKeyLocked)
	if body["needs_split_half"] != true {
		t.Fatalf("body = %v, want needs_split_half", body)
	}
}

func TestSessionState_SignedOutIsGone(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "30d", false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/logout", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	rr := httptest.NewRecorder()
	f.h.handleUserLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout: %d", rr.Code)
	}
	code, body := sessionState(t, f.h, resp.Token)
	wantGone(t, code, body, "ended")
}

func TestSessionState_RevokedIsGone(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "30d", false)
	if err := f.store.DeleteUserSession(context.Background(), claimsOf(t, f.h, resp.Token).SessionID); err != nil {
		t.Fatal(err)
	}
	code, body := sessionState(t, f.h, resp.Token)
	wantGone(t, code, body, "ended")
}

func TestSessionState_ExpiredIsGone(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "30d", false)
	sid := claimsOf(t, f.h, resp.Token).SessionID
	stale, _, err := auth.GenerateJWTWithSessionUntil(f.h.authConfig, exportUserID, exportUsername, sid, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	code, body := sessionState(t, f.h, stale)
	wantGone(t, code, body, "expired")
}

func TestSessionState_MissingAndForgedAreGone(t *testing.T) {
	f := newStayFixture(t)
	code, body := sessionState(t, f.h, "")
	wantGone(t, code, body, "missing")
	code, body = sessionState(t, f.h, "not.a.jwt")
	wantGone(t, code, body, "invalid")
}

func TestSessionState_GetOnly(t *testing.T) {
	f := newStayFixture(t)
	rr := httptest.NewRecorder()
	f.h.handleSessionState(rr, httptest.NewRequest(http.MethodPost, "/api/v1/users/session", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d, want 405", rr.Code)
	}
}
