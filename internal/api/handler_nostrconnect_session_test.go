package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// makeSessionToken returns a Bearer token for the given userID using the
// test handler's auth config.
func makeSessionToken(t *testing.T, h *Handler, userID string) string {
	t.Helper()
	token, _, err := auth.GenerateJWT(h.authConfig, userID, "testuser")
	if err != nil {
		t.Fatalf("makeSessionToken: %v", err)
	}
	return token
}

// validNostrConnectURI returns a minimal nostrconnect:// URI with a 64-char
// client pubkey, a relay, a secret, and optional app name.
func validNostrConnectURI(clientPubkey, relay, appName string) string {
	uri := "nostrconnect://" + clientPubkey + "?relay=" + relay + "&secret=testsecret"
	if appName != "" {
		uri += "&name=" + appName
	}
	return uri
}

const (
	testClientPubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testUserIDSess   = "user-sso-001"
)

// seedUser creates a user and a key owned by that user in the in-memory store.
func seedUserAndKey(t *testing.T, store *storage.MemoryStorage) *storage.Key {
	t.Helper()
	user := &storage.User{
		ID:           testUserIDSess,
		Username:     "ssotest",
		PasswordHash: "x",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("seedUserAndKey: CreateUser: %v", err)
	}
	key := &storage.Key{
		ID:        "key-sso-001",
		Pubkey:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		OwnerID:   testUserIDSess,
		CreatedAt: time.Now(),
	}
	if err := store.CreateKey(context.Background(), key); err != nil {
		t.Fatalf("seedUserAndKey: CreateKey: %v", err)
	}
	return key
}

func TestHandleNostrConnectSession_RequiresAuth(t *testing.T) {
	h, _ := testHandler(t)

	body, _ := json.Marshal(map[string]interface{}{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": "key-sso-001",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect/session", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleNostrConnectSession(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no-auth request status = %d, want 401", rr.Code)
	}
}

func TestHandleNostrConnectSession_MethodNotAllowed(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nostrconnect/session", nil)
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	rr := httptest.NewRecorder()
	h.handleNostrConnectSession(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rr.Code)
	}
}

// TestHandleNostrConnectSession_ConsentRequired verifies that a first-time
// connection without consent=true returns consent_required instead of approving.
func TestHandleNostrConnectSession_ConsentRequired(t *testing.T) {
	h, store := testHandler(t)
	seedUserAndKey(t, store)

	body, _ := json.Marshal(map[string]interface{}{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": "key-sso-001",
		// consent omitted / false
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect/session", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleNostrConnectSession(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var resp NostrConnectSessionResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.ConsentRequired {
		t.Error("consent_required = false, want true on first-time without consent flag")
	}
	if resp.Success {
		t.Error("success = true, should not be approved without consent")
	}
	if resp.AppID != testClientPubkey {
		t.Errorf("app_id = %q, want %q", resp.AppID, testClientPubkey)
	}

	// Verify no consent was stored and no permission was set.
	hasConsent, _ := store.HasAppConsent(context.Background(), testUserIDSess, testClientPubkey)
	if hasConsent {
		t.Error("consent was stored without explicit consent=true")
	}
}

// TestHandleNostrConnectSession_FirstTimeApproval verifies that consent=true
// on the first connection records the consent and sets the permission.
func TestHandleNostrConnectSession_FirstTimeApproval(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)

	body, _ := json.Marshal(map[string]interface{}{
		"uri":     validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id":  "key-sso-001",
		"consent": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect/session", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleNostrConnectSession(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", rr.Code, rr.Body.String())
	}

	var resp NostrConnectSessionResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if !resp.Success {
		t.Errorf("success = false, want true after first-time approval")
	}
	if resp.ConsentRequired {
		t.Error("consent_required = true, want false after consent=true")
	}

	// Consent must now be stored.
	hasConsent, err := store.HasAppConsent(context.Background(), testUserIDSess, testClientPubkey)
	if err != nil {
		t.Fatalf("HasAppConsent: %v", err)
	}
	if !hasConsent {
		t.Error("consent not stored after first-time approval")
	}

	// Permission must be set.
	perm, err := store.GetPermission(context.Background(), key.Pubkey, testClientPubkey)
	if err != nil {
		t.Fatalf("GetPermission: %v", err)
	}
	if perm == nil {
		t.Fatal("permission not set after approval")
	}
}

// TestHandleNostrConnectSession_SilentReauth verifies that a subsequent
// connection from the same app auto-approves without requiring consent=true.
func TestHandleNostrConnectSession_SilentReauth(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)

	// Pre-record consent (simulates a prior first-time approval).
	store.RecordAppConsent(context.Background(), testUserIDSess, testClientPubkey, "TestApp")

	body, _ := json.Marshal(map[string]interface{}{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": "key-sso-001",
		// consent NOT sent — should still auto-approve
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect/session", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleNostrConnectSession(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", rr.Code, rr.Body.String())
	}
	var resp NostrConnectSessionResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if !resp.Success {
		t.Error("success = false on silent re-auth, want true")
	}
	if resp.ConsentRequired {
		t.Error("consent_required = true on re-auth with stored consent, want false")
	}

	// Permission is set.
	perm, _ := store.GetPermission(context.Background(), key.Pubkey, testClientPubkey)
	if perm == nil {
		t.Error("permission not set on silent re-auth")
	}
}

// TestHandleNostrConnectSession_WrongOwner verifies that a key not owned by
// the authenticated user is rejected with 403.
func TestHandleNostrConnectSession_WrongOwner(t *testing.T) {
	h, store := testHandler(t)
	seedUserAndKey(t, store) // creates key owned by testUserIDSess

	// Authenticate as a different user.
	body, _ := json.Marshal(map[string]interface{}{
		"uri":     validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id":  "key-sso-001",
		"consent": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect/session", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, "attacker-user"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleNostrConnectSession(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("wrong-owner status = %d, want 403", rr.Code)
	}
}

// TestHandleNostrConnectRevoke_All verifies that revoke without app_id clears
// all consents and all permissions for the user's keys.
func TestHandleNostrConnectRevoke_All(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)

	// Seed consent and permission.
	store.RecordAppConsent(context.Background(), testUserIDSess, testClientPubkey, "TestApp")
	store.SetPermission(context.Background(), &storage.Permission{
		KeyID:      key.Pubkey,
		UserPubkey: testClientPubkey,
		Methods:    []string{"sign_event"},
	})

	body, _ := json.Marshal(map[string]interface{}{}) // no app_id = revoke all
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleNostrConnectRevoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200\nbody: %s", rr.Code, rr.Body.String())
	}

	// Consent is gone.
	hasConsent, _ := store.HasAppConsent(context.Background(), testUserIDSess, testClientPubkey)
	if hasConsent {
		t.Error("consent still present after revoke-all")
	}
	// Permission is gone.
	perm, err := store.GetPermission(context.Background(), key.Pubkey, testClientPubkey)
	if err == nil && perm != nil {
		t.Error("permission still present after revoke-all")
	}
}
