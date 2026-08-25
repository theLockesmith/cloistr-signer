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
// unlockKey puts the key into the running signer's in-memory map, which is what
// a real user login does (Signer.RegisterKey, "runtime, not persisted").
//
// Every key in production is user-held, so a key that has NOT been unlocked on
// this process cannot be served — the session handler now refuses with 409
// key_locked rather than approving and going silent. The happy-path tests
// therefore have to say out loud that the user has logged in.
func unlockKey(h *Handler, key *storage.Key) {
	h.signer.RegisterKey(key.Pubkey, "0000000000000000000000000000000000000000000000000000000000000001")
}

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

// TestHandleNostrConnectSession_ConsentRequired verifies that when the key is
// configured with RequireApproval (opt-IN friction, unified-auth-design §9), a
// first-time connection without consent=true returns consent_required instead
// of auto-approving.
func TestHandleNostrConnectSession_ConsentRequired(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	// Opt into friction: this key requires explicit approval for new apps.
	key.RequireApproval = true
	if err := store.UpdateKey(context.Background(), key); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

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
		t.Error("consent_required = false, want true on a RequireApproval key without consent flag")
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

// TestHandleNostrConnectSession_OptOutAutoApprove verifies the opt-OUT default
// (unified-auth-design §9): with a normal key (RequireApproval=false), a
// first-time connection with no consent flag auto-approves silently — recording
// consent (so it's revocable in Connected Apps) and setting the permission.
func TestHandleNostrConnectSession_OptOutAutoApprove(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store) // RequireApproval defaults to false
	unlockKey(h, key)               // the user has logged in; their key is unlocked

	body, _ := json.Marshal(map[string]interface{}{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": "key-sso-001",
		// consent omitted / false — the opt-out default should still approve
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
		t.Error("success = false, want true on opt-out auto-approve")
	}
	if resp.ConsentRequired {
		t.Error("consent_required = true, want false on opt-out default")
	}

	// Consent recorded (so the app is listed + revocable) and permission set.
	hasConsent, _ := store.HasAppConsent(context.Background(), testUserIDSess, testClientPubkey)
	if !hasConsent {
		t.Error("consent not recorded on opt-out auto-approve")
	}
	if perm, err := store.GetPermission(context.Background(), key.Pubkey, testClientPubkey); err != nil || perm == nil {
		t.Errorf("permission not set on opt-out auto-approve (err=%v)", err)
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

// A locked key must be REFUSED, not approved-then-silently-unanswered.
//
// This is the regression that cost the most: the handler approved the session,
// returned 200, and SendNostrConnectResponse then found no key and returned
// without publishing. The browser waited 30 seconds for an ack that was never
// coming and blamed the network — for a signer that was healthy throughout.
//
// Every key in production is user-held, so "not unlocked on this replica" is
// the normal state after a pod restart or a request that landed on the wrong
// replica. It has to be a fast, honest answer.
func TestHandleNostrConnectSession_RefusesLockedKey(t *testing.T) {
	h, store := testHandler(t)
	seedUserAndKey(t, store)
	// Deliberately NOT unlocked: no unlockKey() call here.

	body, _ := json.Marshal(map[string]interface{}{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": "key-sso-001",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect/session", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleNostrConnectSession(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for a locked key\nbody: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The CODE is the point: a client cannot tell a locked key from an
	// unreachable relay by prose, and guessing wrong is what pushed the user
	// toward an extension login they did not need.
	if resp["code"] != "key_locked" {
		t.Errorf("code = %q, want %q", resp["code"], "key_locked")
	}
	if resp["error"] == "" {
		t.Error("error message empty; the user must be told what to do")
	}
}
