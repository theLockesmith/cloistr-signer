package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The signer's own "Connect an App" form posts to /api/v1/nostrconnect. If
// the key is not unlocked on this replica (passphrase-wrapped, user signed in
// on another pod, or a deploy re-locked it), approving would store a grant and
// answer success while the app waits forever for an ack nobody can sign. It
// must answer 409 key_locked and store nothing.
func TestHandleNostrConnect_LockedKeyRefused(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store) // deliberately NOT unlocked

	body, _ := json.Marshal(map[string]any{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": key.ID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	rr := httptest.NewRecorder()
	h.handleNostrConnect(rr, req)

	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"key_locked"`) {
		t.Fatalf("status = %d body = %s, want 409 with code key_locked", rr.Code, rr.Body.String())
	}
	if perm, _ := store.GetPermission(context.Background(), key.Pubkey, testClientPubkey); perm != nil {
		t.Fatal("a grant was stored for a session this replica cannot serve")
	}
}

func TestHandleNostrConnect_UnlockedKeyStillApproved(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	unlockKey(h, key)

	body, _ := json.Marshal(map[string]any{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": key.ID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	rr := httptest.NewRecorder()
	h.handleNostrConnect(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// The connect form on replica B reaches the replica holding the key (A), which
// approves with the user's explicit consent.
func TestHandleNostrConnect_ForwardsToHolder(t *testing.T) {
	_, b, key, _, _ := twoReplicas(t)
	body, _ := json.Marshal(map[string]any{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": key.ID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, b, testUserIDSess))
	rr := httptest.NewRecorder()
	b.handleNostrConnect(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Fatalf("status = %d body = %s, want 200 success via the holder", rr.Code, rr.Body.String())
	}
	if perm, _ := b.storage.GetPermission(context.Background(), key.Pubkey, testClientPubkey); perm == nil {
		t.Fatal("holder did not store the grant")
	}
}

// The form's ownership check is the only thing stopping a user from granting
// an app signing rights over someone else's key. Another user's key_id gets
// 403: nothing is stored on a replica that holds the key, and nothing is
// forwarded from one that doesn't.
func TestHandleNostrConnect_OtherUsersKeyRefused(t *testing.T) {
	post := func(h *Handler, keyID string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{
			"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
			"key_id": keyID,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, "intruder-user"))
		rr := httptest.NewRecorder()
		h.handleNostrConnect(rr, req)
		return rr
	}

	t.Run("replica holding the key", func(t *testing.T) {
		a, _, key, _, _ := twoReplicas(t)
		if rr := post(a, key.ID); rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body.String())
		}
		if perm, _ := a.storage.GetPermission(context.Background(), key.Pubkey, testClientPubkey); perm != nil {
			t.Fatal("a grant over another user's key was stored")
		}
	})

	t.Run("replica without the key", func(t *testing.T) {
		_, b, key, _, loc := twoReplicas(t)
		var hits int
		spy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
		defer spy.Close()
		loc.mu.Lock()
		loc.addr = strings.TrimPrefix(spy.URL, "http://")
		loc.mu.Unlock()
		if rr := post(b, key.ID); rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body.String())
		}
		if hits != 0 {
			t.Fatalf("request for another user's key was forwarded (%d hits)", hits)
		}
		if perm, _ := b.storage.GetPermission(context.Background(), key.Pubkey, testClientPubkey); perm != nil {
			t.Fatal("a grant over another user's key was stored")
		}
	})
}

// Consent is recorded the same way whichever replica takes the form, so later
// silent re-approval doesn't depend on routing.
func TestHandleNostrConnect_LocalApprovalRecordsConsent(t *testing.T) {
	h, store := testHandler(t)
	key := seedUserAndKey(t, store)
	unlockKey(h, key)
	body, _ := json.Marshal(map[string]any{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": key.ID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	rr := httptest.NewRecorder()
	h.handleNostrConnect(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if ok, _ := store.HasAppConsent(context.Background(), testUserIDSess, testClientPubkey); !ok {
		t.Fatal("local approval did not record app consent")
	}
}
