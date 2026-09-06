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

// The pending-request endpoints used to take no identity at all: the request
// id was the entire credential, so anyone who could reach the signer could
// list, read, approve or deny requests against any key. Approving is the one
// path that mints a persistent NIP-46 permission, which made it the sharpest
// edge of the four. These tests hold that door shut.

const (
	ownerKeyPubkey    = "1111111111111111111111111111111111111111111111111111111111111111"
	strangerKeyPubkey = "2222222222222222222222222222222222222222222222222222222222222222"
	clientPubkey      = "3333333333333333333333333333333333333333333333333333333333333333"
)

// pendingRequestFixture builds a handler holding two keys — one owned by the
// test user, one owned by somebody else — each with a pending request against
// it. Returns the request id owned by the test user and the one that is not.
func pendingRequestFixture(t *testing.T) (h *Handler, ownedReqID, strangerReqID string) {
	t.Helper()
	h, store := testHandler(t)
	ctx := context.Background()

	for _, k := range []struct{ id, pubkey, owner string }{
		{"ownedkey", ownerKeyPubkey, testUserID},
		{"strangerkey", strangerKeyPubkey, "some-other-user-456"},
	} {
		if err := store.CreateKey(ctx, &storage.Key{
			ID:        k.id,
			Name:      k.id,
			Pubkey:    k.pubkey,
			OwnerID:   k.owner,
			CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateKey(%s): %v", k.id, err)
		}
	}

	for _, r := range []struct{ id, keyPubkey string }{
		{"req-owned", ownerKeyPubkey},
		{"req-stranger", strangerKeyPubkey},
	} {
		if err := store.CreatePendingRequest(ctx, &storage.PendingRequest{
			ID:           r.id,
			KeyPubkey:    r.keyPubkey,
			ClientPubkey: clientPubkey,
			Method:       "nip44_decrypt",
			ExpiresAt:    time.Now().Add(time.Hour),
			CreatedAt:    time.Now(),
		}); err != nil {
			t.Fatalf("CreatePendingRequest(%s): %v", r.id, err)
		}
	}

	return h, "req-owned", "req-stranger"
}

// otherUserAuthHeader signs a token for a real, different user, so a rejection
// proves the ownership check bit rather than the token merely being invalid.
func otherUserAuthHeader(t *testing.T, h *Handler, req *http.Request) {
	t.Helper()
	token, _, err := auth.GenerateJWT(h.authConfig, "some-other-user-456", "otheruser")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
}

func approveBody(t *testing.T) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(ApproveRequestInput{
		Methods:  []string{"nip44_decrypt"},
		Remember: true,
	})
	if err != nil {
		t.Fatalf("marshal approve input: %v", err)
	}
	return bytes.NewReader(b)
}

func TestPendingRequestEndpoints_RejectAnonymous(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		call   func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request)
	}{
		{
			"list by key_pubkey", http.MethodGet,
			"/api/v1/requests?key_pubkey=" + ownerKeyPubkey,
			func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request) { h.handleRequests(rr, req) },
		},
		{
			"get", http.MethodGet, "/api/v1/requests/req-owned",
			func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request) {
				h.handleGetRequest(rr, req, "req-owned")
			},
		},
		{
			"approve", http.MethodPost, "/api/v1/requests/req-owned/approve",
			func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request) {
				h.handleApproveRequest(rr, req, "req-owned")
			},
		},
		{
			"deny", http.MethodPost, "/api/v1/requests/req-owned/deny",
			func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request) {
				h.handleDenyRequest(rr, req, "req-owned")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := pendingRequestFixture(t)

			var body *bytes.Reader = bytes.NewReader(nil)
			if tc.name == "approve" {
				body = approveBody(t)
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			rr := httptest.NewRecorder()

			tc.call(h, rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("anonymous %s: status = %d, want %d (body %q)",
					tc.name, rr.Code, http.StatusUnauthorized, rr.Body.String())
			}
		})
	}
}

func TestPendingRequestEndpoints_RejectNonOwner(t *testing.T) {
	// Authenticated as a real user who does not own ownerKeyPubkey. A 404
	// rather than a 403 is deliberate: an id owned by somebody else must be
	// indistinguishable from one that does not exist.
	cases := []struct {
		name   string
		method string
		path   string
		call   func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request)
	}{
		{
			"list by key_pubkey", http.MethodGet,
			"/api/v1/requests?key_pubkey=" + ownerKeyPubkey,
			func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request) { h.handleRequests(rr, req) },
		},
		{
			"get", http.MethodGet, "/api/v1/requests/req-owned",
			func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request) {
				h.handleGetRequest(rr, req, "req-owned")
			},
		},
		{
			"approve", http.MethodPost, "/api/v1/requests/req-owned/approve",
			func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request) {
				h.handleApproveRequest(rr, req, "req-owned")
			},
		},
		{
			"deny", http.MethodPost, "/api/v1/requests/req-owned/deny",
			func(h *Handler, rr *httptest.ResponseRecorder, req *http.Request) {
				h.handleDenyRequest(rr, req, "req-owned")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := pendingRequestFixture(t)

			var body *bytes.Reader = bytes.NewReader(nil)
			if tc.name == "approve" {
				body = approveBody(t)
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			otherUserAuthHeader(t, h, req)
			rr := httptest.NewRecorder()

			tc.call(h, rr, req)

			if rr.Code != http.StatusNotFound {
				t.Errorf("non-owner %s: status = %d, want %d (body %q)",
					tc.name, rr.Code, http.StatusNotFound, rr.Body.String())
			}
		})
	}
}

// TestApproveRequest_NonOwnerMintsNoPermission is the finding stated as a test:
// the reason approve is the sharpest of the four is that it writes a persistent
// permission. A refused approve must leave no permission behind and must not
// consume the pending request.
func TestApproveRequest_NonOwnerMintsNoPermission(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	if err := store.CreateKey(ctx, &storage.Key{
		ID: "victimkey", Name: "victim", Pubkey: ownerKeyPubkey,
		OwnerID: "victim-user", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if err := store.CreatePendingRequest(ctx, &storage.PendingRequest{
		ID: "req-victim", KeyPubkey: ownerKeyPubkey, ClientPubkey: clientPubkey,
		Method: "nip44_decrypt", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreatePendingRequest: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/requests/req-victim/approve", approveBody(t))
	addAuthHeader(t, h, req) // testUserID, who owns nothing here
	rr := httptest.NewRecorder()

	h.handleApproveRequest(rr, req, "req-victim")

	if rr.Code != http.StatusNotFound {
		t.Fatalf("approve by non-owner: status = %d, want %d", rr.Code, http.StatusNotFound)
	}

	if perm, err := store.GetPermission(ctx, ownerKeyPubkey, clientPubkey); err == nil && perm != nil {
		t.Errorf("refused approve still minted a permission: %+v", perm)
	}

	if _, err := store.GetPendingRequest(ctx, "req-victim"); err != nil {
		t.Errorf("refused approve consumed the pending request: %v", err)
	}
}

// Positive control. Without this, every assertion above is satisfied by a
// handler that refuses everybody, which would be a broken signer rather than a
// fixed one.
func TestPendingRequestEndpoints_OwnerStillWorks(t *testing.T) {
	h, ownedReqID, _ := pendingRequestFixture(t)

	t.Run("list by key_pubkey", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/requests?key_pubkey="+ownerKeyPubkey, nil)
		addAuthHeader(t, h, req)
		rr := httptest.NewRecorder()

		h.handleRequests(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("owner list: status = %d, want %d (body %q)", rr.Code, http.StatusOK, rr.Body.String())
		}
		var got []PendingRequestResponse
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 1 || got[0].ID != ownedReqID {
			t.Errorf("owner list = %+v, want exactly the one request they own", got)
		}
	})

	t.Run("get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/requests/"+ownedReqID, nil)
		addAuthHeader(t, h, req)
		rr := httptest.NewRecorder()

		h.handleGetRequest(rr, req, ownedReqID)

		if rr.Code != http.StatusOK {
			t.Fatalf("owner get: status = %d, want %d (body %q)", rr.Code, http.StatusOK, rr.Body.String())
		}
	})

	t.Run("approve mints the scoped permission", func(t *testing.T) {
		h, ownedReqID, _ := pendingRequestFixture(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/requests/"+ownedReqID+"/approve", approveBody(t))
		addAuthHeader(t, h, req)
		rr := httptest.NewRecorder()

		h.handleApproveRequest(rr, req, ownedReqID)

		if rr.Code != http.StatusOK {
			t.Fatalf("owner approve: status = %d, want %d (body %q)", rr.Code, http.StatusOK, rr.Body.String())
		}

		perm, err := h.storage.GetPermission(context.Background(), ownerKeyPubkey, clientPubkey)
		if err != nil {
			t.Fatalf("owner approve minted no permission: %v", err)
		}
		var hasDecrypt bool
		for _, m := range perm.Methods {
			if m == "nip44_decrypt" {
				hasDecrypt = true
			}
			if m == "*" || m == "all" {
				t.Errorf("scoped approve produced a wildcard method %q", m)
			}
		}
		if !hasDecrypt {
			t.Errorf("permission methods = %v, want nip44_decrypt", perm.Methods)
		}
	})
}
