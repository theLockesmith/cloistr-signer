package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// handleFrostSign and handleExportFrostShare are dispatched through the FROST
// key sub-resource router at /api/v1/frost/keys/{id}/{action}. They must
// require a valid JWT and verify the caller owns the FROST key, matching
// handleFrostSignRound1 which already does both.

func frostKeyFixture(t *testing.T) (*Handler, *storage.MemoryStorage, string) {
	t.Helper()
	h, store := testHandler(t)
	ctx := context.Background()

	if err := store.CreateFrostKey(ctx, &storage.FrostKey{
		ID:          "fk-owned",
		Name:        "test frost key",
		Pubkey:      "aaaa",
		Threshold:   2,
		TotalShares: 3,
		OwnerID:     testUserID,
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("CreateFrostKey: %v", err)
	}
	return h, store, "fk-owned"
}

func TestHandleFrostSign_RejectsNoAuth(t *testing.T) {
	h, _, keyID := frostKeyFixture(t)
	body, _ := json.Marshal(FrostSignRequest{Message: "aa"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keys/"+keyID+"/sign", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleFrostSign(rr, req, keyID)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("handleFrostSign without auth: got %d, want 401; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleFrostSign_RejectsWrongOwner(t *testing.T) {
	h, _, keyID := frostKeyFixture(t)
	body, _ := json.Marshal(FrostSignRequest{Message: "aa"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keys/"+keyID+"/sign", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	otherUserAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleFrostSign(rr, req, keyID)

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleFrostSign wrong owner: got %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleExportFrostShare_RejectsNoAuth(t *testing.T) {
	h, _, keyID := frostKeyFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/frost/keys/"+keyID+"/export/0", nil)
	rr := httptest.NewRecorder()

	h.handleExportFrostShare(rr, req, keyID, "0")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("handleExportFrostShare without auth: got %d, want 401; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleExportFrostShare_RejectsWrongOwner(t *testing.T) {
	h, _, keyID := frostKeyFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/frost/keys/"+keyID+"/export/0", nil)
	otherUserAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleExportFrostShare(rr, req, keyID, "0")

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleExportFrostShare wrong owner: got %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}
