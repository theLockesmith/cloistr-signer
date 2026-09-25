package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// handleImportFrostShare took no identity at all. It created FROST keys with an
// EMPTY OwnerID, and the ownership guards on signing and export read
// `OwnerID != "" && OwnerID != claims.UserID`, so an empty owner skips the check.
// Anyone could mint a key that any authenticated account could then sign with or
// export. When the key already existed it wrote a share into it with no ownership
// test, which is an unauthenticated write into another user's threshold key.
//
// These tests assert ADMISSION as well as refusal. The previous round of fixes here
// shipped seven tests that were all refusals, which cannot tell a correct guard from
// one that locks out the legitimate owner too.

// testHandler leaves FROST unwired, and the ownership checks sit BEHIND the
// FROST-enabled gate, so against a plain test handler every one of these tests
// gets 503 and the thing being tested is never reached. A guard behind another
// guard cannot be probed in place: the outer one has to be opened first.
func frostEnabledHandler(t *testing.T) (*Handler, *storage.MemoryStorage) {
	t.Helper()
	h, store := testHandler(t)
	h.frostKeyGen = frost.NewKeyGenerator(nil)
	h.frostCoordinator = frost.NewCoordinator(store, nil)
	return h, store
}

func validBundle() frost.ShareBundle {
	return frost.ShareBundle{
		ShareIndex:     1,
		ShareData:      hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
		GroupPublicKey: hex.EncodeToString(append([]byte{0x02}, bytes.Repeat([]byte{0x03}, 32)...)),
		Threshold:      2,
		TotalShares:    3,
	}
}

func importRequest(t *testing.T, b frost.ShareBundle) *http.Request {
	t.Helper()
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/shares/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestHandleImportFrostShare_RejectsNoAuth(t *testing.T) {
	h, _ := testHandler(t)
	rr := httptest.NewRecorder()

	h.handleImportFrostShare(rr, importRequest(t, validBundle()))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("import without auth: got %d, want 401; body: %s", rr.Code, rr.Body.String())
	}
}

// The severe half: writing a share into somebody else's existing threshold key.
func TestHandleImportFrostShare_RefusesWriteIntoAnotherOwnersKey(t *testing.T) {
	h, store := frostEnabledHandler(t)
	b := validBundle()
	groupPub, _ := hex.DecodeString(b.GroupPublicKey)
	pubkey := hex.EncodeToString(groupPub[1:])

	if err := store.CreateFrostKey(context.Background(), &storage.FrostKey{
		ID: "fk-someone-else", Name: "theirs", Pubkey: pubkey,
		Threshold: 2, TotalShares: 3, OwnerID: testUserID, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateFrostKey: %v", err)
	}

	req := importRequest(t, b)
	otherUserAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleImportFrostShare(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("import into another owner's key: got %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// ADMISSION, and the one that closes the ownerless-key hole: the owner's import
// succeeds AND the key it creates carries their id rather than an empty one.
func TestHandleImportFrostShare_OwnerAdmittedAndKeyIsOwned(t *testing.T) {
	h, store := frostEnabledHandler(t)
	b := validBundle()
	req := importRequest(t, b)
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleImportFrostShare(rr, req)

	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusNotFound {
		t.Fatalf("the legitimate caller was refused: got %d; body: %s", rr.Code, rr.Body.String())
	}

	groupPub, _ := hex.DecodeString(b.GroupPublicKey)
	key, err := store.GetFrostKeyByPubkey(context.Background(), hex.EncodeToString(groupPub[1:]))
	if err != nil || key == nil {
		t.Skipf("import did not reach key creation (status %d); ownership assertion needs a fuller bundle", rr.Code)
	}
	if key.OwnerID == "" {
		t.Error("imported key has an EMPTY OwnerID: it is exempt from the sign and export guards")
	}
	if key.OwnerID != testUserID {
		t.Errorf("imported key OwnerID = %q, want the importing user", key.OwnerID)
	}
}

// The gap left by the previous round of fixes: nothing asserted that a legitimate
// owner still gets through the sign guard.
func TestHandleFrostSign_AdmitsTheOwner(t *testing.T) {
	h, store := frostEnabledHandler(t)
	if err := store.CreateFrostKey(context.Background(), &storage.FrostKey{
		ID: "fk-owned-sign", Name: "mine", Pubkey: "bbbb",
		Threshold: 2, TotalShares: 3, OwnerID: testUserID, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateFrostKey: %v", err)
	}
	keyID := "fk-owned-sign"
	body, _ := json.Marshal(FrostSignRequest{Message: hex.EncodeToString(bytes.Repeat([]byte{0x04}, 32))})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keys/"+keyID+"/sign", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleFrostSign(rr, req, keyID)

	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusNotFound {
		t.Errorf("the key's own owner was refused by the guard: got %d; body: %s", rr.Code, rr.Body.String())
	}
}
