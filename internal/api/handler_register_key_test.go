package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// TestHandleUserRegister_CreatesSigningKey verifies a new account is provisioned
// with a signing key so it is not left unable to sign anything.
func TestHandleUserRegister_CreatesSigningKey(t *testing.T) {
	h, store := testHandler(t)
	body := `{"username":"newuser","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserRegister(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	var resp UserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	keys, err := store.ListKeys(context.Background(), resp.ID)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("new account has %d signing keys, want 1", len(keys))
	}
}

// TestHandleUserRegister_ImportsProvidedKey verifies an imported nsec/hex key
// becomes the account's initial signing key (pubkey matches).
func TestHandleUserRegister_ImportsProvidedKey(t *testing.T) {
	h, store := testHandler(t)
	priv := nostr.GeneratePrivateKey()
	wantPub, err := nostr.GetPublicKey(priv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	body := `{"username":"importer","password":"password123","import_nsec":"` + priv + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserRegister(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d; body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}
	var resp UserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	keys, err := store.ListKeys(context.Background(), resp.ID)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	if keys[0].Pubkey != wantPub {
		t.Errorf("imported key pubkey = %s, want %s", keys[0].Pubkey, wantPub)
	}
}
