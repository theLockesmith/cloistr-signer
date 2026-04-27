package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// testHandler creates a handler with in-memory storage for testing
func testHandler(t *testing.T) (*Handler, *storage.MemoryStorage) {
	cfg := &config.Config{
		Relays: []string{"wss://relay.example.com"},
		Auth: config.AuthConfig{
			JWTSecret:       "test-secret-key-for-testing-only",
			JWTExpiry:       24,
			MFAIssuer:       "TestIssuer",
			MaxFailedLogins: 5,
			LockoutMinutes:  15,
		},
	}

	store := storage.NewMemoryStorage()

	// Create signer with nil relay client and nil encryptor - tests that need
	// signer methods should handle nil checks appropriately
	s := signer.New(cfg, store, nil, nil, nil, nil, nil)

	h := NewHandler(cfg, s, store, nil)
	return h, store
}

// testUserID is the user ID used in test auth tokens
const testUserID = "test-user-123"

// testAuthToken generates a valid auth token for testing
func testAuthToken(t *testing.T, h *Handler) string {
	token, _, err := auth.GenerateJWT(h.authConfig, testUserID, "testuser")
	if err != nil {
		t.Fatalf("failed to generate test auth token: %v", err)
	}
	return token
}

// addAuthHeader adds the Authorization header with a test token
func addAuthHeader(t *testing.T, h *Handler, req *http.Request) {
	token := testAuthToken(t, h)
	req.Header.Set("Authorization", "Bearer "+token)
}

// TestNewHandler verifies handler creation
func TestNewHandler(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:       "test-secret",
			JWTExpiry:       24,
			MFAIssuer:       "TestIssuer",
			MaxFailedLogins: 5,
			LockoutMinutes:  15,
		},
	}
	store := storage.NewMemoryStorage()
	s := signer.New(cfg, store, nil, nil, nil, nil, nil)

	h := NewHandler(cfg, s, store, nil)

	if h == nil {
		t.Fatal("NewHandler() returned nil")
	}
	if h.config != cfg {
		t.Error("handler config not set correctly")
	}
	if h.storage != store {
		t.Error("handler storage not set correctly")
	}
}

// TestRegisterRoutes verifies all routes are registered
func TestRegisterRoutes(t *testing.T) {
	h, _ := testHandler(t)
	mux := http.NewServeMux()

	h.RegisterRoutes(mux)

	// Test that routes are registered by making requests
	// Note: Some routes (health/ready, status) require a relay client so we skip them
	routes := []string{
		"/health",
		"/health/live",
		// "/health/ready", // requires relay client
		"/api/v1/keys",
		"/api/v1/policies",
		"/api/v1/tokens",
		"/api/v1/requests",
		"/api/v1/users/register",
		"/api/v1/users/login",
		// "/api/v1/status", // requires relay client
		"/.well-known/nostr.json",
		"/api/v1/audit",
	}

	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		// 404 means route not registered, anything else means it was found
		if rr.Code == http.StatusNotFound && !strings.Contains(rr.Body.String(), "not found") {
			t.Errorf("route %s not registered", route)
		}
	}
}

// Health endpoint tests

func TestHandleHealth(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleHealth() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("status = %q, want %q", resp.Status, "ok")
	}
	if resp.Timestamp == "" {
		t.Error("timestamp should not be empty")
	}
}

func TestHandleHealth_MethodNotAllowed(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rr := httptest.NewRecorder()

	h.handleHealth(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleHealth() status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleLive(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	rr := httptest.NewRecorder()

	h.handleLive(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleLive() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// Key management tests

func TestHandleListKeys_Empty(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleKeys(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleListKeys() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var keys []KeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&keys); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("expected empty list, got %d keys", len(keys))
	}
}

func TestHandleCreateKey(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"name": "test-key"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleKeys(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("handleCreateKey() status = %d, want %d; body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var key KeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&key); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if key.Name != "test-key" {
		t.Errorf("key.Name = %q, want %q", key.Name, "test-key")
	}
	if key.Pubkey == "" {
		t.Error("key.Pubkey should not be empty")
	}
	if len(key.Pubkey) != 64 {
		t.Errorf("key.Pubkey length = %d, want 64", len(key.Pubkey))
	}
	if key.ID == "" {
		t.Error("key.ID should not be empty")
	}
}

func TestHandleCreateKey_WithNsec(t *testing.T) {
	h, _ := testHandler(t)

	// Valid nsec for testing
	body := `{"name": "imported-key", "private_key": "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleKeys(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("handleCreateKey() status = %d, want %d; body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var key KeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&key); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// The pubkey should be derived from the provided nsec
	if key.Pubkey == "" {
		t.Error("key.Pubkey should not be empty")
	}
}

func TestHandleCreateKey_InvalidBody(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleKeys(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleCreateKey() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleGetKey(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create a key first with test user as owner
	key := &storage.Key{
		ID:        "testkey123456789",
		Name:      "test-key",
		Pubkey:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		OwnerID:   testUserID,
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/testkey123456789", nil)
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleGetKey(rr, req, "testkey123456789")

	if rr.Code != http.StatusOK {
		t.Errorf("handleGetKey() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp KeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Name != "test-key" {
		t.Errorf("key.Name = %q, want %q", resp.Name, "test-key")
	}
}

func TestHandleGetKey_NotFound(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/nonexistent", nil)
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleGetKey(rr, req, "nonexistent")

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleGetKey() status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleDeleteKey(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create a key first with test user as owner
	key := &storage.Key{
		ID:        "todelete12345678",
		Name:      "to-delete",
		Pubkey:    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		OwnerID:   testUserID,
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/todelete12345678", nil)
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleDeleteKey(rr, req, "todelete12345678")

	if rr.Code != http.StatusNoContent {
		t.Errorf("handleDeleteKey() status = %d, want %d", rr.Code, http.StatusNoContent)
	}

	// Verify key is deleted
	_, err := store.GetKey(ctx, "todelete12345678")
	if err != storage.ErrKeyNotFound {
		t.Error("key should be deleted")
	}
}

func TestHandleDeleteKey_NotFound(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/nonexistent", nil)
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleDeleteKey(rr, req, "nonexistent")

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleDeleteKey() status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleKeyByID_Routing(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create a key with test user as owner
	key := &storage.Key{
		ID:        "routetest1234567",
		Name:      "route-test",
		Pubkey:    "1111111111111111111111111111111111111111111111111111111111111111",
		OwnerID:   testUserID,
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"GET key", http.MethodGet, "/api/v1/keys/routetest1234567", http.StatusOK},
		{"DELETE key", http.MethodDelete, "/api/v1/keys/routetest1234567", http.StatusNoContent},
		{"missing id", http.MethodGet, "/api/v1/keys/", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Recreate key if deleted
			store.CreateKey(ctx, key)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.URL.Path = tt.path
			addAuthHeader(t, h, req)
			rr := httptest.NewRecorder()

			h.handleKeyByID(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("%s: status = %d, want %d", tt.name, rr.Code, tt.wantStatus)
			}
		})
	}
}

// Permission management tests

func TestHandleListPermissions(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create a key with test user as owner
	pubkey := "2222222222222222222222222222222222222222222222222222222222222222"
	key := &storage.Key{
		ID:        "permtest12345678",
		Name:      "perm-test",
		Pubkey:    pubkey,
		OwnerID:   testUserID,
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	// Create a permission
	perm := &storage.Permission{
		KeyID:      pubkey,
		UserPubkey: "3333333333333333333333333333333333333333333333333333333333333333",
		Methods:    []string{"sign_event", "ping"},
	}
	store.SetPermission(ctx, perm)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/permtest12345678/permissions", nil)
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleListPermissions(rr, req, "permtest12345678")

	if rr.Code != http.StatusOK {
		t.Errorf("handleListPermissions() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var perms []PermissionResponse
	if err := json.NewDecoder(rr.Body).Decode(&perms); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(perms) != 1 {
		t.Errorf("expected 1 permission, got %d", len(perms))
	}
}

func TestHandleSetPermission(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create a key with test user as owner
	pubkey := "4444444444444444444444444444444444444444444444444444444444444444"
	key := &storage.Key{
		ID:        "setperm123456789",
		Name:      "set-perm-test",
		Pubkey:    pubkey,
		OwnerID:   testUserID,
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	body := `{
		"user_pubkey": "5555555555555555555555555555555555555555555555555555555555555555",
		"methods": ["sign_event", "get_public_key"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/setperm123456789/permissions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleSetPermission(rr, req, "setperm123456789")

	if rr.Code != http.StatusOK {
		t.Errorf("handleSetPermission() status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp PermissionResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(resp.Methods))
	}
}

func TestHandleSetPermission_InvalidPubkey(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create a key with test user as owner
	key := &storage.Key{
		ID:        "badpubkey1234567",
		Name:      "bad-pubkey-test",
		Pubkey:    "6666666666666666666666666666666666666666666666666666666666666666",
		OwnerID:   testUserID,
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	body := `{
		"user_pubkey": "short",
		"methods": ["sign_event"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/badpubkey1234567/permissions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleSetPermission(rr, req, "badpubkey1234567")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleSetPermission() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleDeletePermission(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create a key and permission with test user as owner
	pubkey := "7777777777777777777777777777777777777777777777777777777777777777"
	userPubkey := "8888888888888888888888888888888888888888888888888888888888888888"

	key := &storage.Key{
		ID:        "delperm123456789",
		Name:      "del-perm-test",
		Pubkey:    pubkey,
		OwnerID:   testUserID,
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	perm := &storage.Permission{
		KeyID:      pubkey,
		UserPubkey: userPubkey,
		Methods:    []string{"sign_event"},
	}
	store.SetPermission(ctx, perm)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/delperm123456789/permissions/"+userPubkey, nil)
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleDeletePermission(rr, req, "delperm123456789", userPubkey)

	if rr.Code != http.StatusNoContent {
		t.Errorf("handleDeletePermission() status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

// Policy management tests

func TestHandleListPolicies_Empty(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	rr := httptest.NewRecorder()

	h.handlePolicies(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleListPolicies() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var policies []PolicyResponse
	if err := json.NewDecoder(rr.Body).Decode(&policies); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(policies) != 0 {
		t.Errorf("expected empty list, got %d policies", len(policies))
	}
}

func TestHandleCreatePolicy(t *testing.T) {
	h, _ := testHandler(t)

	body := `{
		"name": "basic-access",
		"description": "Basic signing access",
		"rules": [
			{"method": "sign_event", "allowed_kinds": [1, 4]},
			{"method": "ping"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handlePolicies(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("handleCreatePolicy() status = %d, want %d; body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var policy PolicyResponse
	if err := json.NewDecoder(rr.Body).Decode(&policy); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if policy.Name != "basic-access" {
		t.Errorf("policy.Name = %q, want %q", policy.Name, "basic-access")
	}
	if len(policy.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(policy.Rules))
	}
}

func TestHandleCreatePolicy_MissingName(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"rules": [{"method": "ping"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handlePolicies(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleCreatePolicy() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleCreatePolicy_NoRules(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"name": "empty-policy", "rules": []}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handlePolicies(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleCreatePolicy() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleGetPolicy(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	policy := &storage.Policy{
		ID:          "policy123",
		Name:        "test-policy",
		Description: "Test policy",
		Rules: []*storage.PolicyRule{
			{ID: "rule1", PolicyID: "policy123", Method: "sign_event"},
		},
		CreatedAt: time.Now(),
	}
	store.CreatePolicy(ctx, policy)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/policy123", nil)
	rr := httptest.NewRecorder()

	h.handleGetPolicy(rr, req, "policy123")

	if rr.Code != http.StatusOK {
		t.Errorf("handleGetPolicy() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleDeletePolicy(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	policy := &storage.Policy{
		ID:   "todelete",
		Name: "delete-me",
		Rules: []*storage.PolicyRule{
			{ID: "rule1", PolicyID: "todelete", Method: "ping"},
		},
		CreatedAt: time.Now(),
	}
	store.CreatePolicy(ctx, policy)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/todelete", nil)
	rr := httptest.NewRecorder()

	h.handleDeletePolicy(rr, req, "todelete")

	if rr.Code != http.StatusNoContent {
		t.Errorf("handleDeletePolicy() status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

// Token management tests

func TestHandleListTokens(t *testing.T) {
	h, _ := testHandler(t)

	// Without key_id parameter
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	rr := httptest.NewRecorder()

	h.handleTokens(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleListTokens() without key_id status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleListTokens_WithKeyID(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tokens?key_id=testkey", nil)
	rr := httptest.NewRecorder()

	h.handleTokens(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleListTokens() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleCreateToken(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create prerequisites
	key := &storage.Key{
		ID:        "tokenkey12345678",
		Name:      "token-key",
		Pubkey:    "9999999999999999999999999999999999999999999999999999999999999999",
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	policy := &storage.Policy{
		ID:   "tokenpolicy123",
		Name: "token-policy",
		Rules: []*storage.PolicyRule{
			{ID: "rule1", PolicyID: "tokenpolicy123", Method: "sign_event"},
		},
		CreatedAt: time.Now(),
	}
	store.CreatePolicy(ctx, policy)

	body := `{
		"policy_id": "tokenpolicy123",
		"key_id": "tokenkey12345678",
		"client_name": "Test Client"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleTokens(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("handleCreateToken() status = %d, want %d; body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}
}

func TestHandleCreateToken_MissingPolicy(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"key_id": "somekey"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleTokens(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleCreateToken() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// Pending request tests

func TestHandleListRequests_MissingKeyPubkey(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/requests", nil)
	rr := httptest.NewRecorder()

	h.handleRequests(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleListRequests() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleListRequests_WithKeyPubkey(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/requests?key_pubkey=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	rr := httptest.NewRecorder()

	h.handleRequests(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleListRequests() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleGetRequest_NotFound(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/requests/nonexistent", nil)
	rr := httptest.NewRecorder()

	h.handleGetRequest(rr, req, "nonexistent")

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleGetRequest() status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// User management tests

func TestHandleUserRegister(t *testing.T) {
	h, _ := testHandler(t)

	body := `{
		"username": "testuser",
		"email": "test@example.com",
		"password": "securepassword123"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserRegister(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("handleUserRegister() status = %d, want %d; body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var resp UserResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Username != "testuser" {
		t.Errorf("username = %q, want %q", resp.Username, "testuser")
	}
}

func TestHandleUserRegister_ShortUsername(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"username": "ab", "password": "securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleUserRegister() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleUserRegister_ShortPassword(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"username": "testuser", "password": "short"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleUserRegister() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleUserRegister_DuplicateUsername(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create existing user
	hash, _ := auth.HashPassword("password123", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "existing123",
		Username:     "existinguser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"username": "existinguser", "password": "newpassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserRegister(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("handleUserRegister() status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandleUserLogin(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create user
	hash, _ := auth.HashPassword("correctpassword", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "loginuser123",
		Username:     "loginuser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"username": "loginuser", "password": "correctpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleUserLogin() status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Token == "" {
		t.Error("token should not be empty")
	}
}

func TestHandleUserLogin_WrongPassword(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	hash, _ := auth.HashPassword("correctpassword", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "wrongpw123",
		Username:     "wrongpwuser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"username": "wrongpwuser", "password": "wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserLogin(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("handleUserLogin() status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandleUserLogin_LockedAccount(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	lockUntil := time.Now().Add(time.Hour)
	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "locked123",
		Username:     "lockeduser",
		PasswordHash: hash,
		LockedUntil:  &lockUntil,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"username": "lockeduser", "password": "password"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleUserLogin(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("handleUserLogin() status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestHandleUserMe(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create user
	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "meuser123",
		Username:     "meuser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	// Generate token
	token, _, _ := auth.GenerateJWT(h.authConfig, user.ID, user.Username)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.handleUserMe(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleUserMe() status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

func TestHandleUserMe_NoAuth(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	rr := httptest.NewRecorder()

	h.handleUserMe(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("handleUserMe() status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandleUserLogout(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create user
	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "logoutuser123",
		Username:     "logoutuser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	// Generate token
	token, _, _ := auth.GenerateJWT(h.authConfig, user.ID, user.Username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.handleUserLogout(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleUserLogout() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleUserSessions(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create user and session
	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "sessionuser123",
		Username:     "sessionuser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	session := &storage.UserSession{
		ID:        "session123",
		UserID:    user.ID,
		Token:     "token123",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	store.CreateUserSession(ctx, session)

	token, _, _ := auth.GenerateJWT(h.authConfig, user.ID, user.Username)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.handleUserSessions(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleUserSessions() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// NIP-05 tests

func TestHandleNIP05(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create a key
	key := &storage.Key{
		ID:        "nip05key12345678",
		Name:      "alice",
		Pubkey:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/nostr.json?name=alice", nil)
	rr := httptest.NewRecorder()

	h.handleNIP05(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleNIP05() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp NIP05Response
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Names["alice"] != key.Pubkey {
		t.Errorf("names[alice] = %q, want %q", resp.Names["alice"], key.Pubkey)
	}
}

func TestHandleNIP05_AllNames(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create multiple keys
	store.CreateKey(ctx, &storage.Key{
		ID:        "key1",
		Name:      "bob",
		Pubkey:    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		CreatedAt: time.Now(),
	})
	store.CreateKey(ctx, &storage.Key{
		ID:        "key2",
		Name:      "carol",
		Pubkey:    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		CreatedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/nostr.json", nil)
	rr := httptest.NewRecorder()

	h.handleNIP05(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleNIP05() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp NIP05Response
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Names) != 2 {
		t.Errorf("expected 2 names, got %d", len(resp.Names))
	}
}

// Audit logs test

func TestHandleAuditLogs(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	rr := httptest.NewRecorder()

	h.handleAuditLogs(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleAuditLogs() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// Helper function tests

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()

	if id1 == "" {
		t.Error("generateID() returned empty string")
	}
	if id1 == id2 {
		t.Error("generateID() should return unique IDs")
	}
	if len(id1) != 32 {
		t.Errorf("generateID() length = %d, want 32", len(id1))
	}
}

func TestUrlDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"hello+world", "hello world"},
		{"hello%20world", "hello world"},
		{"test%2Fpath", "test/path"},
		{"100%25", "100%"},
	}

	for _, tt := range tests {
		got, err := urlDecode(tt.input)
		if err != nil {
			t.Errorf("urlDecode(%q) error = %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("urlDecode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidateAuthHeader(t *testing.T) {
	h, _ := testHandler(t)

	// No auth header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := h.validateAuthHeader(req)
	if err == nil {
		t.Error("validateAuthHeader() should error on missing header")
	}

	// Invalid format
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	_, err = h.validateAuthHeader(req)
	if err == nil {
		t.Error("validateAuthHeader() should error on invalid format")
	}

	// Valid token
	token, _, _ := auth.GenerateJWT(h.authConfig, "user123", "testuser")
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	claims, err := h.validateAuthHeader(req)
	if err != nil {
		t.Errorf("validateAuthHeader() error = %v", err)
	}
	if claims.UserID != "user123" {
		t.Errorf("claims.UserID = %q, want %q", claims.UserID, "user123")
	}
}

// Nostrconnect tests

func TestHandleNostrConnect_InvalidURI(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"uri": "invalid://uri", "key_id": "testkey"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleNostrConnect(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleNostrConnect() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleNostrConnect_MissingURI(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"key_id": "testkey"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleNostrConnect(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleNostrConnect() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleNostrConnect_MissingKeyID(t *testing.T) {
	h, _ := testHandler(t)

	body := `{"uri": "nostrconnect://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee?relay=wss://relay.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleNostrConnect(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleNostrConnect() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// Bunker connect tests

func TestHandleBunkerConnect_MissingKeyID(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bunker/", nil)
	req.URL.Path = "/api/v1/bunker/"
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleBunkerConnect(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleBunkerConnect() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleBunkerConnect_KeyNotFound(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bunker/nonexistent", nil)
	req.URL.Path = "/api/v1/bunker/nonexistent"
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleBunkerConnect(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleBunkerConnect() status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleBunkerConnect_Success(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	key := &storage.Key{
		ID:        "bunkerkey1234567",
		Name:      "bunker-key",
		Pubkey:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		OwnerID:   testUserID,
		CreatedAt: time.Now(),
	}
	store.CreateKey(ctx, key)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bunker/bunkerkey1234567", nil)
	req.URL.Path = "/api/v1/bunker/bunkerkey1234567"
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()

	h.handleBunkerConnect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleBunkerConnect() status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp BunkerConnectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.SignerPubkey != key.Pubkey {
		t.Errorf("signer_pubkey = %q, want %q", resp.SignerPubkey, key.Pubkey)
	}
	if resp.Secret == "" {
		t.Error("secret should not be empty")
	}
	if !strings.HasPrefix(resp.BunkerURI, "bunker://") {
		t.Errorf("bunker_uri should start with bunker://, got %q", resp.BunkerURI)
	}
}

// JSON response helper tests

func TestJsonResponse(t *testing.T) {
	h, _ := testHandler(t)

	rr := httptest.NewRecorder()
	h.jsonResponse(rr, http.StatusOK, map[string]string{"test": "value"})

	if rr.Code != http.StatusOK {
		t.Errorf("jsonResponse() status = %d, want %d", rr.Code, http.StatusOK)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["test"] != "value" {
		t.Errorf("response body incorrect")
	}
}

func TestErrorResponse(t *testing.T) {
	h, _ := testHandler(t)

	rr := httptest.NewRecorder()
	h.errorResponse(rr, http.StatusBadRequest, "test error")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("errorResponse() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "test error" {
		t.Errorf("error = %q, want %q", resp["error"], "test error")
	}
}

// MFA tests

func TestHandleMFASetup(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	// Create user
	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "mfauser123",
		Username:     "mfauser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	token, _, _ := auth.GenerateJWT(h.authConfig, user.ID, user.Username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/mfa/setup", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.handleMFASetup(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleMFASetup() status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp MFASetupResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Secret == "" {
		t.Error("secret should not be empty")
	}
	if resp.QRCodeURL == "" {
		t.Error("qr_code_url should not be empty")
	}
	if len(resp.BackupCodes) == 0 {
		t.Error("backup_codes should not be empty")
	}
}

func TestHandleMFASetup_AlreadyEnabled(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "mfaenabled123",
		Username:     "mfaenableduser",
		PasswordHash: hash,
		MFAEnabled:   true,
		MFASecret:    "secret",
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	token, _, _ := auth.GenerateJWT(h.authConfig, user.ID, user.Username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/mfa/setup", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.handleMFASetup(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("handleMFASetup() status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandleMFAVerify_NotSetup(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "nosetup123",
		Username:     "nosetupuser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	token, _, _ := auth.GenerateJWT(h.authConfig, user.ID, user.Username)

	body := `{"code": "123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/mfa/verify", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleMFAVerify(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleMFAVerify() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleMFADisable_NotEnabled(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "nodisable123",
		Username:     "nodisableuser",
		PasswordHash: hash,
		MFAEnabled:   false,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	token, _, _ := auth.GenerateJWT(h.authConfig, user.ID, user.Username)

	body := `{"code": "123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/mfa/disable", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleMFADisable(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleMFADisable() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
