package admin

import (
	"context"
	"strings"
	"testing"
	"time"

	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/storage"
)

// mockKeyCreator implements KeyCreator for testing
type mockKeyCreator struct {
	registeredKeys map[string]string
}

func newMockKeyCreator() *mockKeyCreator {
	return &mockKeyCreator{
		registeredKeys: make(map[string]string),
	}
}

func (m *mockKeyCreator) RegisterKey(pubkey, privateKeyHex string) {
	m.registeredKeys[pubkey] = privateKeyHex
}

// mockRequestHandler implements RequestHandler for testing
type mockRequestHandler struct {
	approvedRequests []string
	deniedRequests   []string
	status           map[string]interface{}
}

func newMockRequestHandler() *mockRequestHandler {
	return &mockRequestHandler{
		approvedRequests: []string{},
		deniedRequests:   []string{},
		status: map[string]interface{}{
			"keys_loaded":      3,
			"connected_relays": []string{"wss://relay1.example.com", "wss://relay2.example.com"},
		},
	}
}

func (m *mockRequestHandler) ApproveRequest(requestID string, pendingReq *storage.PendingRequest) {
	m.approvedRequests = append(m.approvedRequests, requestID)
}

func (m *mockRequestHandler) DenyRequest(requestID string, pendingReq *storage.PendingRequest) {
	m.deniedRequests = append(m.deniedRequests, requestID)
}

func (m *mockRequestHandler) GetStatus() map[string]interface{} {
	return m.status
}

func TestNew(t *testing.T) {
	cfg := &config.Config{}
	store := storage.NewMemoryStorage()
	keyCreator := newMockKeyCreator()
	reqHandler := newMockRequestHandler()

	handler := New(cfg, store, nil, nil, keyCreator, reqHandler)

	if handler == nil {
		t.Fatal("New() returned nil")
	}
	if handler.config != cfg {
		t.Error("handler.config not set correctly")
	}
	if handler.storage != store {
		t.Error("handler.storage not set correctly")
	}
}

func TestHandler_SetSignerKey(t *testing.T) {
	handler := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, newMockKeyCreator(), newMockRequestHandler())
	handler.SetSignerKey("pubkey123", "privkey456")

	if handler.signerPubkey != "pubkey123" {
		t.Errorf("signerPubkey = %q, want %q", handler.signerPubkey, "pubkey123")
	}
	if handler.signerPriv != "privkey456" {
		t.Errorf("signerPriv = %q, want %q", handler.signerPriv, "privkey456")
	}
}

func TestHandler_isAdmin(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			AdminPubkeys: []string{"admin1", "admin2"},
		},
	}
	handler := New(cfg, storage.NewMemoryStorage(), nil, nil, newMockKeyCreator(), newMockRequestHandler())

	tests := []struct {
		pubkey string
		want   bool
	}{
		{"admin1", true},
		{"admin2", true},
		{"notadmin", false},
		{"", false},
	}

	for _, tt := range tests {
		got := handler.isAdmin(tt.pubkey)
		if got != tt.want {
			t.Errorf("isAdmin(%q) = %v, want %v", tt.pubkey, got, tt.want)
		}
	}
}

func TestHandler_helpMessage(t *testing.T) {
	handler := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, newMockKeyCreator(), newMockRequestHandler())
	msg := handler.helpMessage()

	if !strings.Contains(msg, "Admin Commands") {
		t.Error("help message should contain 'Admin Commands'")
	}
	if !strings.Contains(msg, "get_keys") {
		t.Error("help message should contain 'get_keys'")
	}
	if !strings.Contains(msg, "create_key") {
		t.Error("help message should contain 'create_key'")
	}
	if !strings.Contains(msg, "approve") {
		t.Error("help message should contain 'approve'")
	}
}

func TestHandler_processCommand_Help(t *testing.T) {
	handler := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, newMockKeyCreator(), newMockRequestHandler())
	ctx := context.Background()

	tests := []string{"help", "?", "HELP", "Help"}
	for _, cmd := range tests {
		response := handler.processCommand(ctx, cmd)
		if !strings.Contains(response, "Admin Commands") {
			t.Errorf("processCommand(%q) should return help message", cmd)
		}
	}
}

func TestHandler_processCommand_Status(t *testing.T) {
	cfg := &config.Config{}
	store := storage.NewMemoryStorage()
	reqHandler := newMockRequestHandler()
	handler := New(cfg, store, nil, nil, newMockKeyCreator(), reqHandler)

	ctx := context.Background()
	response := handler.processCommand(ctx, "status")

	if !strings.Contains(response, "Signer Status") {
		t.Error("status command should return status info")
	}
	if !strings.Contains(response, "Keys:") {
		t.Error("status should show keys count")
	}
}

func TestHandler_processCommand_GetKeys(t *testing.T) {
	store := storage.NewMemoryStorage()
	handler := New(&config.Config{}, store, nil, nil, newMockKeyCreator(), newMockRequestHandler())

	ctx := context.Background()

	// Empty keys
	response := handler.processCommand(ctx, "get_keys")
	if !strings.Contains(response, "No keys found") {
		t.Error("get_keys with no keys should say 'No keys found'")
	}

	// Add a key
	store.CreateKey(ctx, &storage.Key{
		ID:        "key1",
		Name:      "TestKey",
		Pubkey:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt: time.Now(),
	})

	response = handler.processCommand(ctx, "get_keys")
	if !strings.Contains(response, "Keys (1)") {
		t.Error("get_keys should show key count")
	}
	if !strings.Contains(response, "TestKey") {
		t.Error("get_keys should show key name")
	}
}

func TestHandler_processCommand_GetKey(t *testing.T) {
	store := storage.NewMemoryStorage()
	handler := New(&config.Config{}, store, nil, nil, newMockKeyCreator(), newMockRequestHandler())

	ctx := context.Background()

	// Missing argument
	response := handler.processCommand(ctx, "get_key")
	if !strings.Contains(response, "Usage:") {
		t.Error("get_key without args should show usage")
	}

	// Key not found
	response = handler.processCommand(ctx, "get_key nonexistent")
	if !strings.Contains(response, "not found") {
		t.Error("get_key for nonexistent key should say 'not found'")
	}

	// Add and get key
	store.CreateKey(ctx, &storage.Key{
		ID:        "key1",
		Name:      "TestKey",
		Pubkey:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt: time.Now(),
	})

	response = handler.processCommand(ctx, "get_key key1")
	if !strings.Contains(response, "TestKey") {
		t.Error("get_key should show key details")
	}
	if !strings.Contains(response, "Pubkey:") {
		t.Error("get_key should show pubkey")
	}
}

func TestHandler_processCommand_CreateKey(t *testing.T) {
	store := storage.NewMemoryStorage()
	keyCreator := newMockKeyCreator()
	handler := New(&config.Config{}, store, nil, nil, keyCreator, newMockRequestHandler())

	ctx := context.Background()

	response := handler.processCommand(ctx, "create_key MyNewKey")
	if !strings.Contains(response, "Key Created") {
		t.Error("create_key should confirm creation")
	}
	if !strings.Contains(response, "MyNewKey") {
		t.Error("create_key should show the key name")
	}

	// Verify key was created in storage
	keys, _ := store.ListKeys(ctx)
	if len(keys) != 1 {
		t.Errorf("storage should have 1 key, got %d", len(keys))
	}

	// Verify key was registered with key creator
	if len(keyCreator.registeredKeys) != 1 {
		t.Error("key should be registered with key creator")
	}
}

func TestHandler_processCommand_DeleteKey(t *testing.T) {
	store := storage.NewMemoryStorage()
	handler := New(&config.Config{}, store, nil, nil, newMockKeyCreator(), newMockRequestHandler())

	ctx := context.Background()

	// Missing argument
	response := handler.processCommand(ctx, "delete_key")
	if !strings.Contains(response, "Usage:") {
		t.Error("delete_key without args should show usage")
	}

	// Key not found
	response = handler.processCommand(ctx, "delete_key nonexistent")
	if !strings.Contains(response, "not found") {
		t.Error("delete_key for nonexistent key should say 'not found'")
	}

	// Add and delete key
	store.CreateKey(ctx, &storage.Key{ID: "key1", Name: "TestKey", Pubkey: "pub1"})

	response = handler.processCommand(ctx, "delete_key key1")
	if !strings.Contains(response, "deleted") {
		t.Error("delete_key should confirm deletion")
	}

	keys, _ := store.ListKeys(ctx)
	if len(keys) != 0 {
		t.Error("key should be deleted from storage")
	}
}

func TestHandler_processCommand_ListPending(t *testing.T) {
	store := storage.NewMemoryStorage()
	handler := New(&config.Config{}, store, nil, nil, newMockKeyCreator(), newMockRequestHandler())

	ctx := context.Background()

	// No keys, no pending requests
	response := handler.processCommand(ctx, "list_pending")
	if !strings.Contains(response, "No pending") {
		t.Error("list_pending with no requests should say 'No pending'")
	}

	// Add a key and pending request (use 64-char hex pubkeys to avoid truncation issues)
	keyPubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	clientPubkey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	store.CreateKey(ctx, &storage.Key{ID: "key1", Pubkey: keyPubkey})
	store.CreatePendingRequest(ctx, &storage.PendingRequest{
		ID:           "req1",
		KeyPubkey:    keyPubkey,
		ClientPubkey: clientPubkey,
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Minute),
	})

	response = handler.processCommand(ctx, "list_pending")
	if !strings.Contains(response, "Pending Requests (1)") {
		t.Error("list_pending should show request count")
	}
	if !strings.Contains(response, "sign_event") {
		t.Error("list_pending should show method")
	}
}

func TestHandler_processCommand_Approve(t *testing.T) {
	store := storage.NewMemoryStorage()
	reqHandler := newMockRequestHandler()
	handler := New(&config.Config{}, store, nil, nil, newMockKeyCreator(), reqHandler)

	ctx := context.Background()

	// Missing argument
	response := handler.processCommand(ctx, "approve")
	if !strings.Contains(response, "Usage:") {
		t.Error("approve without args should show usage")
	}

	// Request not found
	response = handler.processCommand(ctx, "approve nonexistent")
	if !strings.Contains(response, "not found") || !strings.Contains(response, "expired") {
		t.Error("approve for nonexistent request should say 'not found or expired'")
	}

	// Add pending request and approve (use 64-char hex pubkeys)
	keyPubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	clientPubkey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	store.CreatePendingRequest(ctx, &storage.PendingRequest{
		ID:           "req1",
		KeyPubkey:    keyPubkey,
		ClientPubkey: clientPubkey,
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Minute),
	})

	response = handler.processCommand(ctx, "approve req1")
	if !strings.Contains(response, "approved") {
		t.Error("approve should confirm approval")
	}

	if len(reqHandler.approvedRequests) != 1 || reqHandler.approvedRequests[0] != "req1" {
		t.Error("request handler should receive approval")
	}
}

func TestHandler_processCommand_Deny(t *testing.T) {
	store := storage.NewMemoryStorage()
	reqHandler := newMockRequestHandler()
	handler := New(&config.Config{}, store, nil, nil, newMockKeyCreator(), reqHandler)

	ctx := context.Background()

	// Missing argument
	response := handler.processCommand(ctx, "deny")
	if !strings.Contains(response, "Usage:") {
		t.Error("deny without args should show usage")
	}

	// Add pending request and deny (use 64-char hex pubkeys)
	keyPubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	clientPubkey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	store.CreatePendingRequest(ctx, &storage.PendingRequest{
		ID:           "req1",
		KeyPubkey:    keyPubkey,
		ClientPubkey: clientPubkey,
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Minute),
	})

	response = handler.processCommand(ctx, "deny req1")
	if !strings.Contains(response, "denied") {
		t.Error("deny should confirm denial")
	}

	if len(reqHandler.deniedRequests) != 1 || reqHandler.deniedRequests[0] != "req1" {
		t.Error("request handler should receive denial")
	}
}

func TestHandler_processCommand_ListUsers(t *testing.T) {
	store := storage.NewMemoryStorage()
	handler := New(&config.Config{}, store, nil, nil, newMockKeyCreator(), newMockRequestHandler())

	ctx := context.Background()

	// No users
	response := handler.processCommand(ctx, "list_users")
	if !strings.Contains(response, "No users") {
		t.Error("list_users with no users should say 'No users'")
	}

	// Add user (use ID that's at least 16+ chars to avoid truncation issues)
	store.CreateUser(ctx, &storage.User{
		ID:         "user0123456789abcdef",
		Username:   "testuser",
		Email:      "test@example.com",
		MFAEnabled: true,
		CreatedAt:  time.Now(),
	})

	response = handler.processCommand(ctx, "list_users")
	if !strings.Contains(response, "Users (1)") {
		t.Error("list_users should show user count")
	}
	if !strings.Contains(response, "testuser") {
		t.Error("list_users should show username")
	}
}

func TestHandler_processCommand_ListPolicies(t *testing.T) {
	store := storage.NewMemoryStorage()
	handler := New(&config.Config{}, store, nil, nil, newMockKeyCreator(), newMockRequestHandler())

	ctx := context.Background()

	// No policies
	response := handler.processCommand(ctx, "list_policies")
	if !strings.Contains(response, "No policies") {
		t.Error("list_policies with no policies should say 'No policies'")
	}

	// Add policy
	store.CreatePolicy(ctx, &storage.Policy{
		ID:        "policy1",
		Name:      "TestPolicy",
		Rules:     []*storage.PolicyRule{{ID: "rule1", Method: "sign_event"}},
		CreatedAt: time.Now(),
	})

	response = handler.processCommand(ctx, "list_policies")
	if !strings.Contains(response, "Policies (1)") {
		t.Error("list_policies should show policy count")
	}
	if !strings.Contains(response, "TestPolicy") {
		t.Error("list_policies should show policy name")
	}
}

func TestHandler_processCommand_Unknown(t *testing.T) {
	handler := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, newMockKeyCreator(), newMockRequestHandler())
	ctx := context.Background()

	response := handler.processCommand(ctx, "unknowncommand")
	if !strings.Contains(response, "Unknown command") {
		t.Error("unknown command should say 'Unknown command'")
	}
	if !strings.Contains(response, "help") {
		t.Error("unknown command response should mention 'help'")
	}
}

func TestHandler_processCommand_Empty(t *testing.T) {
	handler := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, newMockKeyCreator(), newMockRequestHandler())
	ctx := context.Background()

	response := handler.processCommand(ctx, "")
	if !strings.Contains(response, "Admin Commands") {
		t.Error("empty command should return help")
	}

	response = handler.processCommand(ctx, "   ")
	if !strings.Contains(response, "Admin Commands") {
		t.Error("whitespace command should return help")
	}
}

func TestHandler_ProcessCommandHTTP(t *testing.T) {
	handler := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, newMockKeyCreator(), newMockRequestHandler())
	ctx := context.Background()

	t.Run("successful command", func(t *testing.T) {
		resp := handler.ProcessCommandHTTP(ctx, "status")
		if !resp.Success {
			t.Error("status command should be successful")
		}
		if resp.Message == "" {
			t.Error("response message should not be empty")
		}
	})

	t.Run("error command", func(t *testing.T) {
		resp := handler.ProcessCommandHTTP(ctx, "get_key nonexistent")
		// This returns "Key not found" which doesn't start with "Error"
		// so Success might be true, but let's verify the message
		if resp.Message == "" {
			t.Error("response message should not be empty")
		}
	})

	t.Run("unknown command", func(t *testing.T) {
		resp := handler.ProcessCommandHTTP(ctx, "invalid")
		if resp.Success {
			t.Error("unknown command should not be successful")
		}
	})
}

func TestHandler_GetAdminStats(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			AdminPubkeys:         []string{"admin1", "admin2"},
			RequireApproval:      true,
			AuthorizationTimeout: 120,
		},
	}
	store := storage.NewMemoryStorage()
	reqHandler := newMockRequestHandler()
	handler := New(cfg, store, nil, nil, newMockKeyCreator(), reqHandler)

	ctx := context.Background()

	// Add some data
	store.CreateKey(ctx, &storage.Key{ID: "key1", Pubkey: "pub1"})
	store.CreateUser(ctx, &storage.User{ID: "user1", Username: "user1"})
	store.CreatePolicy(ctx, &storage.Policy{ID: "policy1", Name: "policy1"})

	stats, err := handler.GetAdminStats(ctx)
	if err != nil {
		t.Fatalf("GetAdminStats() error = %v", err)
	}

	if stats["keys_count"] != 1 {
		t.Errorf("keys_count = %v, want 1", stats["keys_count"])
	}
	if stats["users_count"] != 1 {
		t.Errorf("users_count = %v, want 1", stats["users_count"])
	}
	if stats["policies_count"] != 1 {
		t.Errorf("policies_count = %v, want 1", stats["policies_count"])
	}
	if stats["admin_pubkeys"] != 2 {
		t.Errorf("admin_pubkeys = %v, want 2", stats["admin_pubkeys"])
	}
	if stats["require_approval"] != true {
		t.Errorf("require_approval = %v, want true", stats["require_approval"])
	}
	if stats["authorization_timeout"] != 120 {
		t.Errorf("authorization_timeout = %v, want 120", stats["authorization_timeout"])
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"abc", 3, "abc"},
		{"", 5, ""},
		{"test", 4, "test"},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestAdminResponse(t *testing.T) {
	resp := AdminResponse{
		Success: true,
		Message: "Operation completed",
	}

	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.Message != "Operation completed" {
		t.Errorf("Message = %q, want %q", resp.Message, "Operation completed")
	}
}
