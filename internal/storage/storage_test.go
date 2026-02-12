package storage

import (
	"context"
	"testing"
	"time"
)

func TestNewMemoryStorage(t *testing.T) {
	s := NewMemoryStorage()
	if s == nil {
		t.Fatal("NewMemoryStorage() returned nil")
	}
	if s.keys == nil {
		t.Error("NewMemoryStorage().keys is nil")
	}
}

// Key Tests

func TestMemoryStorage_CreateKey(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{
		ID:        "key1",
		Name:      "Test Key",
		Pubkey:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt: time.Now(),
	}

	err := s.CreateKey(ctx, key)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// Try to create duplicate by ID
	err = s.CreateKey(ctx, key)
	if err != ErrKeyExists {
		t.Errorf("CreateKey() duplicate error = %v, want %v", err, ErrKeyExists)
	}

	// Try to create duplicate by pubkey
	key2 := &Key{
		ID:     "key2",
		Pubkey: key.Pubkey,
	}
	err = s.CreateKey(ctx, key2)
	if err != ErrKeyExists {
		t.Errorf("CreateKey() duplicate pubkey error = %v, want %v", err, ErrKeyExists)
	}
}

func TestMemoryStorage_GetKey(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{
		ID:        "key1",
		Name:      "Test Key",
		Pubkey:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt: time.Now(),
	}
	s.CreateKey(ctx, key)

	got, err := s.GetKey(ctx, "key1")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetKey().ID = %q, want %q", got.ID, key.ID)
	}

	_, err = s.GetKey(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKey() nonexistent error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestMemoryStorage_GetKeyByPubkey(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{
		ID:     "key1",
		Pubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	s.CreateKey(ctx, key)

	got, err := s.GetKeyByPubkey(ctx, key.Pubkey)
	if err != nil {
		t.Fatalf("GetKeyByPubkey() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetKeyByPubkey().ID = %q, want %q", got.ID, key.ID)
	}

	_, err = s.GetKeyByPubkey(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKeyByPubkey() nonexistent error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestMemoryStorage_GetKeyByName(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{
		ID:     "key1",
		Name:   "TestKey",
		Pubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	s.CreateKey(ctx, key)

	got, err := s.GetKeyByName(ctx, "TestKey")
	if err != nil {
		t.Fatalf("GetKeyByName() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetKeyByName().ID = %q, want %q", got.ID, key.ID)
	}

	_, err = s.GetKeyByName(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKeyByName() nonexistent error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestMemoryStorage_ListKeys(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	keys, err := s.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListKeys() empty storage = %d keys, want 0", len(keys))
	}

	s.CreateKey(ctx, &Key{ID: "key1", Pubkey: "pub1"})
	s.CreateKey(ctx, &Key{ID: "key2", Pubkey: "pub2"})

	keys, err = s.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys() = %d keys, want 2", len(keys))
	}
}

func TestMemoryStorage_DeleteKey(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{
		ID:     "key1",
		Name:   "TestKey",
		Pubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	s.CreateKey(ctx, key)

	err := s.DeleteKey(ctx, "key1")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	_, err = s.GetKey(ctx, "key1")
	if err != ErrKeyNotFound {
		t.Errorf("GetKey() after delete error = %v, want %v", err, ErrKeyNotFound)
	}

	err = s.DeleteKey(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("DeleteKey() nonexistent error = %v, want %v", err, ErrKeyNotFound)
	}
}

// Permission Tests

func TestMemoryStorage_SetPermission(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{
		ID:     "key1",
		Pubkey: "keypub123",
	}
	s.CreateKey(ctx, key)

	perm := &Permission{
		KeyID:      "keypub123",
		UserPubkey: "userpub456",
		Methods:    []string{"sign_event", "ping"},
	}

	err := s.SetPermission(ctx, perm)
	if err != nil {
		t.Fatalf("SetPermission() error = %v", err)
	}

	// Setting permission for nonexistent key should fail
	err = s.SetPermission(ctx, &Permission{
		KeyID:      "nonexistent",
		UserPubkey: "user",
	})
	if err != ErrKeyNotFound {
		t.Errorf("SetPermission() nonexistent key error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestMemoryStorage_GetPermission(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{ID: "key1", Pubkey: "keypub123"}
	s.CreateKey(ctx, key)

	perm := &Permission{
		KeyID:      "keypub123",
		UserPubkey: "userpub456",
		Methods:    []string{"sign_event"},
	}
	s.SetPermission(ctx, perm)

	got, err := s.GetPermission(ctx, "keypub123", "userpub456")
	if err != nil {
		t.Fatalf("GetPermission() error = %v", err)
	}
	if len(got.Methods) != 1 || got.Methods[0] != "sign_event" {
		t.Errorf("GetPermission().Methods = %v, want [sign_event]", got.Methods)
	}

	_, err = s.GetPermission(ctx, "keypub123", "unknown")
	if err != ErrNotAuthorized {
		t.Errorf("GetPermission() unknown user error = %v, want %v", err, ErrNotAuthorized)
	}
}

func TestMemoryStorage_GetPermissionExpired(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{ID: "key1", Pubkey: "keypub123"}
	s.CreateKey(ctx, key)

	expired := time.Now().Add(-time.Hour)
	perm := &Permission{
		KeyID:      "keypub123",
		UserPubkey: "userpub456",
		Methods:    []string{"sign_event"},
		ExpiresAt:  &expired,
	}
	s.SetPermission(ctx, perm)

	_, err := s.GetPermission(ctx, "keypub123", "userpub456")
	if err != ErrNotAuthorized {
		t.Errorf("GetPermission() expired error = %v, want %v", err, ErrNotAuthorized)
	}
}

func TestMemoryStorage_ListPermissions(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{ID: "key1", Pubkey: "keypub123"}
	s.CreateKey(ctx, key)

	s.SetPermission(ctx, &Permission{KeyID: "keypub123", UserPubkey: "user1", Methods: []string{"ping"}})
	s.SetPermission(ctx, &Permission{KeyID: "keypub123", UserPubkey: "user2", Methods: []string{"sign_event"}})

	perms, err := s.ListPermissions(ctx, "keypub123")
	if err != nil {
		t.Fatalf("ListPermissions() error = %v", err)
	}
	if len(perms) != 2 {
		t.Errorf("ListPermissions() = %d, want 2", len(perms))
	}
}

func TestMemoryStorage_DeletePermission(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	key := &Key{ID: "key1", Pubkey: "keypub123"}
	s.CreateKey(ctx, key)

	perm := &Permission{KeyID: "keypub123", UserPubkey: "userpub456", Methods: []string{"ping"}}
	s.SetPermission(ctx, perm)

	err := s.DeletePermission(ctx, "keypub123", "userpub456")
	if err != nil {
		t.Fatalf("DeletePermission() error = %v", err)
	}

	_, err = s.GetPermission(ctx, "keypub123", "userpub456")
	if err != ErrNotAuthorized {
		t.Errorf("GetPermission() after delete error = %v, want %v", err, ErrNotAuthorized)
	}
}

// Session Tests

func TestMemoryStorage_SessionLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	session := &Session{
		ID:           "sess1",
		KeyID:        "key1",
		ClientPubkey: "client1",
		Permissions:  []string{"ping"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	err := s.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	got, err := s.GetSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("GetSession().ID = %q, want %q", got.ID, session.ID)
	}

	err = s.DeleteSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}

	_, err = s.GetSession(ctx, "sess1")
	if err != ErrSessionNotFound {
		t.Errorf("GetSession() after delete error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestMemoryStorage_GetSessionExpired(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	session := &Session{
		ID:        "sess1",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	s.CreateSession(ctx, session)

	_, err := s.GetSession(ctx, "sess1")
	if err != ErrSessionNotFound {
		t.Errorf("GetSession() expired error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestMemoryStorage_GetSessionByClient(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	session := &Session{
		ID:           "sess1",
		KeyID:        "key1",
		ClientPubkey: "client1",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	s.CreateSession(ctx, session)

	got, err := s.GetSessionByClient(ctx, "key1", "client1")
	if err != nil {
		t.Fatalf("GetSessionByClient() error = %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("GetSessionByClient().ID = %q, want %q", got.ID, session.ID)
	}

	_, err = s.GetSessionByClient(ctx, "key1", "unknown")
	if err != ErrSessionNotFound {
		t.Errorf("GetSessionByClient() unknown error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestMemoryStorage_CleanExpiredSessions(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	s.CreateSession(ctx, &Session{ID: "active", ExpiresAt: time.Now().Add(time.Hour)})
	s.CreateSession(ctx, &Session{ID: "expired", ExpiresAt: time.Now().Add(-time.Hour)})

	err := s.CleanExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredSessions() error = %v", err)
	}

	_, err = s.GetSession(ctx, "active")
	if err != nil {
		t.Errorf("active session should still exist")
	}

	// Expired session should be gone from internal map
	s.mu.RLock()
	_, exists := s.sessions["expired"]
	s.mu.RUnlock()
	if exists {
		t.Error("expired session should be cleaned up")
	}
}

// Policy Tests

func TestMemoryStorage_PolicyLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	policy := &Policy{
		ID:          "policy1",
		Name:        "Test Policy",
		Description: "A test policy",
		Rules: []*PolicyRule{
			{ID: "rule1", PolicyID: "policy1", Method: "sign_event", MaxUsage: 100},
		},
		CreatedAt: time.Now(),
	}

	err := s.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	got, err := s.GetPolicy(ctx, "policy1")
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if got.Name != policy.Name {
		t.Errorf("GetPolicy().Name = %q, want %q", got.Name, policy.Name)
	}

	policies, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("ListPolicies() = %d, want 1", len(policies))
	}

	err = s.DeletePolicy(ctx, "policy1")
	if err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}

	_, err = s.GetPolicy(ctx, "policy1")
	if err != ErrPolicyNotFound {
		t.Errorf("GetPolicy() after delete error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestMemoryStorage_GetPolicyExpired(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	expired := time.Now().Add(-time.Hour)
	policy := &Policy{
		ID:        "policy1",
		ExpiresAt: &expired,
	}
	s.CreatePolicy(ctx, policy)

	_, err := s.GetPolicy(ctx, "policy1")
	if err != ErrPolicyNotFound {
		t.Errorf("GetPolicy() expired error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestMemoryStorage_IncrementRuleUsage(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	policy := &Policy{
		ID:   "policy1",
		Name: "Test",
		Rules: []*PolicyRule{
			{ID: "rule1", PolicyID: "policy1", Method: "sign_event", MaxUsage: 10, CurrentUsage: 0},
		},
	}
	s.CreatePolicy(ctx, policy)

	err := s.IncrementRuleUsage(ctx, "rule1")
	if err != nil {
		t.Fatalf("IncrementRuleUsage() error = %v", err)
	}

	if s.policyRules["rule1"].CurrentUsage != 1 {
		t.Errorf("CurrentUsage = %d, want 1", s.policyRules["rule1"].CurrentUsage)
	}

	err = s.IncrementRuleUsage(ctx, "nonexistent")
	if err != ErrPolicyNotFound {
		t.Errorf("IncrementRuleUsage() nonexistent error = %v, want %v", err, ErrPolicyNotFound)
	}
}

// Token Tests

func TestMemoryStorage_TokenLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	token := &Token{
		ID:        "token1",
		PolicyID:  "policy1",
		KeyID:     "key1",
		CreatedAt: time.Now(),
	}

	err := s.CreateToken(ctx, token)
	if err != nil {
		t.Fatalf("CreateToken() error = %v", err)
	}

	got, err := s.GetToken(ctx, "token1")
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if got.ID != token.ID {
		t.Errorf("GetToken().ID = %q, want %q", got.ID, token.ID)
	}

	tokens, err := s.ListTokens(ctx, "key1")
	if err != nil {
		t.Fatalf("ListTokens() error = %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("ListTokens() = %d, want 1", len(tokens))
	}

	err = s.DeleteToken(ctx, "token1")
	if err != nil {
		t.Fatalf("DeleteToken() error = %v", err)
	}

	_, err = s.GetToken(ctx, "token1")
	if err != ErrTokenNotFound {
		t.Errorf("GetToken() after delete error = %v, want %v", err, ErrTokenNotFound)
	}
}

func TestMemoryStorage_RedeemToken(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	token := &Token{
		ID:        "token1",
		PolicyID:  "policy1",
		KeyID:     "key1",
		CreatedAt: time.Now(),
	}
	s.CreateToken(ctx, token)

	redeemed, err := s.RedeemToken(ctx, "token1", "redeemer123")
	if err != nil {
		t.Fatalf("RedeemToken() error = %v", err)
	}
	if redeemed.RedeemedBy != "redeemer123" {
		t.Errorf("RedeemToken().RedeemedBy = %q, want %q", redeemed.RedeemedBy, "redeemer123")
	}
	if redeemed.RedeemedAt == nil {
		t.Error("RedeemToken().RedeemedAt should not be nil")
	}

	// Try to redeem again
	_, err = s.RedeemToken(ctx, "token1", "another")
	if err != ErrTokenRedeemed {
		t.Errorf("RedeemToken() already redeemed error = %v, want %v", err, ErrTokenRedeemed)
	}
}

func TestMemoryStorage_RedeemTokenExpired(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	expired := time.Now().Add(-time.Hour)
	token := &Token{
		ID:        "token1",
		ExpiresAt: &expired,
	}
	s.CreateToken(ctx, token)

	_, err := s.RedeemToken(ctx, "token1", "redeemer")
	if err != ErrTokenExpired {
		t.Errorf("RedeemToken() expired error = %v, want %v", err, ErrTokenExpired)
	}
}

// Pending Request Tests

func TestMemoryStorage_PendingRequestLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	req := &PendingRequest{
		ID:           "req1",
		KeyPubkey:    "key1",
		ClientPubkey: "client1",
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Minute),
		CreatedAt:    time.Now(),
	}

	err := s.CreatePendingRequest(ctx, req)
	if err != nil {
		t.Fatalf("CreatePendingRequest() error = %v", err)
	}

	got, err := s.GetPendingRequest(ctx, "req1")
	if err != nil {
		t.Fatalf("GetPendingRequest() error = %v", err)
	}
	if got.Method != req.Method {
		t.Errorf("GetPendingRequest().Method = %q, want %q", got.Method, req.Method)
	}

	reqs, err := s.ListPendingRequests(ctx, "key1")
	if err != nil {
		t.Fatalf("ListPendingRequests() error = %v", err)
	}
	if len(reqs) != 1 {
		t.Errorf("ListPendingRequests() = %d, want 1", len(reqs))
	}

	err = s.DeletePendingRequest(ctx, "req1")
	if err != nil {
		t.Fatalf("DeletePendingRequest() error = %v", err)
	}

	_, err = s.GetPendingRequest(ctx, "req1")
	if err != ErrRequestNotFound {
		t.Errorf("GetPendingRequest() after delete error = %v, want %v", err, ErrRequestNotFound)
	}
}

func TestMemoryStorage_GetPendingRequestExpired(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	req := &PendingRequest{
		ID:        "req1",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	s.CreatePendingRequest(ctx, req)

	_, err := s.GetPendingRequest(ctx, "req1")
	if err != ErrRequestExpired {
		t.Errorf("GetPendingRequest() expired error = %v, want %v", err, ErrRequestExpired)
	}
}

// User Tests

func TestMemoryStorage_UserLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	user := &User{
		ID:           "user1",
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash123",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := s.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	// Duplicate ID
	err = s.CreateUser(ctx, user)
	if err != ErrUserExists {
		t.Errorf("CreateUser() duplicate error = %v, want %v", err, ErrUserExists)
	}

	// Duplicate username
	user2 := &User{ID: "user2", Username: "testuser"}
	err = s.CreateUser(ctx, user2)
	if err != ErrUserExists {
		t.Errorf("CreateUser() duplicate username error = %v, want %v", err, ErrUserExists)
	}

	got, err := s.GetUser(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if got.Username != user.Username {
		t.Errorf("GetUser().Username = %q, want %q", got.Username, user.Username)
	}

	got, err = s.GetUserByUsername(ctx, "testuser")
	if err != nil {
		t.Fatalf("GetUserByUsername() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByUsername().ID = %q, want %q", got.ID, user.ID)
	}

	got, err = s.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByEmail().ID = %q, want %q", got.ID, user.ID)
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 1 {
		t.Errorf("ListUsers() = %d, want 1", len(users))
	}

	err = s.DeleteUser(ctx, "user1")
	if err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	_, err = s.GetUser(ctx, "user1")
	if err != ErrUserNotFound {
		t.Errorf("GetUser() after delete error = %v, want %v", err, ErrUserNotFound)
	}
}

func TestMemoryStorage_GetUserByPubkey(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	user := &User{
		ID:       "user1",
		Username: "testuser",
		Pubkey:   "pubkey123",
	}
	s.CreateUser(ctx, user)

	got, err := s.GetUserByPubkey(ctx, "pubkey123")
	if err != nil {
		t.Fatalf("GetUserByPubkey() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByPubkey().ID = %q, want %q", got.ID, user.ID)
	}

	_, err = s.GetUserByPubkey(ctx, "unknown")
	if err != ErrUserNotFound {
		t.Errorf("GetUserByPubkey() unknown error = %v, want %v", err, ErrUserNotFound)
	}
}

func TestMemoryStorage_UpdateUser(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	// Create initial user
	user := &User{
		ID:       "user1",
		Username: "oldname",
		Email:    "old@example.com",
	}
	s.CreateUser(ctx, user)

	// Create updated user (new struct to avoid pointer aliasing)
	updatedUser := &User{
		ID:       "user1",
		Username: "newname",
		Email:    "new@example.com",
	}

	err := s.UpdateUser(ctx, updatedUser)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	got, err := s.GetUserByUsername(ctx, "newname")
	if err != nil {
		t.Fatalf("GetUserByUsername() after update error = %v", err)
	}
	if got.Email != "new@example.com" {
		t.Errorf("UpdateUser() email = %q, want %q", got.Email, "new@example.com")
	}

	_, err = s.GetUserByUsername(ctx, "oldname")
	if err != ErrUserNotFound {
		t.Errorf("old username should not exist after update")
	}
}

func TestMemoryStorage_UserLockout(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	user := &User{ID: "user1", Username: "testuser"}
	s.CreateUser(ctx, user)

	err := s.IncrementFailedLogins(ctx, "user1")
	if err != nil {
		t.Fatalf("IncrementFailedLogins() error = %v", err)
	}

	got, _ := s.GetUser(ctx, "user1")
	if got.FailedLoginAttempts != 1 {
		t.Errorf("FailedLoginAttempts = %d, want 1", got.FailedLoginAttempts)
	}

	lockUntil := time.Now().Add(15 * time.Minute)
	err = s.LockUser(ctx, "user1", lockUntil)
	if err != nil {
		t.Fatalf("LockUser() error = %v", err)
	}

	got, _ = s.GetUser(ctx, "user1")
	if got.LockedUntil == nil {
		t.Error("LockedUntil should not be nil after LockUser()")
	}

	err = s.UnlockUser(ctx, "user1")
	if err != nil {
		t.Fatalf("UnlockUser() error = %v", err)
	}

	got, _ = s.GetUser(ctx, "user1")
	if got.LockedUntil != nil {
		t.Error("LockedUntil should be nil after UnlockUser()")
	}
	if got.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts after unlock = %d, want 0", got.FailedLoginAttempts)
	}

	err = s.ResetFailedLogins(ctx, "user1")
	if err != nil {
		t.Fatalf("ResetFailedLogins() error = %v", err)
	}
}

// User Session Tests

func TestMemoryStorage_UserSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	session := &UserSession{
		ID:        "sess1",
		UserID:    "user1",
		Token:     "token123",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}

	err := s.CreateUserSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateUserSession() error = %v", err)
	}

	got, err := s.GetUserSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("GetUserSession() error = %v", err)
	}
	if got.UserID != session.UserID {
		t.Errorf("GetUserSession().UserID = %q, want %q", got.UserID, session.UserID)
	}

	sessions, err := s.ListUserSessions(ctx, "user1")
	if err != nil {
		t.Fatalf("ListUserSessions() error = %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("ListUserSessions() = %d, want 1", len(sessions))
	}

	err = s.DeleteUserSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("DeleteUserSession() error = %v", err)
	}

	_, err = s.GetUserSession(ctx, "sess1")
	if err != ErrSessionNotFound {
		t.Errorf("GetUserSession() after delete error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestMemoryStorage_DeleteUserSessions(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	s.CreateUserSession(ctx, &UserSession{ID: "sess1", UserID: "user1", ExpiresAt: time.Now().Add(time.Hour)})
	s.CreateUserSession(ctx, &UserSession{ID: "sess2", UserID: "user1", ExpiresAt: time.Now().Add(time.Hour)})
	s.CreateUserSession(ctx, &UserSession{ID: "sess3", UserID: "user2", ExpiresAt: time.Now().Add(time.Hour)})

	err := s.DeleteUserSessions(ctx, "user1")
	if err != nil {
		t.Fatalf("DeleteUserSessions() error = %v", err)
	}

	sessions, _ := s.ListUserSessions(ctx, "user1")
	if len(sessions) != 0 {
		t.Errorf("ListUserSessions() after delete = %d, want 0", len(sessions))
	}

	// user2's session should still exist
	sessions, _ = s.ListUserSessions(ctx, "user2")
	if len(sessions) != 1 {
		t.Errorf("user2 sessions = %d, want 1", len(sessions))
	}
}

// Bunker Secret Tests

func TestMemoryStorage_BunkerSecretLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	secret := &BunkerSecret{
		ID:        "secret1",
		KeyPubkey: "keypub123",
		Secret:    "mysecret",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	err := s.CreateBunkerSecret(ctx, secret)
	if err != nil {
		t.Fatalf("CreateBunkerSecret() error = %v", err)
	}

	got, err := s.ValidateBunkerSecret(ctx, "keypub123", "mysecret")
	if err != nil {
		t.Fatalf("ValidateBunkerSecret() error = %v", err)
	}
	if got.ID != secret.ID {
		t.Errorf("ValidateBunkerSecret().ID = %q, want %q", got.ID, secret.ID)
	}
	if got.UsedAt == nil {
		t.Error("ValidateBunkerSecret() should mark as used")
	}

	// Try to use again (one-time use)
	_, err = s.ValidateBunkerSecret(ctx, "keypub123", "mysecret")
	if err != ErrBunkerSecretInvalid {
		t.Errorf("ValidateBunkerSecret() already used error = %v, want %v", err, ErrBunkerSecretInvalid)
	}
}

func TestMemoryStorage_ValidateBunkerSecretWrongKey(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	secret := &BunkerSecret{
		ID:        "secret1",
		KeyPubkey: "keypub123",
		Secret:    "mysecret",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.CreateBunkerSecret(ctx, secret)

	_, err := s.ValidateBunkerSecret(ctx, "wrongkey", "mysecret")
	if err != ErrBunkerSecretInvalid {
		t.Errorf("ValidateBunkerSecret() wrong key error = %v, want %v", err, ErrBunkerSecretInvalid)
	}
}

func TestMemoryStorage_ValidateBunkerSecretExpired(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	secret := &BunkerSecret{
		ID:        "secret1",
		KeyPubkey: "keypub123",
		Secret:    "mysecret",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	s.CreateBunkerSecret(ctx, secret)

	_, err := s.ValidateBunkerSecret(ctx, "keypub123", "mysecret")
	if err != ErrBunkerSecretInvalid {
		t.Errorf("ValidateBunkerSecret() expired error = %v, want %v", err, ErrBunkerSecretInvalid)
	}
}

func TestMemoryStorage_CleanExpiredBunkerSecrets(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	s.CreateBunkerSecret(ctx, &BunkerSecret{
		ID:        "active",
		Secret:    "active",
		KeyPubkey: "key1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	s.CreateBunkerSecret(ctx, &BunkerSecret{
		ID:        "expired",
		Secret:    "expired",
		KeyPubkey: "key1",
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	err := s.CleanExpiredBunkerSecrets(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredBunkerSecrets() error = %v", err)
	}

	s.mu.RLock()
	_, activeExists := s.bunkerSecrets["active"]
	_, expiredExists := s.bunkerSecrets["expired"]
	s.mu.RUnlock()

	if !activeExists {
		t.Error("active secret should still exist")
	}
	if expiredExists {
		t.Error("expired secret should be cleaned up")
	}
}

// User.IsAdmin Test

func TestUser_IsAdmin(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{"admin", true},
		{"user", false},
		{"", false},
	}

	for _, tt := range tests {
		user := &User{Role: tt.role}
		got := user.IsAdmin()
		if got != tt.want {
			t.Errorf("User{Role: %q}.IsAdmin() = %v, want %v", tt.role, got, tt.want)
		}
	}
}

func TestMemoryStorage_Close(t *testing.T) {
	s := NewMemoryStorage()
	err := s.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}
