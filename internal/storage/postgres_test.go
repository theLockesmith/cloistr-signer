package storage

import (
	"context"
	"os"
	"testing"
	"time"
)

// getTestPostgresStorage creates a PostgresStorage for testing.
// Returns nil if TEST_DATABASE_URL is not set.
func getTestPostgresStorage(t *testing.T) *PostgresStorage {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping PostgreSQL tests")
	}

	ps, err := NewPostgresStorage(dsn)
	if err != nil {
		t.Fatalf("Failed to create PostgresStorage: %v", err)
	}

	// Clean up tables for a fresh test
	cleanupTestDatabase(t, ps)

	return ps
}

// cleanupTestDatabase removes all test data from the database
func cleanupTestDatabase(t *testing.T, ps *PostgresStorage) {
	tables := []string{
		"bunker_secrets",
		"user_sessions",
		"policy_rules",
		"tokens",
		"pending_requests",
		"permissions",
		"sessions",
		"policies",
		"users",
		"keys",
	}

	for _, table := range tables {
		_, err := ps.db.Exec("DELETE FROM " + table)
		if err != nil {
			t.Logf("Warning: failed to clean table %s: %v", table, err)
		}
	}
}

// Key Tests

func TestPostgresStorage_CreateKey(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{
		ID:            "key1",
		Name:          "Test Key",
		Pubkey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EncryptedNsec: "encrypted_nsec_data",
		CreatedAt:     time.Now(),
		CreatedBy:     "admin",
	}

	err := ps.CreateKey(ctx, key)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// Try to create duplicate by ID
	err = ps.CreateKey(ctx, key)
	if err != ErrKeyExists {
		t.Errorf("CreateKey() duplicate error = %v, want %v", err, ErrKeyExists)
	}

	// Try to create duplicate by pubkey
	key2 := &Key{
		ID:            "key2",
		Pubkey:        key.Pubkey,
		EncryptedNsec: "test",
		CreatedAt:     time.Now(),
	}
	err = ps.CreateKey(ctx, key2)
	if err != ErrKeyExists {
		t.Errorf("CreateKey() duplicate pubkey error = %v, want %v", err, ErrKeyExists)
	}
}

func TestPostgresStorage_GetKey(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{
		ID:            "key1",
		Name:          "Test Key",
		Pubkey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EncryptedNsec: "encrypted_nsec",
		CreatedAt:     time.Now(),
	}
	ps.CreateKey(ctx, key)

	got, err := ps.GetKey(ctx, "key1")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetKey().ID = %q, want %q", got.ID, key.ID)
	}
	if got.Name != key.Name {
		t.Errorf("GetKey().Name = %q, want %q", got.Name, key.Name)
	}

	_, err = ps.GetKey(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKey() nonexistent error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestPostgresStorage_GetKeyByPubkey(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{
		ID:            "key1",
		Pubkey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EncryptedNsec: "encrypted",
		CreatedAt:     time.Now(),
	}
	ps.CreateKey(ctx, key)

	got, err := ps.GetKeyByPubkey(ctx, key.Pubkey)
	if err != nil {
		t.Fatalf("GetKeyByPubkey() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetKeyByPubkey().ID = %q, want %q", got.ID, key.ID)
	}

	_, err = ps.GetKeyByPubkey(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKeyByPubkey() nonexistent error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestPostgresStorage_GetKeyByName(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{
		ID:            "key1",
		Name:          "TestKey",
		Pubkey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EncryptedNsec: "encrypted",
		CreatedAt:     time.Now(),
	}
	ps.CreateKey(ctx, key)

	got, err := ps.GetKeyByName(ctx, "TestKey")
	if err != nil {
		t.Fatalf("GetKeyByName() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetKeyByName().ID = %q, want %q", got.ID, key.ID)
	}

	_, err = ps.GetKeyByName(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKeyByName() nonexistent error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestPostgresStorage_ListKeys(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	keys, err := ps.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListKeys() empty storage = %d keys, want 0", len(keys))
	}

	ps.CreateKey(ctx, &Key{ID: "key1", Pubkey: "pub1", EncryptedNsec: "enc1", CreatedAt: time.Now()})
	ps.CreateKey(ctx, &Key{ID: "key2", Pubkey: "pub2", EncryptedNsec: "enc2", CreatedAt: time.Now()})

	keys, err = ps.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys() = %d keys, want 2", len(keys))
	}
}

func TestPostgresStorage_DeleteKey(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{
		ID:            "key1",
		Name:          "TestKey",
		Pubkey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EncryptedNsec: "encrypted",
		CreatedAt:     time.Now(),
	}
	ps.CreateKey(ctx, key)

	err := ps.DeleteKey(ctx, "key1")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	_, err = ps.GetKey(ctx, "key1")
	if err != ErrKeyNotFound {
		t.Errorf("GetKey() after delete error = %v, want %v", err, ErrKeyNotFound)
	}

	err = ps.DeleteKey(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("DeleteKey() nonexistent error = %v, want %v", err, ErrKeyNotFound)
	}
}

// Permission Tests

func TestPostgresStorage_SetPermission(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{
		ID:            "key1",
		Pubkey:        "keypub123",
		EncryptedNsec: "encrypted",
		CreatedAt:     time.Now(),
	}
	ps.CreateKey(ctx, key)

	perm := &Permission{
		KeyID:      "key1",
		UserPubkey: "userpub456",
		Methods:    []string{"sign_event", "ping"},
	}

	err := ps.SetPermission(ctx, perm)
	if err != nil {
		t.Fatalf("SetPermission() error = %v", err)
	}

	// Update existing permission (upsert)
	perm.Methods = []string{"sign_event", "ping", "encrypt"}
	err = ps.SetPermission(ctx, perm)
	if err != nil {
		t.Fatalf("SetPermission() update error = %v", err)
	}

	got, err := ps.GetPermission(ctx, "key1", "userpub456")
	if err != nil {
		t.Fatalf("GetPermission() error = %v", err)
	}
	if len(got.Methods) != 3 {
		t.Errorf("SetPermission() update failed, got %d methods, want 3", len(got.Methods))
	}
}

func TestPostgresStorage_GetPermission(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{ID: "key1", Pubkey: "keypub123", EncryptedNsec: "enc", CreatedAt: time.Now()}
	ps.CreateKey(ctx, key)

	perm := &Permission{
		KeyID:        "key1",
		UserPubkey:   "userpub456",
		Methods:      []string{"sign_event"},
		AllowedKinds: []int{1, 4},
	}
	ps.SetPermission(ctx, perm)

	got, err := ps.GetPermission(ctx, "key1", "userpub456")
	if err != nil {
		t.Fatalf("GetPermission() error = %v", err)
	}
	if len(got.Methods) != 1 || got.Methods[0] != "sign_event" {
		t.Errorf("GetPermission().Methods = %v, want [sign_event]", got.Methods)
	}
	if len(got.AllowedKinds) != 2 {
		t.Errorf("GetPermission().AllowedKinds = %v, want [1, 4]", got.AllowedKinds)
	}

	_, err = ps.GetPermission(ctx, "key1", "unknown")
	if err != ErrNotAuthorized {
		t.Errorf("GetPermission() unknown user error = %v, want %v", err, ErrNotAuthorized)
	}
}

func TestPostgresStorage_GetPermissionExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{ID: "key1", Pubkey: "keypub123", EncryptedNsec: "enc", CreatedAt: time.Now()}
	ps.CreateKey(ctx, key)

	expired := time.Now().Add(-time.Hour)
	perm := &Permission{
		KeyID:      "key1",
		UserPubkey: "userpub456",
		Methods:    []string{"sign_event"},
		ExpiresAt:  &expired,
	}
	ps.SetPermission(ctx, perm)

	_, err := ps.GetPermission(ctx, "key1", "userpub456")
	if err != ErrNotAuthorized {
		t.Errorf("GetPermission() expired error = %v, want %v", err, ErrNotAuthorized)
	}
}

func TestPostgresStorage_ListPermissions(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{ID: "key1", Pubkey: "keypub123", EncryptedNsec: "enc", CreatedAt: time.Now()}
	ps.CreateKey(ctx, key)

	ps.SetPermission(ctx, &Permission{KeyID: "key1", UserPubkey: "user1", Methods: []string{"ping"}})
	ps.SetPermission(ctx, &Permission{KeyID: "key1", UserPubkey: "user2", Methods: []string{"sign_event"}})

	perms, err := ps.ListPermissions(ctx, "key1")
	if err != nil {
		t.Fatalf("ListPermissions() error = %v", err)
	}
	if len(perms) != 2 {
		t.Errorf("ListPermissions() = %d, want 2", len(perms))
	}
}

func TestPostgresStorage_DeletePermission(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	key := &Key{ID: "key1", Pubkey: "keypub123", EncryptedNsec: "enc", CreatedAt: time.Now()}
	ps.CreateKey(ctx, key)

	perm := &Permission{KeyID: "key1", UserPubkey: "userpub456", Methods: []string{"ping"}}
	ps.SetPermission(ctx, perm)

	err := ps.DeletePermission(ctx, "key1", "userpub456")
	if err != nil {
		t.Fatalf("DeletePermission() error = %v", err)
	}

	_, err = ps.GetPermission(ctx, "key1", "userpub456")
	if err != ErrNotAuthorized {
		t.Errorf("GetPermission() after delete error = %v, want %v", err, ErrNotAuthorized)
	}
}

// Session Tests

func TestPostgresStorage_SessionLifecycle(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	session := &Session{
		ID:           "sess1",
		KeyID:        "key1",
		ClientPubkey: "client1",
		Permissions:  []string{"ping"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	err := ps.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	got, err := ps.GetSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("GetSession().ID = %q, want %q", got.ID, session.ID)
	}
	if len(got.Permissions) != 1 || got.Permissions[0] != "ping" {
		t.Errorf("GetSession().Permissions = %v, want [ping]", got.Permissions)
	}

	err = ps.DeleteSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}

	_, err = ps.GetSession(ctx, "sess1")
	if err != ErrSessionNotFound {
		t.Errorf("GetSession() after delete error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestPostgresStorage_GetSessionExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	session := &Session{
		ID:           "sess1",
		KeyID:        "key1",
		ClientPubkey: "client1",
		Permissions:  []string{"ping"},
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	ps.CreateSession(ctx, session)

	_, err := ps.GetSession(ctx, "sess1")
	if err != ErrSessionNotFound {
		t.Errorf("GetSession() expired error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestPostgresStorage_GetSessionByClient(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	session := &Session{
		ID:           "sess1",
		KeyID:        "key1",
		ClientPubkey: "client1",
		Permissions:  []string{"ping"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	ps.CreateSession(ctx, session)

	got, err := ps.GetSessionByClient(ctx, "key1", "client1")
	if err != nil {
		t.Fatalf("GetSessionByClient() error = %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("GetSessionByClient().ID = %q, want %q", got.ID, session.ID)
	}

	_, err = ps.GetSessionByClient(ctx, "key1", "unknown")
	if err != ErrSessionNotFound {
		t.Errorf("GetSessionByClient() unknown error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestPostgresStorage_SessionUpsert(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	session1 := &Session{
		ID:           "sess1",
		KeyID:        "key1",
		ClientPubkey: "client1",
		Permissions:  []string{"ping"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	ps.CreateSession(ctx, session1)

	// Create another session with same key_id and client_pubkey (should upsert)
	session2 := &Session{
		ID:           "sess2",
		KeyID:        "key1",
		ClientPubkey: "client1",
		Permissions:  []string{"ping", "sign_event"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(2 * time.Hour),
	}
	err := ps.CreateSession(ctx, session2)
	if err != nil {
		t.Fatalf("CreateSession() upsert error = %v", err)
	}

	got, err := ps.GetSessionByClient(ctx, "key1", "client1")
	if err != nil {
		t.Fatalf("GetSessionByClient() error = %v", err)
	}
	if got.ID != "sess2" {
		t.Errorf("GetSessionByClient().ID = %q, want %q", got.ID, "sess2")
	}
	if len(got.Permissions) != 2 {
		t.Errorf("GetSessionByClient().Permissions = %v, want 2 permissions", got.Permissions)
	}
}

func TestPostgresStorage_CleanExpiredSessions(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	ps.CreateSession(ctx, &Session{
		ID:           "active",
		KeyID:        "key1",
		ClientPubkey: "client1",
		Permissions:  []string{"ping"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	ps.CreateSession(ctx, &Session{
		ID:           "expired",
		KeyID:        "key2",
		ClientPubkey: "client2",
		Permissions:  []string{"ping"},
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:    time.Now().Add(-time.Hour),
	})

	err := ps.CleanExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredSessions() error = %v", err)
	}

	_, err = ps.GetSession(ctx, "active")
	if err != nil {
		t.Errorf("active session should still exist, got error: %v", err)
	}

	// Try to fetch expired session directly from DB (bypassing expiry check)
	var count int
	ps.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'expired'").Scan(&count)
	if count != 0 {
		t.Error("expired session should be cleaned up from database")
	}
}

// Policy Tests

func TestPostgresStorage_PolicyLifecycle(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	policy := &Policy{
		ID:          "policy1",
		Name:        "Test Policy",
		Description: "A test policy",
		Rules: []*PolicyRule{
			{ID: "rule1", PolicyID: "policy1", Method: "sign_event", MaxUsage: 100, AllowedKinds: []int{1, 4}},
			{ID: "rule2", PolicyID: "policy1", Method: "ping", MaxUsage: 0},
		},
		CreatedAt: time.Now(),
		CreatedBy: "admin",
	}

	err := ps.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	got, err := ps.GetPolicy(ctx, "policy1")
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if got.Name != policy.Name {
		t.Errorf("GetPolicy().Name = %q, want %q", got.Name, policy.Name)
	}
	if got.Description != policy.Description {
		t.Errorf("GetPolicy().Description = %q, want %q", got.Description, policy.Description)
	}
	if len(got.Rules) != 2 {
		t.Errorf("GetPolicy().Rules = %d, want 2", len(got.Rules))
	}

	policies, err := ps.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("ListPolicies() = %d, want 1", len(policies))
	}

	err = ps.DeletePolicy(ctx, "policy1")
	if err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}

	_, err = ps.GetPolicy(ctx, "policy1")
	if err != ErrPolicyNotFound {
		t.Errorf("GetPolicy() after delete error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPostgresStorage_GetPolicyExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	expired := time.Now().Add(-time.Hour)
	policy := &Policy{
		ID:        "policy1",
		Name:      "Expired Policy",
		ExpiresAt: &expired,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	ps.CreatePolicy(ctx, policy)

	_, err := ps.GetPolicy(ctx, "policy1")
	if err != ErrPolicyNotFound {
		t.Errorf("GetPolicy() expired error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPostgresStorage_ListPoliciesExcludesExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	expired := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	ps.CreatePolicy(ctx, &Policy{ID: "active", Name: "Active", CreatedAt: time.Now()})
	ps.CreatePolicy(ctx, &Policy{ID: "future", Name: "Future", ExpiresAt: &future, CreatedAt: time.Now()})
	ps.CreatePolicy(ctx, &Policy{ID: "expired", Name: "Expired", ExpiresAt: &expired, CreatedAt: time.Now()})

	policies, err := ps.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("ListPolicies() = %d, want 2 (excluding expired)", len(policies))
	}
}

func TestPostgresStorage_IncrementRuleUsage(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	policy := &Policy{
		ID:   "policy1",
		Name: "Test",
		Rules: []*PolicyRule{
			{ID: "rule1", PolicyID: "policy1", Method: "sign_event", MaxUsage: 10, CurrentUsage: 0},
		},
		CreatedAt: time.Now(),
	}
	ps.CreatePolicy(ctx, policy)

	err := ps.IncrementRuleUsage(ctx, "rule1")
	if err != nil {
		t.Fatalf("IncrementRuleUsage() error = %v", err)
	}

	// Verify by getting policy
	got, _ := ps.GetPolicy(ctx, "policy1")
	if got.Rules[0].CurrentUsage != 1 {
		t.Errorf("CurrentUsage = %d, want 1", got.Rules[0].CurrentUsage)
	}

	// Increment again
	ps.IncrementRuleUsage(ctx, "rule1")
	got, _ = ps.GetPolicy(ctx, "policy1")
	if got.Rules[0].CurrentUsage != 2 {
		t.Errorf("CurrentUsage = %d, want 2", got.Rules[0].CurrentUsage)
	}

	err = ps.IncrementRuleUsage(ctx, "nonexistent")
	if err != ErrPolicyNotFound {
		t.Errorf("IncrementRuleUsage() nonexistent error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestPostgresStorage_DeletePolicyNotFound(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	err := ps.DeletePolicy(ctx, "nonexistent")
	if err != ErrPolicyNotFound {
		t.Errorf("DeletePolicy() nonexistent error = %v, want %v", err, ErrPolicyNotFound)
	}
}

// Token Tests

func TestPostgresStorage_TokenLifecycle(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	token := &Token{
		ID:         "token1",
		PolicyID:   "policy1",
		KeyID:      "key1",
		ClientName: "Test Client",
		CreatedBy:  "admin",
		CreatedAt:  time.Now(),
	}

	err := ps.CreateToken(ctx, token)
	if err != nil {
		t.Fatalf("CreateToken() error = %v", err)
	}

	got, err := ps.GetToken(ctx, "token1")
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if got.ID != token.ID {
		t.Errorf("GetToken().ID = %q, want %q", got.ID, token.ID)
	}
	if got.ClientName != token.ClientName {
		t.Errorf("GetToken().ClientName = %q, want %q", got.ClientName, token.ClientName)
	}

	tokens, err := ps.ListTokens(ctx, "key1")
	if err != nil {
		t.Fatalf("ListTokens() error = %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("ListTokens() = %d, want 1", len(tokens))
	}

	err = ps.DeleteToken(ctx, "token1")
	if err != nil {
		t.Fatalf("DeleteToken() error = %v", err)
	}

	_, err = ps.GetToken(ctx, "token1")
	if err != ErrTokenNotFound {
		t.Errorf("GetToken() after delete error = %v, want %v", err, ErrTokenNotFound)
	}
}

func TestPostgresStorage_RedeemToken(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	token := &Token{
		ID:        "token1",
		PolicyID:  "policy1",
		KeyID:     "key1",
		CreatedAt: time.Now(),
	}
	ps.CreateToken(ctx, token)

	redeemed, err := ps.RedeemToken(ctx, "token1", "redeemer123")
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
	_, err = ps.RedeemToken(ctx, "token1", "another")
	if err != ErrTokenRedeemed {
		t.Errorf("RedeemToken() already redeemed error = %v, want %v", err, ErrTokenRedeemed)
	}
}

func TestPostgresStorage_RedeemTokenExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	expired := time.Now().Add(-time.Hour)
	token := &Token{
		ID:        "token1",
		PolicyID:  "policy1",
		KeyID:     "key1",
		ExpiresAt: &expired,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	ps.CreateToken(ctx, token)

	_, err := ps.RedeemToken(ctx, "token1", "redeemer")
	if err != ErrTokenExpired {
		t.Errorf("RedeemToken() expired error = %v, want %v", err, ErrTokenExpired)
	}
}

func TestPostgresStorage_RedeemTokenNotFound(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	_, err := ps.RedeemToken(ctx, "nonexistent", "redeemer")
	if err != ErrTokenNotFound {
		t.Errorf("RedeemToken() not found error = %v, want %v", err, ErrTokenNotFound)
	}
}

func TestPostgresStorage_DeleteTokenNotFound(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	err := ps.DeleteToken(ctx, "nonexistent")
	if err != ErrTokenNotFound {
		t.Errorf("DeleteToken() not found error = %v, want %v", err, ErrTokenNotFound)
	}
}

// Pending Request Tests

func TestPostgresStorage_PendingRequestLifecycle(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	kind := 1
	req := &PendingRequest{
		ID:           "req1",
		KeyPubkey:    "key1",
		ClientPubkey: "client1",
		Method:       "sign_event",
		Params:       map[string]interface{}{"foo": "bar"},
		EventKind:    &kind,
		ExpiresAt:    time.Now().Add(time.Minute),
		CreatedAt:    time.Now(),
	}

	err := ps.CreatePendingRequest(ctx, req)
	if err != nil {
		t.Fatalf("CreatePendingRequest() error = %v", err)
	}

	got, err := ps.GetPendingRequest(ctx, "req1")
	if err != nil {
		t.Fatalf("GetPendingRequest() error = %v", err)
	}
	if got.Method != req.Method {
		t.Errorf("GetPendingRequest().Method = %q, want %q", got.Method, req.Method)
	}
	if got.EventKind == nil || *got.EventKind != 1 {
		t.Errorf("GetPendingRequest().EventKind = %v, want 1", got.EventKind)
	}
	if got.Params["foo"] != "bar" {
		t.Errorf("GetPendingRequest().Params = %v, want foo=bar", got.Params)
	}

	reqs, err := ps.ListPendingRequests(ctx, "key1")
	if err != nil {
		t.Fatalf("ListPendingRequests() error = %v", err)
	}
	if len(reqs) != 1 {
		t.Errorf("ListPendingRequests() = %d, want 1", len(reqs))
	}

	err = ps.DeletePendingRequest(ctx, "req1")
	if err != nil {
		t.Fatalf("DeletePendingRequest() error = %v", err)
	}

	_, err = ps.GetPendingRequest(ctx, "req1")
	if err != ErrRequestNotFound {
		t.Errorf("GetPendingRequest() after delete error = %v, want %v", err, ErrRequestNotFound)
	}
}

func TestPostgresStorage_GetPendingRequestExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	req := &PendingRequest{
		ID:           "req1",
		KeyPubkey:    "key1",
		ClientPubkey: "client1",
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(-time.Hour),
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	}
	ps.CreatePendingRequest(ctx, req)

	_, err := ps.GetPendingRequest(ctx, "req1")
	if err != ErrRequestNotFound {
		t.Errorf("GetPendingRequest() expired error = %v, want %v", err, ErrRequestNotFound)
	}
}

func TestPostgresStorage_ListPendingRequestsExcludesExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	ps.CreatePendingRequest(ctx, &PendingRequest{
		ID:           "active",
		KeyPubkey:    "key1",
		ClientPubkey: "client1",
		Method:       "ping",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	})
	ps.CreatePendingRequest(ctx, &PendingRequest{
		ID:           "expired",
		KeyPubkey:    "key1",
		ClientPubkey: "client2",
		Method:       "ping",
		ExpiresAt:    time.Now().Add(-time.Hour),
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	})

	reqs, err := ps.ListPendingRequests(ctx, "key1")
	if err != nil {
		t.Fatalf("ListPendingRequests() error = %v", err)
	}
	if len(reqs) != 1 {
		t.Errorf("ListPendingRequests() = %d, want 1 (excluding expired)", len(reqs))
	}
}

func TestPostgresStorage_CleanExpiredRequests(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	ps.CreatePendingRequest(ctx, &PendingRequest{
		ID:           "active",
		KeyPubkey:    "key1",
		ClientPubkey: "client1",
		Method:       "ping",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	})
	ps.CreatePendingRequest(ctx, &PendingRequest{
		ID:           "expired",
		KeyPubkey:    "key1",
		ClientPubkey: "client2",
		Method:       "ping",
		ExpiresAt:    time.Now().Add(-time.Hour),
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	})

	err := ps.CleanExpiredRequests(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredRequests() error = %v", err)
	}

	var count int
	ps.db.QueryRow("SELECT COUNT(*) FROM pending_requests").Scan(&count)
	if count != 1 {
		t.Errorf("CleanExpiredRequests() left %d requests, want 1", count)
	}
}

// User Tests

func TestPostgresStorage_UserLifecycle(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	user := &User{
		ID:           "user1",
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash123",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := ps.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	// Duplicate ID
	err = ps.CreateUser(ctx, user)
	if err != ErrUserExists {
		t.Errorf("CreateUser() duplicate error = %v, want %v", err, ErrUserExists)
	}

	// Duplicate username
	user2 := &User{ID: "user2", Username: "testuser", PasswordHash: "hash", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	err = ps.CreateUser(ctx, user2)
	if err != ErrUserExists {
		t.Errorf("CreateUser() duplicate username error = %v, want %v", err, ErrUserExists)
	}

	got, err := ps.GetUser(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if got.Username != user.Username {
		t.Errorf("GetUser().Username = %q, want %q", got.Username, user.Username)
	}
	if got.Role != "user" {
		t.Errorf("GetUser().Role = %q, want %q", got.Role, "user")
	}

	got, err = ps.GetUserByUsername(ctx, "testuser")
	if err != nil {
		t.Fatalf("GetUserByUsername() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByUsername().ID = %q, want %q", got.ID, user.ID)
	}

	got, err = ps.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByEmail().ID = %q, want %q", got.ID, user.ID)
	}

	users, err := ps.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 1 {
		t.Errorf("ListUsers() = %d, want 1", len(users))
	}

	err = ps.DeleteUser(ctx, "user1")
	if err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	_, err = ps.GetUser(ctx, "user1")
	if err != ErrUserNotFound {
		t.Errorf("GetUser() after delete error = %v, want %v", err, ErrUserNotFound)
	}
}

func TestPostgresStorage_GetUserByPubkey(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	user := &User{
		ID:           "user1",
		Username:     "testuser",
		Pubkey:       "pubkey123",
		PasswordHash: "hash",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	ps.CreateUser(ctx, user)

	got, err := ps.GetUserByPubkey(ctx, "pubkey123")
	if err != nil {
		t.Fatalf("GetUserByPubkey() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByPubkey().ID = %q, want %q", got.ID, user.ID)
	}

	_, err = ps.GetUserByPubkey(ctx, "unknown")
	if err != ErrUserNotFound {
		t.Errorf("GetUserByPubkey() unknown error = %v, want %v", err, ErrUserNotFound)
	}
}

func TestPostgresStorage_CreateUserDefaultRole(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	user := &User{
		ID:           "user1",
		Username:     "testuser",
		PasswordHash: "hash",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	ps.CreateUser(ctx, user)

	got, _ := ps.GetUser(ctx, "user1")
	if got.Role != "user" {
		t.Errorf("CreateUser() default role = %q, want %q", got.Role, "user")
	}
}

func TestPostgresStorage_UpdateUser(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	user := &User{
		ID:           "user1",
		Username:     "oldname",
		Email:        "old@example.com",
		PasswordHash: "hash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	ps.CreateUser(ctx, user)

	user.Username = "newname"
	user.Email = "new@example.com"
	user.Role = "admin"

	err := ps.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	got, err := ps.GetUser(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUser() after update error = %v", err)
	}
	if got.Username != "newname" {
		t.Errorf("UpdateUser() username = %q, want %q", got.Username, "newname")
	}
	if got.Email != "new@example.com" {
		t.Errorf("UpdateUser() email = %q, want %q", got.Email, "new@example.com")
	}
	if got.Role != "admin" {
		t.Errorf("UpdateUser() role = %q, want %q", got.Role, "admin")
	}
}

func TestPostgresStorage_UpdateUserNotFound(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	user := &User{ID: "nonexistent", Username: "test", PasswordHash: "hash"}
	err := ps.UpdateUser(ctx, user)
	if err != ErrUserNotFound {
		t.Errorf("UpdateUser() not found error = %v, want %v", err, ErrUserNotFound)
	}
}

func TestPostgresStorage_UserLockout(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	user := &User{
		ID:           "user1",
		Username:     "testuser",
		PasswordHash: "hash",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	ps.CreateUser(ctx, user)

	err := ps.IncrementFailedLogins(ctx, "user1")
	if err != nil {
		t.Fatalf("IncrementFailedLogins() error = %v", err)
	}

	got, _ := ps.GetUser(ctx, "user1")
	if got.FailedLoginAttempts != 1 {
		t.Errorf("FailedLoginAttempts = %d, want 1", got.FailedLoginAttempts)
	}

	lockUntil := time.Now().Add(15 * time.Minute)
	err = ps.LockUser(ctx, "user1", lockUntil)
	if err != nil {
		t.Fatalf("LockUser() error = %v", err)
	}

	got, _ = ps.GetUser(ctx, "user1")
	if got.LockedUntil == nil {
		t.Error("LockedUntil should not be nil after LockUser()")
	}

	err = ps.UnlockUser(ctx, "user1")
	if err != nil {
		t.Fatalf("UnlockUser() error = %v", err)
	}

	got, _ = ps.GetUser(ctx, "user1")
	if got.LockedUntil != nil {
		t.Error("LockedUntil should be nil after UnlockUser()")
	}
	if got.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts after unlock = %d, want 0", got.FailedLoginAttempts)
	}
}

func TestPostgresStorage_ResetFailedLogins(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	user := &User{
		ID:           "user1",
		Username:     "testuser",
		PasswordHash: "hash",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	ps.CreateUser(ctx, user)

	ps.IncrementFailedLogins(ctx, "user1")
	ps.IncrementFailedLogins(ctx, "user1")
	ps.IncrementFailedLogins(ctx, "user1")

	got, _ := ps.GetUser(ctx, "user1")
	if got.FailedLoginAttempts != 3 {
		t.Errorf("FailedLoginAttempts = %d, want 3", got.FailedLoginAttempts)
	}

	err := ps.ResetFailedLogins(ctx, "user1")
	if err != nil {
		t.Fatalf("ResetFailedLogins() error = %v", err)
	}

	got, _ = ps.GetUser(ctx, "user1")
	if got.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts after reset = %d, want 0", got.FailedLoginAttempts)
	}
}

func TestPostgresStorage_UserLockoutNotFound(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	err := ps.IncrementFailedLogins(ctx, "nonexistent")
	if err != ErrUserNotFound {
		t.Errorf("IncrementFailedLogins() not found error = %v, want %v", err, ErrUserNotFound)
	}

	err = ps.ResetFailedLogins(ctx, "nonexistent")
	if err != ErrUserNotFound {
		t.Errorf("ResetFailedLogins() not found error = %v, want %v", err, ErrUserNotFound)
	}

	err = ps.LockUser(ctx, "nonexistent", time.Now().Add(time.Hour))
	if err != ErrUserNotFound {
		t.Errorf("LockUser() not found error = %v, want %v", err, ErrUserNotFound)
	}

	err = ps.UnlockUser(ctx, "nonexistent")
	if err != ErrUserNotFound {
		t.Errorf("UnlockUser() not found error = %v, want %v", err, ErrUserNotFound)
	}
}

func TestPostgresStorage_DeleteUserNotFound(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	err := ps.DeleteUser(ctx, "nonexistent")
	if err != ErrUserNotFound {
		t.Errorf("DeleteUser() not found error = %v, want %v", err, ErrUserNotFound)
	}
}

func TestPostgresStorage_UserWithMFA(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	user := &User{
		ID:              "user1",
		Username:        "testuser",
		PasswordHash:    "hash",
		MFASecret:       "JBSWY3DPEHPK3PXP",
		MFAEnabled:      true,
		BackupCodes:     []string{"code1", "code2", "code3"},
		BackupCodesUsed: 1,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	ps.CreateUser(ctx, user)

	got, err := ps.GetUser(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if !got.MFAEnabled {
		t.Error("MFAEnabled should be true")
	}
	if got.MFASecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("MFASecret = %q, want %q", got.MFASecret, "JBSWY3DPEHPK3PXP")
	}
	if len(got.BackupCodes) != 3 {
		t.Errorf("BackupCodes = %d, want 3", len(got.BackupCodes))
	}
	if got.BackupCodesUsed != 1 {
		t.Errorf("BackupCodesUsed = %d, want 1", got.BackupCodesUsed)
	}
}

// User Session Tests

func TestPostgresStorage_UserSessionLifecycle(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	// Create user first (foreign key constraint)
	ps.CreateUser(ctx, &User{
		ID:           "user1",
		Username:     "testuser",
		PasswordHash: "hash",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	session := &UserSession{
		ID:        "sess1",
		UserID:    "user1",
		Token:     "token123",
		UserAgent: "Mozilla/5.0",
		IPAddress: "192.168.1.1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}

	err := ps.CreateUserSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateUserSession() error = %v", err)
	}

	got, err := ps.GetUserSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("GetUserSession() error = %v", err)
	}
	if got.UserID != session.UserID {
		t.Errorf("GetUserSession().UserID = %q, want %q", got.UserID, session.UserID)
	}
	if got.UserAgent != "Mozilla/5.0" {
		t.Errorf("GetUserSession().UserAgent = %q, want %q", got.UserAgent, "Mozilla/5.0")
	}

	sessions, err := ps.ListUserSessions(ctx, "user1")
	if err != nil {
		t.Fatalf("ListUserSessions() error = %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("ListUserSessions() = %d, want 1", len(sessions))
	}

	err = ps.DeleteUserSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("DeleteUserSession() error = %v", err)
	}

	_, err = ps.GetUserSession(ctx, "sess1")
	if err != ErrSessionNotFound {
		t.Errorf("GetUserSession() after delete error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestPostgresStorage_GetUserSessionExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	ps.CreateUser(ctx, &User{
		ID:           "user1",
		Username:     "testuser",
		PasswordHash: "hash",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	session := &UserSession{
		ID:        "sess1",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	ps.CreateUserSession(ctx, session)

	_, err := ps.GetUserSession(ctx, "sess1")
	if err != ErrSessionNotFound {
		t.Errorf("GetUserSession() expired error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestPostgresStorage_DeleteUserSessions(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	ps.CreateUser(ctx, &User{ID: "user1", Username: "user1", PasswordHash: "hash", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	ps.CreateUser(ctx, &User{ID: "user2", Username: "user2", PasswordHash: "hash", CreatedAt: time.Now(), UpdatedAt: time.Now()})

	ps.CreateUserSession(ctx, &UserSession{ID: "sess1", UserID: "user1", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()})
	ps.CreateUserSession(ctx, &UserSession{ID: "sess2", UserID: "user1", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()})
	ps.CreateUserSession(ctx, &UserSession{ID: "sess3", UserID: "user2", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()})

	err := ps.DeleteUserSessions(ctx, "user1")
	if err != nil {
		t.Fatalf("DeleteUserSessions() error = %v", err)
	}

	sessions, _ := ps.ListUserSessions(ctx, "user1")
	if len(sessions) != 0 {
		t.Errorf("ListUserSessions() after delete = %d, want 0", len(sessions))
	}

	sessions, _ = ps.ListUserSessions(ctx, "user2")
	if len(sessions) != 1 {
		t.Errorf("user2 sessions = %d, want 1", len(sessions))
	}
}

func TestPostgresStorage_CleanExpiredUserSessions(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	ps.CreateUser(ctx, &User{ID: "user1", Username: "testuser", PasswordHash: "hash", CreatedAt: time.Now(), UpdatedAt: time.Now()})

	ps.CreateUserSession(ctx, &UserSession{
		ID:        "active",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})
	ps.CreateUserSession(ctx, &UserSession{
		ID:        "expired",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})

	err := ps.CleanExpiredUserSessions(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredUserSessions() error = %v", err)
	}

	var count int
	ps.db.QueryRow("SELECT COUNT(*) FROM user_sessions").Scan(&count)
	if count != 1 {
		t.Errorf("CleanExpiredUserSessions() left %d sessions, want 1", count)
	}
}

// Bunker Secret Tests

func TestPostgresStorage_BunkerSecretLifecycle(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	secret := &BunkerSecret{
		ID:        "secret1",
		KeyPubkey: "keypub123",
		Secret:    "mysecret",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	err := ps.CreateBunkerSecret(ctx, secret)
	if err != nil {
		t.Fatalf("CreateBunkerSecret() error = %v", err)
	}

	got, err := ps.ValidateBunkerSecret(ctx, "keypub123", "mysecret")
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
	_, err = ps.ValidateBunkerSecret(ctx, "keypub123", "mysecret")
	if err != ErrBunkerSecretInvalid {
		t.Errorf("ValidateBunkerSecret() already used error = %v, want %v", err, ErrBunkerSecretInvalid)
	}
}

func TestPostgresStorage_ValidateBunkerSecretWrongKey(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	secret := &BunkerSecret{
		ID:        "secret1",
		KeyPubkey: "keypub123",
		Secret:    "mysecret",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	ps.CreateBunkerSecret(ctx, secret)

	_, err := ps.ValidateBunkerSecret(ctx, "wrongkey", "mysecret")
	if err != ErrBunkerSecretInvalid {
		t.Errorf("ValidateBunkerSecret() wrong key error = %v, want %v", err, ErrBunkerSecretInvalid)
	}
}

func TestPostgresStorage_ValidateBunkerSecretExpired(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	secret := &BunkerSecret{
		ID:        "secret1",
		KeyPubkey: "keypub123",
		Secret:    "mysecret",
		ExpiresAt: time.Now().Add(-time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	ps.CreateBunkerSecret(ctx, secret)

	_, err := ps.ValidateBunkerSecret(ctx, "keypub123", "mysecret")
	if err != ErrBunkerSecretInvalid {
		t.Errorf("ValidateBunkerSecret() expired error = %v, want %v", err, ErrBunkerSecretInvalid)
	}
}

func TestPostgresStorage_ValidateBunkerSecretNotFound(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	_, err := ps.ValidateBunkerSecret(ctx, "keypub123", "nonexistent")
	if err != ErrBunkerSecretInvalid {
		t.Errorf("ValidateBunkerSecret() not found error = %v, want %v", err, ErrBunkerSecretInvalid)
	}
}

func TestPostgresStorage_DeleteBunkerSecret(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	secret := &BunkerSecret{
		ID:        "secret1",
		KeyPubkey: "keypub123",
		Secret:    "mysecret",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	ps.CreateBunkerSecret(ctx, secret)

	err := ps.DeleteBunkerSecret(ctx, "secret1")
	if err != nil {
		t.Fatalf("DeleteBunkerSecret() error = %v", err)
	}

	_, err = ps.ValidateBunkerSecret(ctx, "keypub123", "mysecret")
	if err != ErrBunkerSecretInvalid {
		t.Errorf("ValidateBunkerSecret() after delete error = %v, want %v", err, ErrBunkerSecretInvalid)
	}
}

func TestPostgresStorage_CleanExpiredBunkerSecrets(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()

	ps.CreateBunkerSecret(ctx, &BunkerSecret{
		ID:        "active",
		Secret:    "active",
		KeyPubkey: "key1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})
	ps.CreateBunkerSecret(ctx, &BunkerSecret{
		ID:        "expired",
		Secret:    "expired",
		KeyPubkey: "key1",
		ExpiresAt: time.Now().Add(-time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})

	err := ps.CleanExpiredBunkerSecrets(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredBunkerSecrets() error = %v", err)
	}

	var count int
	ps.db.QueryRow("SELECT COUNT(*) FROM bunker_secrets").Scan(&count)
	if count != 1 {
		t.Errorf("CleanExpiredBunkerSecrets() left %d secrets, want 1", count)
	}
}

// Close Test

func TestPostgresStorage_Close(t *testing.T) {
	ps := getTestPostgresStorage(t)

	err := ps.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify connection is closed by trying to query
	_, err = ps.db.Query("SELECT 1")
	if err == nil {
		t.Error("Close() should close the database connection")
	}
}

// Helper function tests

func TestIsDuplicateError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{ErrKeyNotFound, false},
	}

	for _, tt := range tests {
		got := isDuplicateError(tt.err)
		if got != tt.want {
			t.Errorf("isDuplicateError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestNullString(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"", false},
		{"test", true},
	}

	for _, tt := range tests {
		got := nullString(tt.input)
		if got.Valid != tt.valid {
			t.Errorf("nullString(%q).Valid = %v, want %v", tt.input, got.Valid, tt.valid)
		}
		if tt.valid && got.String != tt.input {
			t.Errorf("nullString(%q).String = %q, want %q", tt.input, got.String, tt.input)
		}
	}
}
