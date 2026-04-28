package storage

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestNewSQLiteStorage(t *testing.T) {
	// Use temp file
	tmpFile := t.TempDir() + "/test.db"

	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	// Verify connection
	if s.db == nil {
		t.Error("NewSQLiteStorage().db is nil")
	}
}

func TestSQLiteStorage_KeyLifecycle(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	key := &Key{
		ID:               "key1",
		Name:             "Test Key",
		Pubkey:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		KeyType:          KeyTypeLocal,
		EncryptedNsec:    "enc:encrypted-data",
		EncryptionMethod: "local",
		RequireApproval:  true,
		CreatedAt:        time.Now(),
		OwnerID:          "owner1",
	}

	// Create
	err = s.CreateKey(ctx, key)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// Get by ID
	got, err := s.GetKey(ctx, "key1")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if got.Name != key.Name {
		t.Errorf("GetKey().Name = %q, want %q", got.Name, key.Name)
	}
	if got.EncryptionMethod != "local" {
		t.Errorf("GetKey().EncryptionMethod = %q, want %q", got.EncryptionMethod, "local")
	}
	if !got.RequireApproval {
		t.Error("GetKey().RequireApproval should be true")
	}

	// Get by pubkey
	got, err = s.GetKeyByPubkey(ctx, key.Pubkey)
	if err != nil {
		t.Fatalf("GetKeyByPubkey() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetKeyByPubkey().ID = %q, want %q", got.ID, key.ID)
	}

	// Get by name
	got, err = s.GetKeyByName(ctx, "Test Key")
	if err != nil {
		t.Fatalf("GetKeyByName() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetKeyByName().ID = %q, want %q", got.ID, key.ID)
	}

	// Update
	key.Name = "Updated Key"
	err = s.UpdateKey(ctx, key)
	if err != nil {
		t.Fatalf("UpdateKey() error = %v", err)
	}

	got, _ = s.GetKey(ctx, "key1")
	if got.Name != "Updated Key" {
		t.Errorf("GetKey().Name after update = %q, want %q", got.Name, "Updated Key")
	}

	// Delete
	err = s.DeleteKey(ctx, "key1")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	_, err = s.GetKey(ctx, "key1")
	if err != ErrKeyNotFound {
		t.Errorf("GetKey() after delete error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestSQLiteStorage_ListKeysOwnerIsolation(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	// Create keys for different owners
	s.CreateKey(ctx, &Key{ID: "key1", Pubkey: "pub1", OwnerID: "owner1"})
	s.CreateKey(ctx, &Key{ID: "key2", Pubkey: "pub2", OwnerID: "owner1"})
	s.CreateKey(ctx, &Key{ID: "key3", Pubkey: "pub3", OwnerID: "owner2"})

	// Owner 1 should only see their keys
	keys, err := s.ListKeys(ctx, "owner1")
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys(owner1) = %d keys, want 2", len(keys))
	}

	// Owner 2 should only see their keys
	keys, err = s.ListKeys(ctx, "owner2")
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("ListKeys(owner2) = %d keys, want 1", len(keys))
	}

	// ListAllKeys should return all
	allKeys, err := s.ListAllKeys(ctx)
	if err != nil {
		t.Fatalf("ListAllKeys() error = %v", err)
	}
	if len(allKeys) != 3 {
		t.Errorf("ListAllKeys() = %d keys, want 3", len(allKeys))
	}
}

func TestSQLiteStorage_PermissionLifecycle(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	// Create a key first (foreign key constraint)
	s.CreateKey(ctx, &Key{ID: "key1", Pubkey: "keypub123"})

	requireApproval := true
	perm := &Permission{
		KeyID:           "keypub123",
		UserPubkey:      "userpub456",
		Methods:         []string{"sign_event", "ping"},
		AllowedKinds:    []int{1, 4, 30023},
		RequireApproval: &requireApproval,
		AppName:         "TestApp",
		CreatedAt:       time.Now(),
	}

	err = s.SetPermission(ctx, perm)
	if err != nil {
		t.Fatalf("SetPermission() error = %v", err)
	}

	// Get permission
	got, err := s.GetPermission(ctx, "keypub123", "userpub456")
	if err != nil {
		t.Fatalf("GetPermission() error = %v", err)
	}
	if len(got.Methods) != 2 {
		t.Errorf("GetPermission().Methods = %v, want 2 methods", got.Methods)
	}
	if got.RequireApproval == nil || !*got.RequireApproval {
		t.Error("GetPermission().RequireApproval should be true")
	}

	// List permissions
	perms, err := s.ListPermissions(ctx, "keypub123")
	if err != nil {
		t.Fatalf("ListPermissions() error = %v", err)
	}
	if len(perms) != 1 {
		t.Errorf("ListPermissions() = %d, want 1", len(perms))
	}

	// Update last used
	err = s.UpdatePermissionLastUsed(ctx, "keypub123", "userpub456")
	if err != nil {
		t.Fatalf("UpdatePermissionLastUsed() error = %v", err)
	}

	// Delete
	err = s.DeletePermission(ctx, "keypub123", "userpub456")
	if err != nil {
		t.Fatalf("DeletePermission() error = %v", err)
	}

	_, err = s.GetPermission(ctx, "keypub123", "userpub456")
	if err != ErrNotAuthorized {
		t.Errorf("GetPermission() after delete error = %v, want %v", err, ErrNotAuthorized)
	}
}

func TestSQLiteStorage_UserLifecycle(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	user := &User{
		ID:           "user1",
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash123",
		MFAEnabled:   true,
		BackupCodes:  []string{"code1", "code2"},
		CreatedAt:    time.Now(),
	}

	// Create
	err = s.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	// Get by ID
	got, err := s.GetUser(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if got.Username != user.Username {
		t.Errorf("GetUser().Username = %q, want %q", got.Username, user.Username)
	}
	if !got.MFAEnabled {
		t.Error("GetUser().MFAEnabled should be true")
	}

	// Get by username
	got, err = s.GetUserByUsername(ctx, "testuser")
	if err != nil {
		t.Fatalf("GetUserByUsername() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByUsername().ID = %q, want %q", got.ID, user.ID)
	}

	// Get by email
	got, err = s.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByEmail().ID = %q, want %q", got.ID, user.ID)
	}

	// List users
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 1 {
		t.Errorf("ListUsers() = %d, want 1", len(users))
	}

	// Increment failed logins
	err = s.IncrementFailedLogins(ctx, "user1")
	if err != nil {
		t.Fatalf("IncrementFailedLogins() error = %v", err)
	}

	got, _ = s.GetUser(ctx, "user1")
	if got.FailedLoginAttempts != 1 {
		t.Errorf("FailedLoginAttempts = %d, want 1", got.FailedLoginAttempts)
	}

	// Lock user
	lockUntil := time.Now().Add(15 * time.Minute)
	err = s.LockUser(ctx, "user1", lockUntil)
	if err != nil {
		t.Fatalf("LockUser() error = %v", err)
	}

	got, _ = s.GetUser(ctx, "user1")
	if got.LockedUntil == nil {
		t.Error("LockedUntil should not be nil after LockUser()")
	}

	// Unlock user
	err = s.UnlockUser(ctx, "user1")
	if err != nil {
		t.Fatalf("UnlockUser() error = %v", err)
	}

	got, _ = s.GetUser(ctx, "user1")
	if got.LockedUntil != nil {
		t.Error("LockedUntil should be nil after UnlockUser()")
	}

	// Delete
	err = s.DeleteUser(ctx, "user1")
	if err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
}

func TestSQLiteStorage_SessionLifecycle(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	session := &Session{
		ID:           "sess1",
		KeyID:        "key1",
		ClientPubkey: "client1",
		Permissions:  []string{"ping", "sign_event"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	// Create
	err = s.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Get
	got, err := s.GetSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if len(got.Permissions) != 2 {
		t.Errorf("GetSession().Permissions = %v, want 2", got.Permissions)
	}

	// Get by client
	got, err = s.GetSessionByClient(ctx, "key1", "client1")
	if err != nil {
		t.Fatalf("GetSessionByClient() error = %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("GetSessionByClient().ID = %q, want %q", got.ID, session.ID)
	}

	// Delete
	err = s.DeleteSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}

	_, err = s.GetSession(ctx, "sess1")
	if err != ErrSessionNotFound {
		t.Errorf("GetSession() after delete error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestSQLiteStorage_PendingRequestLifecycle(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	eventKind := 1
	req := &PendingRequest{
		ID:           "req1",
		KeyPubkey:    "key1",
		ClientPubkey: "client1",
		Method:       "sign_event",
		EventKind:    &eventKind,
		ExpiresAt:    time.Now().Add(time.Minute),
		CreatedAt:    time.Now(),
	}

	// Create
	err = s.CreatePendingRequest(ctx, req)
	if err != nil {
		t.Fatalf("CreatePendingRequest() error = %v", err)
	}

	// Get
	got, err := s.GetPendingRequest(ctx, "req1")
	if err != nil {
		t.Fatalf("GetPendingRequest() error = %v", err)
	}
	if got.Method != req.Method {
		t.Errorf("GetPendingRequest().Method = %q, want %q", got.Method, req.Method)
	}
	if got.EventKind == nil || *got.EventKind != 1 {
		t.Errorf("GetPendingRequest().EventKind = %v, want 1", got.EventKind)
	}

	// List
	reqs, err := s.ListPendingRequests(ctx, "key1")
	if err != nil {
		t.Fatalf("ListPendingRequests() error = %v", err)
	}
	if len(reqs) != 1 {
		t.Errorf("ListPendingRequests() = %d, want 1", len(reqs))
	}

	// Delete
	err = s.DeletePendingRequest(ctx, "req1")
	if err != nil {
		t.Fatalf("DeletePendingRequest() error = %v", err)
	}

	_, err = s.GetPendingRequest(ctx, "req1")
	if err != ErrRequestNotFound {
		t.Errorf("GetPendingRequest() after delete error = %v, want %v", err, ErrRequestNotFound)
	}
}

func TestSQLiteStorage_FrostKeyLifecycle(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	key := &FrostKey{
		ID:                 "frost1",
		Name:               "Test FROST Key",
		Pubkey:             "frostpub123",
		Threshold:          2,
		TotalShares:        3,
		GroupPublicKey:     []byte("group-key-data"),
		VerificationShares: []byte("verification-data"),
		CreatedAt:          time.Now(),
		OwnerID:            "owner1",
	}

	// Create
	err = s.CreateFrostKey(ctx, key)
	if err != nil {
		t.Fatalf("CreateFrostKey() error = %v", err)
	}

	// Get by ID
	got, err := s.GetFrostKey(ctx, "frost1")
	if err != nil {
		t.Fatalf("GetFrostKey() error = %v", err)
	}
	if got.Threshold != 2 {
		t.Errorf("GetFrostKey().Threshold = %d, want 2", got.Threshold)
	}

	// Get by pubkey
	got, err = s.GetFrostKeyByPubkey(ctx, "frostpub123")
	if err != nil {
		t.Fatalf("GetFrostKeyByPubkey() error = %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("GetFrostKeyByPubkey().ID = %q, want %q", got.ID, key.ID)
	}

	// List
	keys, err := s.ListFrostKeys(ctx)
	if err != nil {
		t.Fatalf("ListFrostKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("ListFrostKeys() = %d, want 1", len(keys))
	}

	// List by owner
	keys, err = s.ListFrostKeysByOwner(ctx, "owner1")
	if err != nil {
		t.Fatalf("ListFrostKeysByOwner() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("ListFrostKeysByOwner() = %d, want 1", len(keys))
	}

	// Delete
	err = s.DeleteFrostKey(ctx, "frost1")
	if err != nil {
		t.Fatalf("DeleteFrostKey() error = %v", err)
	}

	_, err = s.GetFrostKey(ctx, "frost1")
	if err != ErrFrostKeyNotFound {
		t.Errorf("GetFrostKey() after delete error = %v, want %v", err, ErrFrostKeyNotFound)
	}
}

func TestSQLiteStorage_FrostShareLifecycle(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	// Create FROST key first (foreign key)
	key := &FrostKey{
		ID:                 "frost1",
		Pubkey:             "frostpub123",
		Threshold:          2,
		TotalShares:        3,
		GroupPublicKey:     []byte("group-key"),
		VerificationShares: []byte("verification"),
		CreatedAt:          time.Now(),
	}
	s.CreateFrostKey(ctx, key)

	share := &FrostShare{
		ID:             "share1",
		FrostKeyID:     "frost1",
		ShareIndex:     1,
		EncryptedShare: []byte("encrypted-share-data"),
		IsLocal:        true,
		PublicShare:    []byte("public-share-data"),
		CreatedAt:      time.Now(),
	}

	// Create
	err = s.CreateFrostShare(ctx, share)
	if err != nil {
		t.Fatalf("CreateFrostShare() error = %v", err)
	}

	// Get by ID
	got, err := s.GetFrostShare(ctx, "share1")
	if err != nil {
		t.Fatalf("GetFrostShare() error = %v", err)
	}
	if got.ShareIndex != 1 {
		t.Errorf("GetFrostShare().ShareIndex = %d, want 1", got.ShareIndex)
	}
	if !got.IsLocal {
		t.Error("GetFrostShare().IsLocal should be true")
	}

	// Get by key and index
	got, err = s.GetFrostShareByKeyAndIndex(ctx, "frost1", 1)
	if err != nil {
		t.Fatalf("GetFrostShareByKeyAndIndex() error = %v", err)
	}
	if got.ID != share.ID {
		t.Errorf("GetFrostShareByKeyAndIndex().ID = %q, want %q", got.ID, share.ID)
	}

	// List
	shares, err := s.ListFrostShares(ctx, "frost1")
	if err != nil {
		t.Fatalf("ListFrostShares() error = %v", err)
	}
	if len(shares) != 1 {
		t.Errorf("ListFrostShares() = %d, want 1", len(shares))
	}

	// List local only
	shares, err = s.ListLocalFrostShares(ctx, "frost1")
	if err != nil {
		t.Fatalf("ListLocalFrostShares() error = %v", err)
	}
	if len(shares) != 1 {
		t.Errorf("ListLocalFrostShares() = %d, want 1", len(shares))
	}

	// Delete
	err = s.DeleteFrostShare(ctx, "share1")
	if err != nil {
		t.Fatalf("DeleteFrostShare() error = %v", err)
	}
}

func TestSQLiteStorage_PolicyLifecycle(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	policy := &Policy{
		ID:          "policy1",
		Name:        "Test Policy",
		Description: "A test policy",
		Rules: []*PolicyRule{
			{ID: "rule1", PolicyID: "policy1", Method: "sign_event", AllowedKinds: []int{1, 4}, MaxUsage: 100},
		},
		CreatedAt: time.Now(),
	}

	// Create
	err = s.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Get
	got, err := s.GetPolicy(ctx, "policy1")
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if got.Name != policy.Name {
		t.Errorf("GetPolicy().Name = %q, want %q", got.Name, policy.Name)
	}
	if len(got.Rules) != 1 {
		t.Errorf("GetPolicy().Rules = %d, want 1", len(got.Rules))
	}
	if len(got.Rules[0].AllowedKinds) != 2 {
		t.Errorf("GetPolicy().Rules[0].AllowedKinds = %d, want 2", len(got.Rules[0].AllowedKinds))
	}

	// List
	policies, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("ListPolicies() = %d, want 1", len(policies))
	}

	// Increment rule usage
	err = s.IncrementRuleUsage(ctx, "rule1")
	if err != nil {
		t.Fatalf("IncrementRuleUsage() error = %v", err)
	}

	got, _ = s.GetPolicy(ctx, "policy1")
	if got.Rules[0].CurrentUsage != 1 {
		t.Errorf("Rule.CurrentUsage = %d, want 1", got.Rules[0].CurrentUsage)
	}

	// Delete
	err = s.DeletePolicy(ctx, "policy1")
	if err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}

	_, err = s.GetPolicy(ctx, "policy1")
	if err != ErrPolicyNotFound {
		t.Errorf("GetPolicy() after delete error = %v, want %v", err, ErrPolicyNotFound)
	}
}

func TestSQLiteStorage_Settings(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	// Set
	err = s.SetSetting(ctx, "signer_identity_key", "encrypted-key-data")
	if err != nil {
		t.Fatalf("SetSetting() error = %v", err)
	}

	// Get
	got, err := s.GetSetting(ctx, "signer_identity_key")
	if err != nil {
		t.Fatalf("GetSetting() error = %v", err)
	}
	if got != "encrypted-key-data" {
		t.Errorf("GetSetting() = %q, want %q", got, "encrypted-key-data")
	}

	// Update (upsert)
	err = s.SetSetting(ctx, "signer_identity_key", "new-key-data")
	if err != nil {
		t.Fatalf("SetSetting() update error = %v", err)
	}

	got, _ = s.GetSetting(ctx, "signer_identity_key")
	if got != "new-key-data" {
		t.Errorf("GetSetting() after update = %q, want %q", got, "new-key-data")
	}
}

func TestSQLiteStorage_UpdateKeyEncryption(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	// Create key with local encryption
	key := &Key{
		ID:               "key1",
		Pubkey:           "pub1",
		EncryptedNsec:    "enc:local-encrypted",
		EncryptionMethod: "local",
	}
	s.CreateKey(ctx, key)

	// Update to vault encryption
	err = s.UpdateKeyEncryption(ctx, "key1", "vault:v1:vault-encrypted", "vault")
	if err != nil {
		t.Fatalf("UpdateKeyEncryption() error = %v", err)
	}

	got, _ := s.GetKey(ctx, "key1")
	if got.EncryptedNsec != "vault:v1:vault-encrypted" {
		t.Errorf("EncryptedNsec = %q, want %q", got.EncryptedNsec, "vault:v1:vault-encrypted")
	}
	if got.EncryptionMethod != "vault" {
		t.Errorf("EncryptionMethod = %q, want %q", got.EncryptionMethod, "vault")
	}
}

func TestSQLiteStorage_DataPersistence(t *testing.T) {
	// Test that data persists across connections
	tmpFile := t.TempDir() + "/test.db"

	// First connection - create data
	s1, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}

	ctx := context.Background()
	s1.CreateKey(ctx, &Key{ID: "key1", Pubkey: "pub1", Name: "Persistent Key"})
	s1.Close()

	// Second connection - verify data
	s2, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() second connection error = %v", err)
	}
	defer s2.Close()

	got, err := s2.GetKey(ctx, "key1")
	if err != nil {
		t.Fatalf("GetKey() after reconnect error = %v", err)
	}
	if got.Name != "Persistent Key" {
		t.Errorf("Data not persisted: got name %q, want %q", got.Name, "Persistent Key")
	}
}

func TestSQLiteStorage_ConcurrentAccess(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("NewSQLiteStorage() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	// Create multiple keys concurrently
	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			key := &Key{
				ID:     "key" + string(rune('0'+idx)),
				Pubkey: "pub" + string(rune('0'+idx)),
			}
			done <- s.CreateKey(ctx, key)
		}(i)
	}

	// Wait for all
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Errorf("Concurrent CreateKey error = %v", err)
		}
	}

	// Verify all were created
	keys, _ := s.ListAllKeys(ctx)
	if len(keys) != 10 {
		t.Errorf("Concurrent creation: got %d keys, want 10", len(keys))
	}
}

// Cleanup helper - remove test database file
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
