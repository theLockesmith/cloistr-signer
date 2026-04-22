package frost

import (
	"context"
	"crypto/sha256"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// testEncryptor is a simple encryptor for testing that just returns data as-is
type testEncryptor struct{}

func (t *testEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (t *testEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

// testStorage implements the Storage interface for testing
type testStorage struct {
	frostKeys   map[string]*storage.FrostKey
	frostShares map[string]*storage.FrostShare
}

func newTestStorage() *testStorage {
	return &testStorage{
		frostKeys:   make(map[string]*storage.FrostKey),
		frostShares: make(map[string]*storage.FrostShare),
	}
}

func (s *testStorage) CreateFrostKey(ctx context.Context, key *storage.FrostKey) error {
	s.frostKeys[key.ID] = key
	return nil
}

func (s *testStorage) GetFrostKey(ctx context.Context, id string) (*storage.FrostKey, error) {
	key, ok := s.frostKeys[id]
	if !ok {
		return nil, storage.ErrKeyNotFound
	}
	return key, nil
}

func (s *testStorage) GetFrostKeyByPubkey(ctx context.Context, pubkey string) (*storage.FrostKey, error) {
	for _, key := range s.frostKeys {
		if key.Pubkey == pubkey {
			return key, nil
		}
	}
	return nil, storage.ErrKeyNotFound
}

func (s *testStorage) ListFrostKeys(ctx context.Context) ([]*storage.FrostKey, error) {
	var keys []*storage.FrostKey
	for _, key := range s.frostKeys {
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *testStorage) DeleteFrostKey(ctx context.Context, id string) error {
	delete(s.frostKeys, id)
	// Also delete associated shares
	for shareID, share := range s.frostShares {
		if share.FrostKeyID == id {
			delete(s.frostShares, shareID)
		}
	}
	return nil
}

func (s *testStorage) CreateFrostShare(ctx context.Context, share *storage.FrostShare) error {
	s.frostShares[share.ID] = share
	return nil
}

func (s *testStorage) GetFrostShare(ctx context.Context, id string) (*storage.FrostShare, error) {
	share, ok := s.frostShares[id]
	if !ok {
		return nil, storage.ErrKeyNotFound
	}
	return share, nil
}

func (s *testStorage) GetFrostShareByKeyAndIndex(ctx context.Context, frostKeyID string, index int) (*storage.FrostShare, error) {
	for _, share := range s.frostShares {
		if share.FrostKeyID == frostKeyID && share.ShareIndex == index {
			return share, nil
		}
	}
	return nil, storage.ErrKeyNotFound
}

func (s *testStorage) ListFrostShares(ctx context.Context, frostKeyID string) ([]*storage.FrostShare, error) {
	var shares []*storage.FrostShare
	for _, share := range s.frostShares {
		if share.FrostKeyID == frostKeyID {
			shares = append(shares, share)
		}
	}
	return shares, nil
}

func (s *testStorage) ListLocalFrostShares(ctx context.Context, frostKeyID string) ([]*storage.FrostShare, error) {
	var shares []*storage.FrostShare
	for _, share := range s.frostShares {
		if share.FrostKeyID == frostKeyID && share.IsLocal {
			shares = append(shares, share)
		}
	}
	return shares, nil
}

func (s *testStorage) DeleteFrostShare(ctx context.Context, id string) error {
	delete(s.frostShares, id)
	return nil
}

func TestKeyGenConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *KeyGenConfig
		wantErr bool
	}{
		{
			name: "valid 2-of-3",
			config: &KeyGenConfig{
				Threshold:   2,
				TotalShares: 3,
			},
			wantErr: false,
		},
		{
			name: "valid 3-of-5",
			config: &KeyGenConfig{
				Threshold:   3,
				TotalShares: 5,
			},
			wantErr: false,
		},
		{
			name: "valid 1-of-1",
			config: &KeyGenConfig{
				Threshold:   1,
				TotalShares: 1,
			},
			wantErr: false,
		},
		{
			name: "invalid threshold zero",
			config: &KeyGenConfig{
				Threshold:   0,
				TotalShares: 3,
			},
			wantErr: true,
		},
		{
			name: "invalid threshold greater than total",
			config: &KeyGenConfig{
				Threshold:   5,
				TotalShares: 3,
			},
			wantErr: true,
		},
		{
			name: "invalid threshold too large",
			config: &KeyGenConfig{
				Threshold:   256,
				TotalShares: 300,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeyGenerator_GenerateKey(t *testing.T) {
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	tests := []struct {
		name        string
		config      *KeyGenConfig
		wantErr     bool
		checkShares bool
	}{
		{
			name: "generate 2-of-3 key",
			config: &KeyGenConfig{
				Name:        "test key",
				Threshold:   2,
				TotalShares: 3,
			},
			wantErr:     false,
			checkShares: true,
		},
		{
			name: "generate 3-of-5 key",
			config: &KeyGenConfig{
				Threshold:   3,
				TotalShares: 5,
			},
			wantErr:     false,
			checkShares: true,
		},
		{
			name: "generate 1-of-1 key",
			config: &KeyGenConfig{
				Threshold:   1,
				TotalShares: 1,
			},
			wantErr:     false,
			checkShares: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := kg.GenerateKey(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify key properties
			if result.FrostKey == nil {
				t.Error("FrostKey is nil")
				return
			}

			if result.FrostKey.Threshold != tt.config.Threshold {
				t.Errorf("Threshold = %d, want %d", result.FrostKey.Threshold, tt.config.Threshold)
			}

			if result.FrostKey.TotalShares != tt.config.TotalShares {
				t.Errorf("TotalShares = %d, want %d", result.FrostKey.TotalShares, tt.config.TotalShares)
			}

			if len(result.FrostKey.Pubkey) != 64 {
				t.Errorf("Pubkey length = %d, want 64 hex chars", len(result.FrostKey.Pubkey))
			}

			if len(result.FrostKey.GroupPublicKey) == 0 {
				t.Error("GroupPublicKey is empty")
			}

			if len(result.FrostKey.VerificationShares) == 0 {
				t.Error("VerificationShares is empty")
			}

			// Verify shares
			if tt.checkShares {
				if len(result.Shares) != tt.config.TotalShares {
					t.Errorf("Shares count = %d, want %d", len(result.Shares), tt.config.TotalShares)
				}

				for i, share := range result.Shares {
					if share.ShareIndex != i+1 {
						t.Errorf("Share %d index = %d, want %d", i, share.ShareIndex, i+1)
					}
					if !share.IsLocal {
						t.Errorf("Share %d should be local", i)
					}
					if len(share.EncryptedShare) == 0 {
						t.Errorf("Share %d has no data", i)
					}
				}

				if len(result.SecretData) != tt.config.TotalShares {
					t.Errorf("SecretData count = %d, want %d", len(result.SecretData), tt.config.TotalShares)
				}
			}
		})
	}
}

func TestCoordinator_SignMessage_2of3(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a 2-of-3 key
	config := &KeyGenConfig{
		Name:        "test signing key",
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store the key and shares
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}

	for _, share := range result.Shares {
		if err := store.CreateFrostShare(ctx, share); err != nil {
			t.Fatalf("Failed to store share: %v", err)
		}
	}

	// Create a test message (simulating event hash)
	message := sha256.Sum256([]byte("test message to sign"))

	// Sign the message
	signature, err := coord.SignMessage(ctx, result.FrostKey.ID, message[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	// Verify the signature
	valid, err := coord.VerifySignature(ctx, result.FrostKey.ID, message[:], signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}
}

func TestCoordinator_SignMessage_3of5(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a 3-of-5 key
	config := &KeyGenConfig{
		Name:        "test 3-of-5 key",
		Threshold:   3,
		TotalShares: 5,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store the key and all shares
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}

	for _, share := range result.Shares {
		if err := store.CreateFrostShare(ctx, share); err != nil {
			t.Fatalf("Failed to store share: %v", err)
		}
	}

	// Sign multiple messages
	for i := 0; i < 5; i++ {
		message := sha256.Sum256([]byte("test message " + string(rune('A'+i))))

		signature, err := coord.SignMessage(ctx, result.FrostKey.ID, message[:])
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}

		valid, err := coord.VerifySignature(ctx, result.FrostKey.ID, message[:], signature)
		if err != nil {
			t.Fatalf("Failed to verify signature %d: %v", i, err)
		}

		if !valid {
			t.Errorf("Signature %d verification failed", i)
		}
	}
}

func TestCoordinator_SignMessage_ThresholdShares(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a 2-of-3 key
	config := &KeyGenConfig{
		Name:        "test threshold key",
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store the key
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}

	// Only store 2 of 3 shares (threshold)
	for i := 0; i < 2; i++ {
		if err := store.CreateFrostShare(ctx, result.Shares[i]); err != nil {
			t.Fatalf("Failed to store share: %v", err)
		}
	}

	// Should still be able to sign with exactly threshold shares
	message := sha256.Sum256([]byte("test with threshold shares"))

	signature, err := coord.SignMessage(ctx, result.FrostKey.ID, message[:])
	if err != nil {
		t.Fatalf("Failed to sign with threshold shares: %v", err)
	}

	valid, err := coord.VerifySignature(ctx, result.FrostKey.ID, message[:], signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed with threshold shares")
	}
}

func TestCoordinator_SignMessage_InsufficientShares(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a 2-of-3 key
	config := &KeyGenConfig{
		Name:        "test insufficient key",
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store the key
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}

	// Only store 1 share (less than threshold)
	if err := store.CreateFrostShare(ctx, result.Shares[0]); err != nil {
		t.Fatalf("Failed to store share: %v", err)
	}

	// Signing should fail
	message := sha256.Sum256([]byte("test with insufficient shares"))

	_, err = coord.SignMessage(ctx, result.FrostKey.ID, message[:])
	if err == nil {
		t.Error("Expected error with insufficient shares")
	}
}

func TestCoordinator_SignEvent(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a key
	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store key and shares
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}
	for _, share := range result.Shares {
		if err := store.CreateFrostShare(ctx, share); err != nil {
			t.Fatalf("Failed to store share: %v", err)
		}
	}

	// Create a 32-byte event hash
	eventHash := sha256.Sum256([]byte(`["0","pubkey",1234567890,1,[],{"content":"test"}]`))

	// Sign the event
	signatureHex, err := coord.SignEvent(ctx, result.FrostKey.ID, eventHash[:])
	if err != nil {
		t.Fatalf("Failed to sign event: %v", err)
	}

	// Verify signature format (should be 128 hex chars = 64 bytes)
	if len(signatureHex) < 128 {
		t.Errorf("Signature hex length = %d, expected at least 128", len(signatureHex))
	}
}

func TestCoordinator_SignEvent_InvalidHash(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	coord := NewCoordinator(store, encryptor)

	// Try to sign with invalid hash lengths
	invalidHashes := [][]byte{
		nil,
		{},
		{0x01, 0x02, 0x03}, // Too short
		make([]byte, 31),   // One byte short
		make([]byte, 33),   // One byte too long
	}

	for _, hash := range invalidHashes {
		_, err := coord.SignEvent(ctx, "any-key-id", hash)
		if err == nil {
			t.Errorf("Expected error for hash length %d", len(hash))
		}
	}
}

func TestCoordinator_CanSign(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a 2-of-3 key
	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store the key
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}

	// With 0 shares
	canSign, err := coord.CanSign(ctx, result.FrostKey.ID)
	if err != nil {
		t.Fatalf("CanSign error: %v", err)
	}
	if canSign {
		t.Error("Should not be able to sign with 0 shares")
	}

	// Add 1 share
	if err := store.CreateFrostShare(ctx, result.Shares[0]); err != nil {
		t.Fatalf("Failed to store share: %v", err)
	}

	canSign, err = coord.CanSign(ctx, result.FrostKey.ID)
	if err != nil {
		t.Fatalf("CanSign error: %v", err)
	}
	if canSign {
		t.Error("Should not be able to sign with 1 share (threshold is 2)")
	}

	// Add second share
	if err := store.CreateFrostShare(ctx, result.Shares[1]); err != nil {
		t.Fatalf("Failed to store share: %v", err)
	}

	canSign, err = coord.CanSign(ctx, result.FrostKey.ID)
	if err != nil {
		t.Fatalf("CanSign error: %v", err)
	}
	if !canSign {
		t.Error("Should be able to sign with 2 shares (threshold)")
	}
}

func TestCoordinator_GetAvailableShareCount(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a key
	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store the key
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}

	// Initially 0 shares
	count, err := coord.GetAvailableShareCount(ctx, result.FrostKey.ID)
	if err != nil {
		t.Fatalf("GetAvailableShareCount error: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 shares, got %d", count)
	}

	// Add shares one by one
	for i, share := range result.Shares {
		if err := store.CreateFrostShare(ctx, share); err != nil {
			t.Fatalf("Failed to store share: %v", err)
		}

		count, err = coord.GetAvailableShareCount(ctx, result.FrostKey.ID)
		if err != nil {
			t.Fatalf("GetAvailableShareCount error: %v", err)
		}
		if count != i+1 {
			t.Errorf("Expected %d shares, got %d", i+1, count)
		}
	}
}

func TestCoordinator_GetShareHolders(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a key
	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store the key and shares
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}
	for _, share := range result.Shares {
		if err := store.CreateFrostShare(ctx, share); err != nil {
			t.Fatalf("Failed to store share: %v", err)
		}
	}

	// Get share holders
	holders, err := coord.GetShareHolders(ctx, result.FrostKey.ID)
	if err != nil {
		t.Fatalf("GetShareHolders error: %v", err)
	}

	if len(holders) != 3 {
		t.Errorf("Expected 3 holders, got %d", len(holders))
	}

	for _, holder := range holders {
		if !holder.IsLocal {
			t.Error("Expected all holders to be local")
		}
		if !holder.IsOnline {
			t.Error("Expected all local holders to be online")
		}
	}
}

func TestKeyGenerator_CreateShareBundle(t *testing.T) {
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	// Generate a key
	config := &KeyGenConfig{
		Name:        "bundle test",
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create bundle for first share
	bundle, err := kg.CreateShareBundle(result.FrostKey, result.Shares[0])
	if err != nil {
		t.Fatalf("Failed to create share bundle: %v", err)
	}

	// Verify bundle contents
	if bundle.FrostKeyID != result.FrostKey.ID {
		t.Errorf("Bundle FrostKeyID mismatch")
	}
	if bundle.ShareIndex != 1 {
		t.Errorf("Bundle ShareIndex = %d, want 1", bundle.ShareIndex)
	}
	if bundle.Threshold != 2 {
		t.Errorf("Bundle Threshold = %d, want 2", bundle.Threshold)
	}
	if bundle.TotalShares != 3 {
		t.Errorf("Bundle TotalShares = %d, want 3", bundle.TotalShares)
	}
	if bundle.ShareData == "" {
		t.Error("Bundle ShareData is empty")
	}
	if bundle.GroupPublicKey == "" {
		t.Error("Bundle GroupPublicKey is empty")
	}
	if bundle.VerificationShares == "" {
		t.Error("Bundle VerificationShares is empty")
	}
}

func TestConvertToNostrSignature(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantLen   int
		wantErr   bool
	}{
		{
			name:    "64-byte signature",
			input:   make([]byte, 64),
			wantLen: 128, // hex encoding
			wantErr: false,
		},
		{
			name:    "65-byte signature",
			input:   append([]byte{0x02}, make([]byte, 64)...),
			wantLen: 128,
			wantErr: false,
		},
		{
			name:    "wrong length",
			input:   make([]byte, 60),
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ConvertToNostrSignature(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertToNostrSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantLen {
				t.Errorf("ConvertToNostrSignature() length = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestDeterministicSignatures(t *testing.T) {
	// FROST signatures are NOT deterministic (random nonces), but signing the
	// same message twice should produce valid signatures both times
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate a key
	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store key and shares
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("Failed to store frost key: %v", err)
	}
	for _, share := range result.Shares {
		if err := store.CreateFrostShare(ctx, share); err != nil {
			t.Fatalf("Failed to store share: %v", err)
		}
	}

	message := sha256.Sum256([]byte("determinism test"))

	// Sign twice
	sig1, err := coord.SignMessage(ctx, result.FrostKey.ID, message[:])
	if err != nil {
		t.Fatalf("First sign failed: %v", err)
	}

	sig2, err := coord.SignMessage(ctx, result.FrostKey.ID, message[:])
	if err != nil {
		t.Fatalf("Second sign failed: %v", err)
	}

	// Signatures should be different (random nonces)
	// But we don't enforce this - some implementations might be deterministic

	// Both should verify
	valid1, err := coord.VerifySignature(ctx, result.FrostKey.ID, message[:], sig1)
	if err != nil {
		t.Fatalf("Verify sig1 error: %v", err)
	}
	if !valid1 {
		t.Error("Signature 1 should verify")
	}

	valid2, err := coord.VerifySignature(ctx, result.FrostKey.ID, message[:], sig2)
	if err != nil {
		t.Fatalf("Verify sig2 error: %v", err)
	}
	if !valid2 {
		t.Error("Signature 2 should verify")
	}
}

func TestWrongKeyVerification(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	// Generate two keys
	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result1, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key 1: %v", err)
	}

	result2, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("Failed to generate key 2: %v", err)
	}

	// Store both keys and shares
	for _, result := range []*KeyGenResult{result1, result2} {
		if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
			t.Fatalf("Failed to store frost key: %v", err)
		}
		for _, share := range result.Shares {
			if err := store.CreateFrostShare(ctx, share); err != nil {
				t.Fatalf("Failed to store share: %v", err)
			}
		}
	}

	message := sha256.Sum256([]byte("cross verification test"))

	// Sign with key1
	signature, err := coord.SignMessage(ctx, result1.FrostKey.ID, message[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with key1 (should succeed)
	valid, err := coord.VerifySignature(ctx, result1.FrostKey.ID, message[:], signature)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !valid {
		t.Error("Should verify with correct key")
	}

	// Verify with key2 (should fail)
	valid, err = coord.VerifySignature(ctx, result2.FrostKey.ID, message[:], signature)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if valid {
		t.Error("Should NOT verify with wrong key")
	}
}

func TestFrostKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)

	// Generate key
	config := &KeyGenConfig{
		Name:        "lifecycle test",
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	// Store key and shares
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("CreateFrostKey error: %v", err)
	}
	for _, share := range result.Shares {
		if err := store.CreateFrostShare(ctx, share); err != nil {
			t.Fatalf("CreateFrostShare error: %v", err)
		}
	}

	// List keys
	keys, err := store.ListFrostKeys(ctx)
	if err != nil {
		t.Fatalf("ListFrostKeys error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}

	// List shares
	shares, err := store.ListFrostShares(ctx, result.FrostKey.ID)
	if err != nil {
		t.Fatalf("ListFrostShares error: %v", err)
	}
	if len(shares) != 3 {
		t.Errorf("Expected 3 shares, got %d", len(shares))
	}

	// Get key by pubkey
	keyByPub, err := store.GetFrostKeyByPubkey(ctx, result.FrostKey.Pubkey)
	if err != nil {
		t.Fatalf("GetFrostKeyByPubkey error: %v", err)
	}
	if keyByPub.ID != result.FrostKey.ID {
		t.Error("Key ID mismatch")
	}

	// Delete key (should cascade to shares)
	if err := store.DeleteFrostKey(ctx, result.FrostKey.ID); err != nil {
		t.Fatalf("DeleteFrostKey error: %v", err)
	}

	// Verify deletion
	keys, err = store.ListFrostKeys(ctx)
	if err != nil {
		t.Fatalf("ListFrostKeys error: %v", err)
	}
	if len(keys) != 0 {
		t.Error("Key should be deleted")
	}

	shares, err = store.ListFrostShares(ctx, result.FrostKey.ID)
	if err != nil {
		t.Fatalf("ListFrostShares error: %v", err)
	}
	if len(shares) != 0 {
		t.Error("Shares should be deleted with key")
	}
}

// Benchmark tests
func BenchmarkKeyGeneration_2of3(b *testing.B) {
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kg.GenerateKey(config)
		if err != nil {
			b.Fatalf("GenerateKey error: %v", err)
		}
	}
}

func BenchmarkKeyGeneration_3of5(b *testing.B) {
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	config := &KeyGenConfig{
		Threshold:   3,
		TotalShares: 5,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kg.GenerateKey(config)
		if err != nil {
			b.Fatalf("GenerateKey error: %v", err)
		}
	}
}

func BenchmarkSigning_2of3(b *testing.B) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		b.Fatalf("GenerateKey error: %v", err)
	}

	store.CreateFrostKey(ctx, result.FrostKey)
	for _, share := range result.Shares {
		store.CreateFrostShare(ctx, share)
	}

	message := sha256.Sum256([]byte("benchmark message"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := coord.SignMessage(ctx, result.FrostKey.ID, message[:])
		if err != nil {
			b.Fatalf("SignMessage error: %v", err)
		}
	}
}

func BenchmarkVerification(b *testing.B) {
	ctx := context.Background()
	store := newTestStorage()
	encryptor := &testEncryptor{}

	kg := NewKeyGenerator(encryptor)
	coord := NewCoordinator(store, encryptor)

	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		b.Fatalf("GenerateKey error: %v", err)
	}

	store.CreateFrostKey(ctx, result.FrostKey)
	for _, share := range result.Shares {
		store.CreateFrostShare(ctx, share)
	}

	message := sha256.Sum256([]byte("benchmark message"))
	signature, err := coord.SignMessage(ctx, result.FrostKey.ID, message[:])
	if err != nil {
		b.Fatalf("SignMessage error: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := coord.VerifySignature(ctx, result.FrostKey.ID, message[:], signature)
		if err != nil {
			b.Fatalf("VerifySignature error: %v", err)
		}
	}
}
