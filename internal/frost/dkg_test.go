package frost

import (
	"context"
	"testing"

	"github.com/bytemare/ecc"
)

func TestKeyGenerator_ImportShare(t *testing.T) {
	ctx := context.Background()
	encryptor := &testEncryptor{}
	store := newTestStorage()
	kg := NewKeyGenerator(encryptor)

	// First generate a key to get valid share data
	config := &KeyGenConfig{
		Name:        "import test key",
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	// Store the FROST key
	if err := store.CreateFrostKey(ctx, result.FrostKey); err != nil {
		t.Fatalf("CreateFrostKey error: %v", err)
	}

	// Get raw share data from the first share
	shareData := result.SecretData[0]

	t.Run("import local share", func(t *testing.T) {
		importedShare, err := kg.ImportShare(result.FrostKey.ID, 1, shareData, true)
		if err != nil {
			t.Fatalf("ImportShare error: %v", err)
		}

		if importedShare.FrostKeyID != result.FrostKey.ID {
			t.Errorf("FrostKeyID = %q, want %q", importedShare.FrostKeyID, result.FrostKey.ID)
		}
		if importedShare.ShareIndex != 1 {
			t.Errorf("ShareIndex = %d, want 1", importedShare.ShareIndex)
		}
		if !importedShare.IsLocal {
			t.Error("IsLocal should be true")
		}
		if len(importedShare.EncryptedShare) == 0 {
			t.Error("EncryptedShare should not be empty")
		}
		if len(importedShare.PublicShare) == 0 {
			t.Error("PublicShare should not be empty for local shares")
		}
	})

	t.Run("import remote share reference", func(t *testing.T) {
		// Remote shares don't have local data, just reference
		importedShare, err := kg.ImportShare(result.FrostKey.ID, 2, nil, false)
		if err != nil {
			t.Fatalf("ImportShare error: %v", err)
		}

		if importedShare.IsLocal {
			t.Error("IsLocal should be false for remote share")
		}
		if len(importedShare.EncryptedShare) != 0 {
			t.Error("EncryptedShare should be empty for remote shares")
		}
	})

	t.Run("import local share with nil encryptor", func(t *testing.T) {
		// Create key generator with nil encryptor
		kgNil := NewKeyGenerator(nil)

		// Use the same share data from the original result
		importedShare, err := kgNil.ImportShare(result.FrostKey.ID, 1, result.SecretData[0], true)
		if err != nil {
			t.Fatalf("ImportShare with nil encryptor error: %v", err)
		}

		if !importedShare.IsLocal {
			t.Error("IsLocal should be true")
		}
		// With nil encryptor, EncryptedShare should contain the raw data
		if len(importedShare.EncryptedShare) == 0 {
			t.Error("EncryptedShare should not be empty")
		}
	})
}

func TestKeyGenerator_ImportShare_InvalidData(t *testing.T) {
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	// Try to import with invalid share data
	invalidData := []byte{0x01, 0x02, 0x03} // Too short to be a valid key share

	_, err := kg.ImportShare("some-key-id", 1, invalidData, true)
	if err == nil {
		t.Error("expected error for invalid share data")
	}
}

func TestGenerateID(t *testing.T) {
	// Generate multiple IDs and verify they're unique
	ids := make(map[string]bool)

	for i := 0; i < 100; i++ {
		id := generateID()

		// Check length (16 bytes = 32 hex chars)
		if len(id) != 32 {
			t.Errorf("ID length = %d, want 32", len(id))
		}

		// Check uniqueness
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true

		// Verify it's valid hex
		_, err := HexDecode(id)
		if err != nil {
			t.Errorf("ID is not valid hex: %s", id)
		}
	}
}

func TestEncodeDecodeVerificationShares(t *testing.T) {
	group := DefaultCiphersuite.Group()

	t.Run("encode and decode 3 public keys", func(t *testing.T) {
		// Create random public keys
		pubKeys := make([]*ecc.Element, 3)
		for i := 0; i < 3; i++ {
			scalar := group.NewScalar().Random()
			pubKeys[i] = group.Base().Multiply(scalar)
		}

		// Encode
		encoded, err := encodeVerificationShares(pubKeys, group)
		if err != nil {
			t.Fatalf("encode error: %v", err)
		}

		// Verify header (count)
		count := int(encoded[0])<<8 | int(encoded[1])
		if count != 3 {
			t.Errorf("encoded count = %d, want 3", count)
		}

		// Decode
		decoded, err := decodeVerificationShares(encoded, group)
		if err != nil {
			t.Fatalf("decode error: %v", err)
		}

		// Verify
		if len(decoded) != len(pubKeys) {
			t.Errorf("decoded length = %d, want %d", len(decoded), len(pubKeys))
		}

		for i := 0; i < len(pubKeys); i++ {
			if !pubKeys[i].Equal(decoded[i]) {
				t.Errorf("public key %d mismatch", i)
			}
		}
	})

	t.Run("empty public keys", func(t *testing.T) {
		encoded, err := encodeVerificationShares([]*ecc.Element{}, group)
		if err != nil {
			t.Fatalf("encode error: %v", err)
		}

		decoded, err := decodeVerificationShares(encoded, group)
		if err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if len(decoded) != 0 {
			t.Errorf("decoded length = %d, want 0", len(decoded))
		}
	})

	t.Run("single public key", func(t *testing.T) {
		scalar := group.NewScalar().Random()
		pubKey := group.Base().Multiply(scalar)

		encoded, err := encodeVerificationShares([]*ecc.Element{pubKey}, group)
		if err != nil {
			t.Fatalf("encode error: %v", err)
		}

		decoded, err := decodeVerificationShares(encoded, group)
		if err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if len(decoded) != 1 {
			t.Errorf("decoded length = %d, want 1", len(decoded))
		}
		if !pubKey.Equal(decoded[0]) {
			t.Error("public key mismatch")
		}
	})
}

func TestDecodeVerificationShares_Errors(t *testing.T) {
	group := DefaultCiphersuite.Group()

	t.Run("data too short", func(t *testing.T) {
		_, err := decodeVerificationShares([]byte{0x00}, group)
		if err == nil {
			t.Error("expected error for data too short")
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		// Header says 1 element but data is wrong size
		data := []byte{0x00, 0x01, 0x01, 0x02, 0x03} // Claims 1 element but wrong size
		_, err := decodeVerificationShares(data, group)
		if err == nil {
			t.Error("expected error for size mismatch")
		}
	})

	t.Run("invalid element decode", func(t *testing.T) {
		// Create data with correct size for 1 element but invalid element bytes
		elemSize := group.ElementLength()
		data := make([]byte, 2+elemSize)
		data[0] = 0x00
		data[1] = 0x01 // 1 element
		// Fill element data with all zeros - invalid point
		for i := 2; i < len(data); i++ {
			data[i] = 0x00
		}
		_, err := decodeVerificationShares(data, group)
		if err == nil {
			t.Error("expected error for invalid element decode")
		}
	})
}

func TestDecodeKeyShare(t *testing.T) {
	group := DefaultCiphersuite.Group()
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	// Generate a key to get valid share data
	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	// Decode the first share's secret data
	ks, err := decodeKeyShare(result.SecretData[0], group)
	if err != nil {
		t.Fatalf("decodeKeyShare error: %v", err)
	}

	// Verify it's a valid key share
	if ks == nil {
		t.Fatal("decoded key share is nil")
	}

	// The public key should match what we stored
	pubKey := ks.Public()
	if pubKey == nil {
		t.Error("key share has no public key")
	}
}

func TestDecodeKeyShare_InvalidData(t *testing.T) {
	group := DefaultCiphersuite.Group()

	// Invalid key share data
	invalidData := []byte{0x00, 0x01, 0x02}
	_, err := decodeKeyShare(invalidData, group)
	if err == nil {
		t.Error("expected error for invalid key share data")
	}
}

func TestPubkeyToHex(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "33-byte compressed pubkey",
			input:    append([]byte{0x02}, make([]byte, 32)...), // Prefix is stripped
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "32-byte x-only pubkey",
			input:    make([]byte, 32),
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pubkeyToHex(tt.input)
			if result != tt.expected {
				t.Errorf("pubkeyToHex = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestKeyGenConfig_Validate_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		config  *KeyGenConfig
		wantErr bool
	}{
		{
			name: "threshold equals total",
			config: &KeyGenConfig{
				Threshold:   5,
				TotalShares: 5,
			},
			wantErr: false,
		},
		{
			name: "maximum valid threshold",
			config: &KeyGenConfig{
				Threshold:   255,
				TotalShares: 255,
			},
			wantErr: false,
		},
		{
			name: "total shares zero",
			config: &KeyGenConfig{
				Threshold:   1,
				TotalShares: 0,
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

func TestKeyGenerator_GenerateKey_WithExistingSecret(t *testing.T) {
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	// Generate a random secret (32 bytes for secp256k1)
	group := DefaultCiphersuite.Group()
	existingSecret := group.NewScalar().Random()
	secretBytes := existingSecret.Encode()

	config := &KeyGenConfig{
		Name:           "imported secret key",
		Threshold:      2,
		TotalShares:    3,
		ExistingSecret: secretBytes,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	// Generate again with the same secret
	result2, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("GenerateKey second time error: %v", err)
	}

	// Both should produce the same public key
	if result.FrostKey.Pubkey != result2.FrostKey.Pubkey {
		t.Errorf("Pubkeys don't match: %s != %s", result.FrostKey.Pubkey, result2.FrostKey.Pubkey)
	}
}

func TestKeyGenerator_GenerateKey_EncryptError(t *testing.T) {
	encryptor := &failingEncryptor{failEncrypt: true}
	kg := NewKeyGenerator(encryptor)

	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	_, err := kg.GenerateKey(config)
	if err == nil {
		t.Error("expected error for encryption failure")
	}
}

func TestKeyGenerator_GenerateKey_InvalidExistingSecret(t *testing.T) {
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	config := &KeyGenConfig{
		Threshold:      2,
		TotalShares:   3,
		ExistingSecret: []byte{0x01, 0x02, 0x03}, // Invalid - too short
	}

	_, err := kg.GenerateKey(config)
	if err == nil {
		t.Error("expected error for invalid existing secret")
	}
}

func TestKeyGenerator_ImportShare_EncryptError(t *testing.T) {
	encryptor := &failingEncryptor{failEncrypt: true}
	kg := NewKeyGenerator(encryptor)

	// Generate valid share data first
	goodEncryptor := &testEncryptor{}
	goodKg := NewKeyGenerator(goodEncryptor)
	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}
	result, err := goodKg.GenerateKey(config)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	// Now try to import with failing encryptor
	_, err = kg.ImportShare(result.FrostKey.ID, 1, result.SecretData[0], true)
	if err == nil {
		t.Error("expected error for encryption failure")
	}
}

func TestKeyGenerator_GenerateKey_InvalidConfig(t *testing.T) {
	encryptor := &testEncryptor{}
	kg := NewKeyGenerator(encryptor)

	config := &KeyGenConfig{
		Threshold:   0, // Invalid threshold
		TotalShares: 3,
	}

	_, err := kg.GenerateKey(config)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestKeyGenerator_GenerateKey_NilEncryptor(t *testing.T) {
	// Test with nil encryptor - should work but store unencrypted
	kg := NewKeyGenerator(nil)

	config := &KeyGenConfig{
		Threshold:   2,
		TotalShares: 3,
	}

	result, err := kg.GenerateKey(config)
	if err != nil {
		t.Fatalf("GenerateKey with nil encryptor failed: %v", err)
	}

	if len(result.Shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(result.Shares))
	}

	// Verify shares were stored (unencrypted)
	for i, share := range result.Shares {
		if len(share.EncryptedShare) == 0 {
			t.Errorf("share %d has empty data", i)
		}
	}
}

