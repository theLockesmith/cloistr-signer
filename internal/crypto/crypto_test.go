package crypto

import (
	"strings"
	"testing"
)

func TestNewEncryptor(t *testing.T) {
	tests := []struct {
		name    string
		hexKey  string
		wantErr bool
	}{
		{
			name:    "valid 32-byte key",
			hexKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: false,
		},
		{
			name:    "invalid hex",
			hexKey:  "not-valid-hex",
			wantErr: true,
		},
		{
			name:    "too short",
			hexKey:  "0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "too long",
			hexKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
			wantErr: true,
		},
		{
			name:    "empty key",
			hexKey:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEncryptor(tt.hexKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEncryptor() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple string",
			plaintext: "hello world",
		},
		{
			name:      "hex private key",
			plaintext: "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa",
		},
		{
			name:      "nsec format",
			plaintext: "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "unicode",
			plaintext: "こんにちは世界 🔐",
		},
		{
			name:      "long string",
			plaintext: strings.Repeat("a", 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Verify prefix
			if !strings.HasPrefix(ciphertext, "enc:") {
				t.Errorf("Encrypt() ciphertext should have 'enc:' prefix")
			}

			// Verify ciphertext is different from plaintext
			if ciphertext == tt.plaintext && tt.plaintext != "" {
				t.Error("Encrypt() ciphertext should differ from plaintext")
			}

			// Decrypt and verify
			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestDecryptWithoutPrefix(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := "test data"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Remove prefix and decrypt
	withoutPrefix := strings.TrimPrefix(ciphertext, "enc:")
	decrypted, err := enc.Decrypt(withoutPrefix)
	if err != nil {
		t.Fatalf("Decrypt() without prefix error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
	}
}

func TestDecryptInvalid(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
	}{
		{
			name:       "invalid base64",
			ciphertext: "not-valid-base64!!!",
		},
		{
			name:       "too short",
			ciphertext: "YWJj", // "abc" in base64
		},
		{
			name:       "wrong key",
			ciphertext: "enc:dGVzdA==", // won't decrypt with this key
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := enc.Decrypt(tt.ciphertext)
			if err == nil {
				t.Error("Decrypt() should return error for invalid ciphertext")
			}
		})
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := "same plaintext"
	ciphertext1, _ := enc.Encrypt(plaintext)
	ciphertext2, _ := enc.Encrypt(plaintext)

	// Due to random nonce, ciphertexts should differ
	if ciphertext1 == ciphertext2 {
		t.Error("Encrypt() should produce different ciphertexts for same plaintext (random nonce)")
	}

	// But both should decrypt to same plaintext
	dec1, _ := enc.Decrypt(ciphertext1)
	dec2, _ := enc.Decrypt(ciphertext2)
	if dec1 != dec2 || dec1 != plaintext {
		t.Error("Both ciphertexts should decrypt to same plaintext")
	}
}

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"enc:abc123", true},
		{"enc:", true},
		{"plaintext", false},
		{"", false},
		{"encrypted:abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := IsEncrypted(tt.value); got != tt.want {
				t.Errorf("IsEncrypted(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Should be 64 hex chars (32 bytes)
	if len(key1) != 64 {
		t.Errorf("GenerateKey() length = %d, want 64", len(key1))
	}

	// Should be valid for creating encryptor
	_, err = NewEncryptor(key1)
	if err != nil {
		t.Errorf("Generated key should be valid: %v", err)
	}

	// Should generate different keys
	key2, _ := GenerateKey()
	if key1 == key2 {
		t.Error("GenerateKey() should produce different keys")
	}
}

func TestDifferentKeysCannotDecrypt(t *testing.T) {
	key1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	enc1, _ := NewEncryptor(key1)
	enc2, _ := NewEncryptor(key2)

	plaintext := "secret data"
	ciphertext, _ := enc1.Encrypt(plaintext)

	// enc2 should not be able to decrypt enc1's ciphertext
	_, err := enc2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Different key should not be able to decrypt")
	}
}
