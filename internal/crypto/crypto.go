package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrInvalidKey        = errors.New("invalid encryption key: must be 32 bytes (64 hex chars)")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// Encryptor handles AES-256-GCM encryption/decryption
type Encryptor struct {
	gcm cipher.AEAD
}

// NewEncryptor creates a new Encryptor with the given hex-encoded key.
// The key must be 32 bytes (64 hex characters) for AES-256.
func NewEncryptor(hexKey string) (*Encryptor, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKey, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &Encryptor{gcm: gcm}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns base64-encoded ciphertext with "enc:" prefix.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	// Generate random nonce
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and append nonce to ciphertext
	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Return with prefix to identify encrypted values
	return "enc:" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext that was encrypted with Encrypt.
// Accepts ciphertext with or without "enc:" prefix.
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	// Strip prefix if present
	ciphertext = strings.TrimPrefix(ciphertext, "enc:")

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidCiphertext, err)
	}

	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("%w: data too short", ErrInvalidCiphertext)
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// IsEncrypted checks if a value has the encryption prefix
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, "enc:")
}

// GenerateKey generates a random 32-byte key and returns it hex-encoded.
// Use this to generate a new encryption key.
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
