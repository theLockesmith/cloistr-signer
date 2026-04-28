package crypto

import (
	"context"
	"encoding/base64"
	"fmt"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

// VaultEncryptor handles encryption/decryption via HashiCorp Vault transit engine.
// Each user has their own transit key, and operations require the user's Vault token.
type VaultEncryptor struct {
	client *vault.Client
	userID string
	token  string
}

// NewVaultEncryptor creates a new VaultEncryptor for a specific user.
// The token should be the user's Vault token (obtained via userpass auth).
// The userID is used to derive the transit key name.
func NewVaultEncryptor(client *vault.Client, userID, token string) *VaultEncryptor {
	return &VaultEncryptor{
		client: client,
		userID: userID,
		token:  token,
	}
}

// Encrypt encrypts plaintext using the user's Vault transit key.
// Returns Vault ciphertext (vault:v1:...).
func (v *VaultEncryptor) Encrypt(plaintext string) (string, error) {
	return v.EncryptWithContext(context.Background(), plaintext)
}

// EncryptWithContext encrypts plaintext with a context for cancellation.
func (v *VaultEncryptor) EncryptWithContext(ctx context.Context, plaintext string) (string, error) {
	// Vault transit expects base64-encoded plaintext
	b64Plaintext := base64.StdEncoding.EncodeToString([]byte(plaintext))

	keyName := vault.UserTransitKeyName(v.userID)
	ciphertext, err := v.client.TransitEncryptWithToken(ctx, v.token, keyName, b64Plaintext)
	if err != nil {
		return "", fmt.Errorf("vault encrypt failed: %w", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using the user's Vault transit key.
// Accepts Vault ciphertext (vault:v1:...).
func (v *VaultEncryptor) Decrypt(ciphertext string) (string, error) {
	return v.DecryptWithContext(context.Background(), ciphertext)
}

// DecryptWithContext decrypts ciphertext with a context for cancellation.
func (v *VaultEncryptor) DecryptWithContext(ctx context.Context, ciphertext string) (string, error) {
	keyName := vault.UserTransitKeyName(v.userID)
	b64Plaintext, err := v.client.TransitDecryptWithToken(ctx, v.token, keyName, ciphertext)
	if err != nil {
		return "", fmt.Errorf("vault decrypt failed: %w", err)
	}

	// Vault transit returns base64-encoded plaintext
	plaintext, err := base64.StdEncoding.DecodeString(b64Plaintext)
	if err != nil {
		return "", fmt.Errorf("failed to decode plaintext: %w", err)
	}

	return string(plaintext), nil
}

// EncryptBytes encrypts raw bytes using the user's Vault transit key.
func (v *VaultEncryptor) EncryptBytes(plaintext []byte) ([]byte, error) {
	return v.EncryptBytesWithContext(context.Background(), plaintext)
}

// EncryptBytesWithContext encrypts raw bytes with a context.
func (v *VaultEncryptor) EncryptBytesWithContext(ctx context.Context, plaintext []byte) ([]byte, error) {
	// Vault transit expects base64-encoded plaintext
	b64Plaintext := base64.StdEncoding.EncodeToString(plaintext)

	keyName := vault.UserTransitKeyName(v.userID)
	ciphertext, err := v.client.TransitEncryptWithToken(ctx, v.token, keyName, b64Plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault encrypt failed: %w", err)
	}

	// Return ciphertext as bytes (it's ASCII, so this is safe)
	return []byte(ciphertext), nil
}

// DecryptBytes decrypts raw bytes using the user's Vault transit key.
func (v *VaultEncryptor) DecryptBytes(ciphertext []byte) ([]byte, error) {
	return v.DecryptBytesWithContext(context.Background(), ciphertext)
}

// DecryptBytesWithContext decrypts raw bytes with a context.
func (v *VaultEncryptor) DecryptBytesWithContext(ctx context.Context, ciphertext []byte) ([]byte, error) {
	keyName := vault.UserTransitKeyName(v.userID)
	b64Plaintext, err := v.client.TransitDecryptWithToken(ctx, v.token, keyName, string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("vault decrypt failed: %w", err)
	}

	// Vault transit returns base64-encoded plaintext
	plaintext, err := base64.StdEncoding.DecodeString(b64Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	return plaintext, nil
}

// UserID returns the user ID this encryptor is configured for.
func (v *VaultEncryptor) UserID() string {
	return v.userID
}

// KeyEncryptor defines the interface for key encryption/decryption.
// Both Encryptor (local AES-GCM) and VaultEncryptor implement this.
type KeyEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
	EncryptBytes(plaintext []byte) ([]byte, error)
	DecryptBytes(ciphertext []byte) ([]byte, error)
}

// Ensure both types implement KeyEncryptor
var _ KeyEncryptor = (*Encryptor)(nil)
var _ KeyEncryptor = (*VaultEncryptor)(nil)
