package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
)

// PassphraseEncryptor encrypts key material under a KEK derived from the user's login
// passphrase (PBKDF2-HMAC-SHA-256), giving self-hosters the same security property as
// Vault transit -- the server cannot decrypt a user's key without that user -- with no
// external dependency.
//
// This exists so that the strong posture is NOT gated behind running a Vault. The three
// KeyEncryptor implementations line up as:
//
//	Encryptor           local AES-GCM under a server-held ENCRYPTION_KEY
//	                    -> server CAN decrypt alone. Legacy; do not use for new keys.
//	VaultEncryptor      Vault transit under the user's own token (userpass)
//	                    -> server CANNOT decrypt alone. Requires a Vault.
//	PassphraseEncryptor PBKDF2 KEK from the user's passphrase
//	                    -> server CANNOT decrypt alone. Requires nothing.
//
// Ciphertext format:  pbk:<base64( salt[16] || nonce[12] || aesgcm_ciphertext )>
//
// The salt is random per encryption and stored inline, so there is no salt registry to
// keep in sync and every key can be re-wrapped independently.
//
// IMPORTANT (see cloistr-password-reset-recovery-gap): the passphrase is cryptographically
// load-bearing here. A password change MUST re-wrap every key encrypted under the old
// passphrase (see ReWrap) or the material becomes unreadable, and a forgotten passphrase
// means the key is unrecoverable by anyone, including the operator. That is the intended
// trade-off -- it is what "the server cannot decrypt without you" actually costs.
type PassphraseEncryptor struct {
	passphrase string
}

const (
	// PassphrasePrefix identifies passphrase-KEK ciphertext.
	PassphrasePrefix = "pbk:"

	// pbkdf2Iterations matches the browser-side IndexedDB/FROST-share discipline
	// (600k, OWASP-recommended for PBKDF2-HMAC-SHA-256).
	pbkdf2Iterations = 600_000

	pbkdf2SaltLen = 16 // 128-bit salt, stored inline with the ciphertext
	pbkdf2KeyLen  = 32 // AES-256
)

// ErrEmptyPassphrase is returned when constructing an encryptor with no passphrase.
var ErrEmptyPassphrase = errors.New("passphrase must not be empty")

// NewPassphraseEncryptor creates an encryptor bound to a user's passphrase.
// The passphrase is held only for the lifetime of this value; callers should scope it
// to an authenticated session and release it on logout, exactly as Vault tokens are.
func NewPassphraseEncryptor(passphrase string) (*PassphraseEncryptor, error) {
	if passphrase == "" {
		return nil, ErrEmptyPassphrase
	}
	return &PassphraseEncryptor{passphrase: passphrase}, nil
}

// IsPassphraseEncrypted reports whether a value was encrypted with a passphrase KEK.
func IsPassphraseEncrypted(value string) bool {
	return strings.HasPrefix(value, PassphrasePrefix)
}

// deriveKEK stretches the passphrase into an AES-256 key using the given salt.
func (p *PassphraseEncryptor) deriveKEK(salt []byte) []byte {
	return pbkdf2.Key([]byte(p.passphrase), salt, pbkdf2Iterations, pbkdf2KeyLen, sha256.New)
}

// EncryptBytes encrypts plaintext under a freshly-salted passphrase-derived KEK.
func (p *PassphraseEncryptor) EncryptBytes(plaintext []byte) ([]byte, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	gcm, err := newGCM(p.deriveKEK(salt))
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// salt || nonce || ciphertext -- Seal appends to the nonce prefix.
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return append(salt, sealed...), nil
}

// DecryptBytes reverses EncryptBytes, recovering the salt from the ciphertext.
func (p *PassphraseEncryptor) DecryptBytes(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < pbkdf2SaltLen {
		return nil, fmt.Errorf("%w: too short for salt", ErrInvalidCiphertext)
	}
	salt, rest := ciphertext[:pbkdf2SaltLen], ciphertext[pbkdf2SaltLen:]

	gcm, err := newGCM(p.deriveKEK(salt))
	if err != nil {
		return nil, err
	}

	if len(rest) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: too short for nonce", ErrInvalidCiphertext)
	}
	nonce, sealed := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		// Wrong passphrase is indistinguishable from tampering, by design.
		return nil, fmt.Errorf("%w: authentication failed (wrong passphrase or corrupt data)", ErrInvalidCiphertext)
	}
	return plaintext, nil
}

// Encrypt encrypts plaintext and returns it base64-encoded with the "pbk:" prefix.
func (p *PassphraseEncryptor) Encrypt(plaintext string) (string, error) {
	raw, err := p.EncryptBytes([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return PassphrasePrefix + base64.StdEncoding.EncodeToString(raw), nil
}

// Decrypt decrypts ciphertext produced by Encrypt, with or without the prefix.
func (p *PassphraseEncryptor) Decrypt(ciphertext string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, PassphrasePrefix))
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidCiphertext, err)
	}
	plaintext, err := p.DecryptBytes(raw)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ReWrap re-encrypts ciphertext from the old passphrase to a new one. This MUST be
// called for every key a user owns whenever their password changes -- the KEK is derived
// from the passphrase, so without it the material becomes permanently unreadable.
//
// It is a package-level function rather than a method so the caller must hold both
// passphrases explicitly, making the requirement hard to overlook.
func ReWrap(oldPassphrase, newPassphrase, ciphertext string) (string, error) {
	oldEnc, err := NewPassphraseEncryptor(oldPassphrase)
	if err != nil {
		return "", fmt.Errorf("old passphrase: %w", err)
	}
	newEnc, err := NewPassphraseEncryptor(newPassphrase)
	if err != nil {
		return "", fmt.Errorf("new passphrase: %w", err)
	}

	plaintext, err := oldEnc.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("re-wrap failed to decrypt under old passphrase: %w", err)
	}
	return newEnc.Encrypt(plaintext)
}

// newGCM builds an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}

// Ensure PassphraseEncryptor satisfies the same seam as the other two.
var _ KeyEncryptor = (*PassphraseEncryptor)(nil)
