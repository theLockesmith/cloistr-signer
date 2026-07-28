package crypto

import (
	"strings"
	"testing"
)

const (
	testPassphrase = "correct horse battery staple"
	testNsec       = "nsec1testkeymaterialthatmustroundtripexactly000000000000000000"
)

func newTestPassphraseEncryptor(t *testing.T, pass string) *PassphraseEncryptor {
	t.Helper()
	e, err := NewPassphraseEncryptor(pass)
	if err != nil {
		t.Fatalf("NewPassphraseEncryptor: %v", err)
	}
	return e
}

func TestPassphraseEncryptor_RoundTrip(t *testing.T) {
	e := newTestPassphraseEncryptor(t, testPassphrase)

	ct, err := e.Encrypt(testNsec)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ct, PassphrasePrefix) {
		t.Errorf("ciphertext missing %q prefix: %q", PassphrasePrefix, ct[:min(12, len(ct))])
	}
	if strings.Contains(ct, testNsec) {
		t.Fatal("plaintext key material appears in ciphertext")
	}

	got, err := e.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != testNsec {
		t.Errorf("round-trip mismatch: got %q, want %q", got, testNsec)
	}
}

// The whole point of this encryptor: without the passphrase, the data is unreadable.
func TestPassphraseEncryptor_WrongPassphraseFails(t *testing.T) {
	ct, err := newTestPassphraseEncryptor(t, testPassphrase).Encrypt(testNsec)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := newTestPassphraseEncryptor(t, "wrong passphrase").Decrypt(ct); err == nil {
		t.Fatal("decrypt succeeded with the wrong passphrase -- the security property is broken")
	}
}

// Each encryption must use a fresh random salt, so identical plaintext under the same
// passphrase never produces identical ciphertext.
func TestPassphraseEncryptor_SaltIsPerEncryption(t *testing.T) {
	e := newTestPassphraseEncryptor(t, testPassphrase)

	a, err := e.Encrypt(testNsec)
	if err != nil {
		t.Fatalf("Encrypt a: %v", err)
	}
	b, err := e.Encrypt(testNsec)
	if err != nil {
		t.Fatalf("Encrypt b: %v", err)
	}
	if a == b {
		t.Error("identical ciphertext for identical plaintext -- salt/nonce is not random per encryption")
	}

	// Both must still decrypt (salt is recovered from the ciphertext, not stored elsewhere).
	for i, ct := range []string{a, b} {
		got, err := e.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt #%d: %v", i, err)
		}
		if got != testNsec {
			t.Errorf("Decrypt #%d mismatch", i)
		}
	}
}

// A password change must re-wrap key material, or it becomes permanently unreadable.
func TestReWrap_PasswordChange(t *testing.T) {
	const newPass = "a completely different passphrase"

	ct, err := newTestPassphraseEncryptor(t, testPassphrase).Encrypt(testNsec)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	rewrapped, err := ReWrap(testPassphrase, newPass, ct)
	if err != nil {
		t.Fatalf("ReWrap: %v", err)
	}

	// Readable under the new passphrase...
	got, err := newTestPassphraseEncryptor(t, newPass).Decrypt(rewrapped)
	if err != nil {
		t.Fatalf("Decrypt after re-wrap: %v", err)
	}
	if got != testNsec {
		t.Errorf("re-wrapped plaintext mismatch: got %q, want %q", got, testNsec)
	}

	// ...and NOT under the old one.
	if _, err := newTestPassphraseEncryptor(t, testPassphrase).Decrypt(rewrapped); err == nil {
		t.Error("old passphrase still decrypts after re-wrap")
	}
}

func TestReWrap_WrongOldPassphraseFails(t *testing.T) {
	ct, err := newTestPassphraseEncryptor(t, testPassphrase).Encrypt(testNsec)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := ReWrap("not the old passphrase", "new", ct); err == nil {
		t.Fatal("ReWrap succeeded with the wrong old passphrase")
	}
}

func TestNewPassphraseEncryptor_RejectsEmpty(t *testing.T) {
	if _, err := NewPassphraseEncryptor(""); err == nil {
		t.Fatal("expected an error for an empty passphrase")
	}
}

// Detection must route pbk: to the passphrase method, and classify it as user-held so
// the signer skips it at boot instead of storing the ciphertext as a private key.
func TestDetectEncryptionMethod_Passphrase(t *testing.T) {
	ct, err := newTestPassphraseEncryptor(t, testPassphrase).Encrypt(testNsec)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if got := DetectEncryptionMethod(ct); got != EncryptionMethodPassphrase {
		t.Errorf("DetectEncryptionMethod = %q, want %q", got, EncryptionMethodPassphrase)
	}
	if !IsPassphraseEncrypted(ct) {
		t.Error("IsPassphraseEncrypted = false for pbk: ciphertext")
	}
	if !DetectEncryptionMethod(ct).UserHeld() {
		t.Error("passphrase ciphertext must be UserHeld (server cannot decrypt alone)")
	}
}

func TestEncryptionMethod_UserHeld(t *testing.T) {
	cases := map[EncryptionMethod]bool{
		EncryptionMethodVault:      true,
		EncryptionMethodPassphrase: true,
		EncryptionMethodLocal:      false, // server-held ENCRYPTION_KEY -- decryptable alone
	}
	for method, want := range cases {
		if got := method.UserHeld(); got != want {
			t.Errorf("%s.UserHeld() = %v, want %v", method, got, want)
		}
	}
}

// Guard the classification boundary: a pbk: value must never be seen as "local", which
// would send it down the enc: path and get it stored verbatim as a private key.
func TestPassphraseCiphertext_NotMisclassifiedAsLocal(t *testing.T) {
	ct, err := newTestPassphraseEncryptor(t, testPassphrase).Encrypt(testNsec)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if IsEncrypted(ct) {
		t.Error("pbk: ciphertext matched IsEncrypted (enc:) -- would be mishandled at boot")
	}
	if IsVaultEncrypted(ct) {
		t.Error("pbk: ciphertext matched IsVaultEncrypted")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
