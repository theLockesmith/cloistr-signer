package api

import (
	"context"
	"strings"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// The property under test: a key minted during registration must not be
// decryptable by the server alone.
//
// createInitialSigningKey is the only place a brand-new account's Primary key is
// written, and nothing migrates it afterwards -- loadUserVaultKeys skips anything
// that is not already Vault ciphertext. So whatever this function chooses is what
// the key is wrapped with for its entire life.

func newWrapTestHandler(t *testing.T, serverKey string) (*Handler, storage.Storage) {
	t.Helper()
	store := storage.NewMemoryStorage()
	cfg := &config.Config{Relays: []string{"wss://relay.example.com"}}

	var enc *crypto.Encryptor
	if serverKey != "" {
		var err error
		enc, err = crypto.NewEncryptor(serverKey)
		if err != nil {
			t.Fatalf("NewEncryptor: %v", err)
		}
	}
	s := signer.New(cfg, store, nil, enc, nil, nil, nil)
	return &Handler{config: cfg, storage: store, signer: s, encryptor: enc}, store
}

func TestCreateInitialSigningKey_WrapsUnderPassphraseNotServerKey(t *testing.T) {
	ctx := context.Background()
	serverKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	h, _ := newWrapTestHandler(t, serverKey)

	const passphrase = "correct horse battery staple"
	key, err := h.createInitialSigningKey(ctx, "owner-1", "Primary", "", passphrase)
	if err != nil {
		t.Fatalf("createInitialSigningKey: %v", err)
	}

	if !crypto.IsPassphraseEncrypted(key.EncryptedNsec) {
		t.Fatalf("key is not passphrase-wrapped: %.12s...", key.EncryptedNsec)
	}
	if crypto.IsEncrypted(key.EncryptedNsec) {
		t.Error("key carries the server-held enc: prefix")
	}
	if got, want := key.EncryptionMethod, string(crypto.EncryptionMethodPassphrase); got != want {
		t.Errorf("EncryptionMethod = %q, want %q", got, want)
	}

	// The whole point: the server's own encryptor must not be able to open it.
	if _, err := h.encryptor.Decrypt(key.EncryptedNsec); err == nil {
		t.Error("the server-held encryptor decrypted the key — it is still custodial")
	}

	// And the passphrase must.
	pe, err := crypto.NewPassphraseEncryptor(passphrase)
	if err != nil {
		t.Fatalf("NewPassphraseEncryptor: %v", err)
	}
	priv, err := pe.Decrypt(key.EncryptedNsec)
	if err != nil {
		t.Fatalf("passphrase decrypt failed: %v", err)
	}
	if len(priv) != 64 {
		t.Errorf("decrypted private key length = %d, want 64 hex chars", len(priv))
	}
}

// The method string is what signer.Start() consults via DetectEncryptionMethod /
// UserHeld() to decide whether to skip a key at boot. A registration key must be
// classified user-held, or startup would treat the ciphertext as a private key.
func TestCreateInitialSigningKey_IsClassifiedUserHeld(t *testing.T) {
	ctx := context.Background()
	h, _ := newWrapTestHandler(t, "")

	key, err := h.createInitialSigningKey(ctx, "owner-1", "Primary", "", "a passphrase")
	if err != nil {
		t.Fatalf("createInitialSigningKey: %v", err)
	}
	method := crypto.DetectEncryptionMethod(key.EncryptedNsec)
	if method != crypto.EncryptionMethodPassphrase {
		t.Errorf("DetectEncryptionMethod = %q, want %q", method, crypto.EncryptionMethodPassphrase)
	}
	if !method.UserHeld() {
		t.Error("registration key is not classified user-held; startup would mis-handle it")
	}
}

// Importing an existing nsec must get the same treatment — arguably more so,
// since that key already has value outside this system.
func TestCreateInitialSigningKey_ImportedKeyAlsoPassphraseWrapped(t *testing.T) {
	ctx := context.Background()
	serverKey, _ := crypto.GenerateKey()
	h, _ := newWrapTestHandler(t, serverKey)

	const passphrase = "another passphrase"
	// A known-good hex private key.
	const imported = "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a"

	key, err := h.createInitialSigningKey(ctx, "owner-2", "Primary", imported, passphrase)
	if err != nil {
		t.Fatalf("createInitialSigningKey: %v", err)
	}
	if !crypto.IsPassphraseEncrypted(key.EncryptedNsec) {
		t.Fatalf("imported key is not passphrase-wrapped: %.12s...", key.EncryptedNsec)
	}
	pe, _ := crypto.NewPassphraseEncryptor(passphrase)
	priv, err := pe.Decrypt(key.EncryptedNsec)
	if err != nil {
		t.Fatalf("passphrase decrypt failed: %v", err)
	}
	if priv != imported {
		t.Error("round-trip did not return the imported private key")
	}
}

// With no passphrase there is no user-held option, so the server key is the only
// way to avoid storing plaintext. That path survives deliberately — but it must
// stay the fallback, not the default.
func TestCreateInitialSigningKey_FallsBackToServerKeyWithoutPassphrase(t *testing.T) {
	ctx := context.Background()
	serverKey, _ := crypto.GenerateKey()
	h, _ := newWrapTestHandler(t, serverKey)

	key, err := h.createInitialSigningKey(ctx, "owner-3", "Primary", "", "")
	if err != nil {
		t.Fatalf("createInitialSigningKey: %v", err)
	}
	if !crypto.IsEncrypted(key.EncryptedNsec) {
		t.Errorf("expected server-held enc: fallback, got %.12s...", key.EncryptedNsec)
	}
	if crypto.IsPassphraseEncrypted(key.EncryptedNsec) {
		t.Error("claimed passphrase wrapping with no passphrase supplied")
	}
	// Never plaintext, whatever else happens.
	if !strings.Contains(key.EncryptedNsec, ":") {
		t.Error("private key appears to be stored unencrypted")
	}
}

// loadUserPassphraseKeys is the counterpart: without it a registration key is
// wrapped correctly but never usable, because user-held keys are skipped at boot.
func TestLoadUserPassphraseKeys_RegistersKeyInSignerRuntime(t *testing.T) {
	ctx := context.Background()
	h, _ := newWrapTestHandler(t, "")

	const passphrase = "load me"
	key, err := h.createInitialSigningKey(ctx, "owner-4", "Primary", "", passphrase)
	if err != nil {
		t.Fatalf("createInitialSigningKey: %v", err)
	}
	// createInitialSigningKey registers it eagerly; drop it so the load is what counts.
	h.signer.UnregisterKey(key.Pubkey)
	if h.signer.IsKeyLoaded(key.Pubkey) {
		t.Fatal("precondition failed: key still loaded after unregister")
	}

	h.loadUserPassphraseKeys(ctx, "owner-4", passphrase)
	if !h.signer.IsKeyLoaded(key.Pubkey) {
		t.Error("passphrase-wrapped key was not loaded into the signer runtime")
	}
}

func TestLoadUserPassphraseKeys_WrongPassphraseLoadsNothing(t *testing.T) {
	ctx := context.Background()
	h, _ := newWrapTestHandler(t, "")

	key, err := h.createInitialSigningKey(ctx, "owner-5", "Primary", "", "right")
	if err != nil {
		t.Fatalf("createInitialSigningKey: %v", err)
	}
	h.signer.UnregisterKey(key.Pubkey)

	h.loadUserPassphraseKeys(ctx, "owner-5", "wrong")
	if h.signer.IsKeyLoaded(key.Pubkey) {
		t.Error("a wrong passphrase loaded the key — the KEK is not actually gating decryption")
	}

	// An empty passphrase must be a no-op rather than an error path.
	h.loadUserPassphraseKeys(ctx, "owner-5", "")
	if h.signer.IsKeyLoaded(key.Pubkey) {
		t.Error("an empty passphrase loaded the key")
	}
}
