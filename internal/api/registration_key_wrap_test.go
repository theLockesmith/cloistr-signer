package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

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

// Legacy drain: existing accounts hold "enc:" keys the server can open. They
// cannot be migrated by a batch job, because re-wrapping needs the passphrase and
// the server never holds it outside an authenticated request — so the migration
// rides the login that supplies it.

// seedLegacyKey writes a key wrapped with the server-held encryptor, as every
// pre-fix registration did.
func seedLegacyKey(t *testing.T, h *Handler, store storage.Storage, ownerID string) *storage.Key {
	t.Helper()
	priv := "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a"
	pub, err := nostr.GetPublicKey(priv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	ct, err := h.encryptor.Encrypt(priv)
	if err != nil {
		t.Fatalf("server encrypt: %v", err)
	}
	key := &storage.Key{
		ID: pub[:16], Name: "Primary", Pubkey: pub, KeyType: storage.KeyTypeLocal,
		EncryptedNsec: ct, EncryptionMethod: string(crypto.EncryptionMethodLocal),
		CreatedAt: time.Now(), OwnerID: ownerID,
	}
	if err := store.CreateKey(context.Background(), key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return key
}

func TestRewrapLegacyLocalKeys_MigratesAndServerCanNoLongerDecrypt(t *testing.T) {
	ctx := context.Background()
	serverKey, _ := crypto.GenerateKey()
	h, store := newWrapTestHandler(t, serverKey)
	seeded := seedLegacyKey(t, h, store, "owner-legacy")

	const passphrase = "the user's password"
	if n := h.rewrapLegacyLocalKeys(ctx, "owner-legacy", passphrase); n != 1 {
		t.Fatalf("migrated %d keys, want 1", n)
	}

	got, err := store.GetKey(ctx, seeded.ID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if !crypto.IsPassphraseEncrypted(got.EncryptedNsec) {
		t.Fatalf("key was not re-wrapped: %.12s...", got.EncryptedNsec)
	}
	if got.EncryptionMethod != string(crypto.EncryptionMethodPassphrase) {
		t.Errorf("EncryptionMethod = %q, want passphrase", got.EncryptionMethod)
	}
	if _, err := h.encryptor.Decrypt(got.EncryptedNsec); err == nil {
		t.Error("the server can still decrypt the migrated key")
	}
	pe, _ := crypto.NewPassphraseEncryptor(passphrase)
	if priv, err := pe.Decrypt(got.EncryptedNsec); err != nil || priv != "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a" {
		t.Errorf("migrated key does not round-trip to the original private key (err=%v)", err)
	}
	// "enc:" keys are loaded at boot; "pbk:" ones are skipped, so the migration
	// must hand the key to the runtime itself.
	if !h.signer.IsKeyLoaded(got.Pubkey) {
		t.Error("migrated key was not registered in the signer runtime")
	}
}

func TestRewrapLegacyLocalKeys_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	serverKey, _ := crypto.GenerateKey()
	h, store := newWrapTestHandler(t, serverKey)
	seeded := seedLegacyKey(t, h, store, "owner-idem")

	if n := h.rewrapLegacyLocalKeys(ctx, "owner-idem", "pw"); n != 1 {
		t.Fatalf("first pass migrated %d, want 1", n)
	}
	first, _ := store.GetKey(ctx, seeded.ID)

	if n := h.rewrapLegacyLocalKeys(ctx, "owner-idem", "pw"); n != 0 {
		t.Errorf("second pass migrated %d, want 0", n)
	}
	second, _ := store.GetKey(ctx, seeded.ID)
	if first.EncryptedNsec != second.EncryptedNsec {
		t.Error("a second pass re-wrapped an already-migrated key")
	}
}

// A key whose plaintext doesn't derive its stored pubkey must be left alone, not
// "migrated" into ciphertext nobody can check.
func TestRewrapLegacyLocalKeys_LeavesMismatchedKeyUntouched(t *testing.T) {
	ctx := context.Background()
	serverKey, _ := crypto.GenerateKey()
	h, store := newWrapTestHandler(t, serverKey)

	priv := "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a"
	ct, _ := h.encryptor.Encrypt(priv)
	bogus := &storage.Key{
		ID: "bogus-id", Name: "Primary",
		Pubkey:        "0000000000000000000000000000000000000000000000000000000000000000",
		KeyType:       storage.KeyTypeLocal,
		EncryptedNsec: ct, EncryptionMethod: string(crypto.EncryptionMethodLocal),
		CreatedAt: time.Now(), OwnerID: "owner-bad",
	}
	if err := store.CreateKey(ctx, bogus); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	if n := h.rewrapLegacyLocalKeys(ctx, "owner-bad", "pw"); n != 0 {
		t.Errorf("migrated %d mismatched keys, want 0", n)
	}
	got, _ := store.GetKey(ctx, "bogus-id")
	if got.EncryptedNsec != ct {
		t.Error("mismatched key was modified; the original ciphertext must be retained")
	}
}

// Vault-wrapped and already-passphrase-wrapped keys are user-held already and
// must not be dragged through the legacy path.
func TestRewrapLegacyLocalKeys_SkipsUserHeldKeys(t *testing.T) {
	ctx := context.Background()
	serverKey, _ := crypto.GenerateKey()
	h, store := newWrapTestHandler(t, serverKey)

	for i, ct := range []string{
		"vault:v1:abcdef",
		"pbk:YWJjZGVm",
	} {
		k := &storage.Key{
			ID: string(rune('a' + i)), Name: "K", Pubkey: strings.Repeat(string(rune('0'+i)), 64),
			KeyType: storage.KeyTypeLocal, EncryptedNsec: ct,
			CreatedAt: time.Now(), OwnerID: "owner-userheld",
		}
		if err := store.CreateKey(ctx, k); err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
	}

	if n := h.rewrapLegacyLocalKeys(ctx, "owner-userheld", "pw"); n != 0 {
		t.Errorf("migrated %d user-held keys, want 0", n)
	}
	for i, want := range []string{"vault:v1:abcdef", "pbk:YWJjZGVm"} {
		got, err := store.GetKey(ctx, string(rune('a'+i)))
		if err != nil {
			t.Fatalf("GetKey: %v", err)
		}
		if got.EncryptedNsec != want {
			t.Errorf("user-held key %d was modified: %q", i, got.EncryptedNsec)
		}
	}
}

// Without a passphrase (or without a server encryptor to open the legacy
// ciphertext) the migration must be a no-op rather than an error path.
func TestRewrapLegacyLocalKeys_NoOpWithoutPassphraseOrEncryptor(t *testing.T) {
	ctx := context.Background()
	serverKey, _ := crypto.GenerateKey()
	h, store := newWrapTestHandler(t, serverKey)
	seeded := seedLegacyKey(t, h, store, "owner-noop")

	if n := h.rewrapLegacyLocalKeys(ctx, "owner-noop", ""); n != 0 {
		t.Errorf("migrated %d with no passphrase, want 0", n)
	}
	noEnc, _ := newWrapTestHandler(t, "")
	if n := noEnc.rewrapLegacyLocalKeys(ctx, "owner-noop", "pw"); n != 0 {
		t.Errorf("migrated %d with no server encryptor, want 0", n)
	}
	got, _ := store.GetKey(ctx, seeded.ID)
	if !crypto.IsEncrypted(got.EncryptedNsec) {
		t.Error("legacy key was altered by a no-op call")
	}
}
