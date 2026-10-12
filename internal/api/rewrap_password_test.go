package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

const (
	rwOldPass = "old passphrase for rewrap tests"
	rwNewPass = "new passphrase for rewrap tests"
	rwNsec    = "nsec1rewraptestkeymaterial00000000000000000000000000000000000"
)

// seedPassphraseKey stores a key wrapped under the given passphrase.
func seedPassphraseKey(t *testing.T, store storage.Storage, id, owner, passphrase, plaintext string) *storage.Key {
	t.Helper()
	enc, err := crypto.NewPassphraseEncryptor(passphrase)
	if err != nil {
		t.Fatalf("NewPassphraseEncryptor: %v", err)
	}
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	k := &storage.Key{
		ID:               id,
		Name:             "Primary",
		Pubkey:           id + "-pubkey",
		KeyType:          "local",
		EncryptedNsec:    ct,
		EncryptionMethod: string(crypto.EncryptionMethodPassphrase),
		OwnerID:          owner,
		CreatedBy:        owner,
	}
	if err := store.CreateKey(context.Background(), k); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return k
}

// The core invariant: after a password change, passphrase-wrapped key material must be
// readable under the NEW passphrase. If this regresses, users silently destroy their own
// keys by changing their password.
func TestRewrapPassphraseKeys_ReadableUnderNewPassphrase(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	seedPassphraseKey(t, store, "key-1", testUserID, rwOldPass, rwNsec)

	_, count, err := h.rewrapPassphraseKeys(ctx, testUserID, rwOldPass, rwNewPass)
	if err != nil {
		t.Fatalf("rewrapPassphraseKeys: %v", err)
	}
	if count != 1 {
		t.Fatalf("re-wrapped %d keys, want 1", count)
	}

	got, err := store.GetKey(ctx, "key-1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}

	newEnc, _ := crypto.NewPassphraseEncryptor(rwNewPass)
	plaintext, err := newEnc.Decrypt(got.EncryptedNsec)
	if err != nil {
		t.Fatalf("key not readable under the NEW passphrase: %v", err)
	}
	if plaintext != rwNsec {
		t.Errorf("plaintext = %q, want %q", plaintext, rwNsec)
	}

	// And must NOT be readable under the old one.
	oldEnc, _ := crypto.NewPassphraseEncryptor(rwOldPass)
	if _, err := oldEnc.Decrypt(got.EncryptedNsec); err == nil {
		t.Error("key still decrypts under the OLD passphrase after re-wrap")
	}
}

// Vault- and local-encrypted keys are not tied to the passphrase and must be left alone.
func TestRewrapPassphraseKeys_LeavesOtherMethodsUntouched(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	const vaultCT = "vault:v1:someopaquevaultciphertext"
	const localCT = "enc:c29tZWxvY2FsY2lwaGVydGV4dA=="

	for id, ct := range map[string]string{"vault-key": vaultCT, "local-key": localCT} {
		if err := store.CreateKey(ctx, &storage.Key{
			ID: id, Name: "k", Pubkey: id + "-pub", KeyType: "local",
			EncryptedNsec: ct, OwnerID: testUserID, CreatedBy: testUserID,
		}); err != nil {
			t.Fatalf("CreateKey %s: %v", id, err)
		}
	}

	_, count, err := h.rewrapPassphraseKeys(ctx, testUserID, rwOldPass, rwNewPass)
	if err != nil {
		t.Fatalf("rewrapPassphraseKeys: %v", err)
	}
	if count != 0 {
		t.Errorf("re-wrapped %d keys, want 0 (no passphrase keys present)", count)
	}

	for id, want := range map[string]string{"vault-key": vaultCT, "local-key": localCT} {
		got, err := store.GetKey(ctx, id)
		if err != nil {
			t.Fatalf("GetKey %s: %v", id, err)
		}
		if got.EncryptedNsec != want {
			t.Errorf("%s ciphertext was modified: got %q, want %q", id, got.EncryptedNsec, want)
		}
	}
}

// A wrong current passphrase must abort before ANY key is written (all-or-nothing), so a
// failed attempt can never leave keys split across two passphrases.
func TestRewrapPassphraseKeys_WrongPassphraseWritesNothing(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	k1 := seedPassphraseKey(t, store, "key-a", testUserID, rwOldPass, rwNsec)
	k2 := seedPassphraseKey(t, store, "key-b", testUserID, rwOldPass, rwNsec)
	before := map[string]string{"key-a": k1.EncryptedNsec, "key-b": k2.EncryptedNsec}

	if _, _, err := h.rewrapPassphraseKeys(ctx, testUserID, "the wrong passphrase", rwNewPass); err == nil {
		t.Fatal("expected an error re-wrapping with the wrong old passphrase")
	}

	for id, want := range before {
		got, err := store.GetKey(ctx, id)
		if err != nil {
			t.Fatalf("GetKey %s: %v", id, err)
		}
		if got.EncryptedNsec != want {
			t.Errorf("%s was modified despite the failure -- re-wrap is not all-or-nothing", id)
		}
	}
}

// The rollback closure must restore the previous ciphertext, so a failed password commit
// cannot strand keys under a passphrase the account does not have.
func TestRewrapPassphraseKeys_RollbackRestoresOldCiphertext(t *testing.T) {
	h, store := testHandler(t)
	ctx := context.Background()

	k := seedPassphraseKey(t, store, "key-rb", testUserID, rwOldPass, rwNsec)
	original := k.EncryptedNsec

	rollback, count, err := h.rewrapPassphraseKeys(ctx, testUserID, rwOldPass, rwNewPass)
	if err != nil || count != 1 {
		t.Fatalf("rewrapPassphraseKeys: count=%d err=%v", count, err)
	}
	if rollback == nil {
		t.Fatal("expected a rollback func")
	}

	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	got, err := store.GetKey(ctx, "key-rb")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.EncryptedNsec != original {
		t.Error("rollback did not restore the original ciphertext")
	}

	oldEnc, _ := crypto.NewPassphraseEncryptor(rwOldPass)
	if _, err := oldEnc.Decrypt(got.EncryptedNsec); err != nil {
		t.Errorf("after rollback the key is not readable under the old passphrase: %v", err)
	}
}

// The same invariants on a SQL backend. MemoryStorage.UpdateKey stores the whole
// struct, so a re-wrap persisted through it passed every test above while SQLite
// and Postgres silently dropped the new ciphertext.
func sqliteRewrapHandler(t *testing.T) (*Handler, storage.Storage) {
	t.Helper()
	h, _ := testHandler(t)
	store, err := storage.NewSQLiteStorage(filepath.Join(t.TempDir(), "signer.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.CreateUser(context.Background(), &storage.User{
		ID: testUserID, Username: "rewrap-user", PasswordHash: "x", Role: "user",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	h.storage = store
	return h, store
}

func TestRewrapPassphraseKeys_PersistsOnSQL(t *testing.T) {
	h, store := sqliteRewrapHandler(t)
	ctx := context.Background()
	k := seedPassphraseKey(t, store, "key-sql", testUserID, rwOldPass, rwNsec)
	original := k.EncryptedNsec

	rollback, count, err := h.rewrapPassphraseKeys(ctx, testUserID, rwOldPass, rwNewPass)
	if err != nil || count != 1 {
		t.Fatalf("rewrapPassphraseKeys: count=%d err=%v", count, err)
	}
	got, err := store.GetKey(ctx, "key-sql")
	if err != nil {
		t.Fatal(err)
	}
	newEnc, _ := crypto.NewPassphraseEncryptor(rwNewPass)
	if pt, err := newEnc.Decrypt(got.EncryptedNsec); err != nil || pt != rwNsec {
		t.Fatalf("stored key not readable under the NEW passphrase: %v", err)
	}

	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, _ = store.GetKey(ctx, "key-sql")
	if got.EncryptedNsec != original {
		t.Fatal("rollback did not restore the stored ciphertext")
	}
}
