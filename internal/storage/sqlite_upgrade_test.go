package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// oldSchemaDB writes a database the way the first SQLite version (73f9ecb,
// 2026-04-28) left it: its schema, an account, a key, and grants as they
// could exist then (key_id holding the key's id, as its foreign key required,
// or its pubkey, written with foreign keys off), plus one naming no key.
func oldSchemaDB(t *testing.T) (path, keyPub string) {
	t.Helper()
	schema, err := os.ReadFile("testdata/sqlite_schema_73f9ecb.sql")
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyPub = "1111111111111111111111111111111111111111111111111111111111111111"
	for _, q := range []string{
		string(schema),
		`INSERT INTO signer_web_accounts (id, username, password_hash) VALUES ('owner', 'owner', 'x')`,
		`INSERT INTO signer_keys (id, name, pubkey, owner_id) VALUES ('key-a', 'a', '` + keyPub + `', 'owner')`,
		`INSERT INTO signer_permissions (key_id, user_pubkey, methods, created_at, last_used_at) VALUES ('key-a', 'older-client', '["sign_event"]', '2026-05-01T00:00:00Z', '2026-05-02T00:00:00Z')`,
		`INSERT INTO signer_permissions (key_id, user_pubkey, methods, created_at, last_used_at) VALUES ('` + keyPub + `', 'newer-client', '["sign_event"]', '2026-05-01T00:00:00Z', '2026-06-01T00:00:00Z')`,
		`INSERT INTO signer_permissions (key_id, user_pubkey, methods) VALUES ('no-such-key', 'orphan-client', '["ping"]')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("build old database: %v\n%s", err, q)
		}
	}
	return path, keyPub
}

// Opening a database made by the first SQLite version brings it up to the
// current schema: new columns added with their defaults, the grants table
// rebuilt onto the key's pubkey, one live grant per slot, and the new code
// paths work on it. Before the upgrade path, opening it failed outright
// (the current schema's indexes name columns the old tables lack).
func TestSQLiteUpgrade_FromFirstSchema(t *testing.T) {
	path, keyPub := oldSchemaDB(t)
	ctx := context.Background()

	s, err := NewSQLiteStorage(path)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}

	key, err := s.GetKey(ctx, "key-a")
	if err != nil || key.Pubkey != keyPub || key.IsPrimary || key.DisposableMode {
		t.Fatalf("GetKey after upgrade = %+v, %v; want the key with new flags at their defaults", key, err)
	}
	if err := s.SetPrimaryKey(ctx, "owner", "key-a"); err != nil {
		t.Fatalf("SetPrimaryKey (new column): %v", err)
	}

	// Both carried grants resolve to the pubkey; the less recently used one
	// is revoked so the slot holds one live grant; the orphan is gone.
	if p, err := s.GetPermission(ctx, keyPub, "newer-client"); err != nil || p.Slot != SlotDefault {
		t.Fatalf("newer grant = %+v, %v; want live in the default slot", p, err)
	}
	if _, err := s.GetPermission(ctx, keyPub, "older-client"); err == nil {
		t.Fatal("older grant is still live; two live grants in one slot")
	}
	var notPubkey int
	if err := s.db.QueryRow(`SELECT count(*) FROM signer_permissions WHERE key_id != ?`, keyPub).Scan(&notPubkey); err != nil || notPubkey != 0 {
		t.Fatalf("%d grant rows keep a key_id that is not the key's pubkey (%v)", notPubkey, err)
	}
	var orphans int
	if err := s.db.QueryRow(`SELECT count(*) FROM signer_permissions WHERE user_pubkey = 'orphan-client'`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("orphan grant rows = %d, %v; want 0", orphans, err)
	}

	// Writing a grant works: the foreign key now references the pubkey.
	exp := time.Now().Add(time.Hour)
	if err := s.SetPermission(ctx, &Permission{KeyID: keyPub, UserPubkey: "publisher-client", Slot: SlotPublisher, Methods: []string{"sign_event"}, ExpiresAt: &exp}); err != nil {
		t.Fatalf("SetPermission on upgraded database: %v", err)
	}
	s.Close()

	// A second start changes nothing: no grant is revoked again.
	s, err = NewSQLiteStorage(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	for _, client := range []string{"newer-client", "publisher-client"} {
		if _, err := s.GetPermission(ctx, keyPub, client); err != nil {
			t.Errorf("%s lost its grant on restart: %v", client, err)
		}
	}
	var fkTarget string
	if err := s.db.QueryRow(`SELECT "to" FROM pragma_foreign_key_list('signer_permissions')`).Scan(&fkTarget); err != nil || fkTarget != "pubkey" {
		t.Fatalf("grants foreign key references %q (%v), want pubkey", fkTarget, err)
	}
}
