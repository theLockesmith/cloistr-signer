package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// oldSchemaDB writes a database the way the first SQLite version (73f9ecb,
// 2026-04-28) left it: its schema, an account, a key, and grants as they
// could exist then (key_id holding the key's id, as its foreign key required,
// or its pubkey, written with foreign keys off), plus one naming no key. The
// account is named username: the fleet account's keys become single-grant.
func oldSchemaDB(t *testing.T, username string) (path, keyPub string) {
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
		`INSERT INTO signer_web_accounts (id, username, password_hash) VALUES ('owner', '` + username + `', 'x')`,
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
	path, keyPub := oldSchemaDB(t, FleetAccountUsername)
	ctx := context.Background()

	s, err := NewSQLiteStorage(path)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}

	key, err := s.GetKey(ctx, "key-a")
	if err != nil || key.Pubkey != keyPub || key.IsPrimary || key.DisposableMode || !key.SingleGrant {
		t.Fatalf("GetKey after upgrade = %+v, %v; want the key with new flags at their defaults, single-grant (fleet account)", key, err)
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

// captureLogs sends slog output to a buffer for the test's duration.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func logLines(t *testing.T, buf *bytes.Buffer, msgPrefix string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if m, _ := rec["msg"].(string); strings.HasPrefix(m, msgPrefix) {
			out = append(out, rec)
		}
	}
	return out
}

// Before an upgrade changes anything, the database is copied beside itself
// as it was (old schema, every row, the orphan included), and each grant the
// upgrade drops or retires is logged by key and client. A second start, with
// nothing left to upgrade, takes no new backup.
func TestSQLiteUpgrade_BacksUpAndLogsWhatItRemoves(t *testing.T) {
	path, keyPub := oldSchemaDB(t, FleetAccountUsername)
	logs := captureLogs(t)

	s, err := NewSQLiteStorage(path)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}
	s.Close()

	backups, _ := filepath.Glob(path + ".pre-upgrade-*.bak")
	if len(backups) != 1 {
		t.Fatalf("backups beside the database = %v, want exactly one", backups)
	}
	logged := logLines(t, logs, "sqlite upgrade: database backed up")
	if len(logged) != 1 || logged[0]["backup"] != backups[0] {
		t.Fatalf("backup log lines = %v, want one naming %s", logged, backups[0])
	}

	// The backup is the database as it was: old schema, all three grants.
	b, err := sql.Open("sqlite", backups[0])
	if err != nil {
		t.Fatal(err)
	}
	var hasPrimary, grants int
	if err := b.QueryRow(`SELECT count(*) FROM pragma_table_info('signer_keys') WHERE name = 'is_primary'`).Scan(&hasPrimary); err != nil {
		t.Fatal(err)
	}
	if err := b.QueryRow(`SELECT count(*) FROM signer_permissions`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if hasPrimary != 0 || grants != 3 {
		t.Fatalf("backup has is_primary=%d grants=%d, want the old schema (0) and all 3 grants", hasPrimary, grants)
	}

	dropped := logLines(t, logs, "sqlite upgrade: dropped grant")
	if len(dropped) != 1 || dropped[0]["key_id"] != "no-such-key" || dropped[0]["client_pubkey"] != "orphan-client" {
		t.Fatalf("dropped-grant log lines = %v, want exactly the orphan (no-such-key / orphan-client)", dropped)
	}
	retired := logLines(t, logs, "sqlite upgrade: retired")
	if len(retired) != 1 || retired[0]["key_id"] != keyPub || retired[0]["slot"] != SlotDefault || retired[0]["client_pubkey"] != "older-client" {
		t.Fatalf("retired-grant log lines = %v, want exactly older-client in the default slot", retired)
	}

	// Nothing left to upgrade: no second backup, nothing more logged.
	logs.Reset()
	s, err = NewSQLiteStorage(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s.Close()
	if again, _ := filepath.Glob(path + ".pre-upgrade-*.bak"); len(again) != 1 {
		t.Fatalf("backups after a second start = %v, want still one", again)
	}
	if n := len(logLines(t, logs, "sqlite upgrade:")); n != 0 {
		t.Fatalf("second start logged %d upgrade lines, want none: %s", n, logs.String())
	}
}

// A database this version created needs no upgrade and gets no backup.
func TestSQLiteUpgrade_CurrentDatabaseNotBackedUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	for i := 0; i < 2; i++ {
		s, err := NewSQLiteStorage(path)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	if b, _ := filepath.Glob(path + ".pre-upgrade-*.bak"); len(b) != 0 {
		t.Fatalf("a current database was backed up: %v", b)
	}
}

// Two signer processes starting at once on an old database (a restart that
// overlaps the old pod, two containers on one volume): both must start. Each
// NewSQLiteStorage has its own connection, as separate processes do.
func TestSQLiteUpgrade_SimultaneousStarts(t *testing.T) {
	for trial := 0; trial < 10; trial++ {
		path, _ := oldSchemaDB(t, FleetAccountUsername)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				s, err := NewSQLiteStorage(path)
				if err == nil {
					s.Close()
				}
				errs[i] = err
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("trial %d, start %d: %v", trial, i, err)
			}
		}
	}
}

// A backup that fails part way (a full disk) leaves no file behind that could
// be mistaken for a backup, and the upgrade does not run.
func TestSQLiteUpgrade_FailedBackupLeavesNoFile(t *testing.T) {
	path, _ := oldSchemaDB(t, FleetAccountUsername)
	prev := vacuumInto
	vacuumInto = func(_ *sql.DB, backup string) error {
		if err := os.WriteFile(backup, nil, 0o600); err != nil { // what a full disk leaves
			t.Fatal(err)
		}
		return errors.New("database or disk is full (13)")
	}
	t.Cleanup(func() { vacuumInto = prev })

	if s, err := NewSQLiteStorage(path); err == nil {
		s.Close()
		t.Fatal("opened an old database whose backup failed; the upgrade must not run without one")
	}
	if left, _ := filepath.Glob(path + ".pre-upgrade-*.bak"); len(left) != 0 {
		t.Fatalf("failed backup left %v", left)
	}
	// Untouched: still the old schema.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hasPrimary int
	if err := db.QueryRow(`SELECT count(*) FROM pragma_table_info('signer_keys') WHERE name = 'is_primary'`).Scan(&hasPrimary); err != nil || hasPrimary != 0 {
		t.Fatalf("database changed although the backup failed (is_primary present=%d, %v)", hasPrimary, err)
	}
}

// A user key's grants all stay live through the upgrade: nothing is retired,
// and a grant with no expiry gets a full sliding SlidingGrantTTL, so nobody is
// signed out by it. A second start does not extend the expiry again.
func TestSQLiteUpgrade_UserKeyKeepsEveryGrant(t *testing.T) {
	path, keyPub := oldSchemaDB(t, "someone")
	ctx := context.Background()
	s, err := NewSQLiteStorage(path)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}
	if k, err := s.GetKey(ctx, "key-a"); err != nil || k.SingleGrant {
		t.Fatalf("GetKey = %+v, %v; want a user key", k, err)
	}
	expiry := map[string]time.Time{}
	for _, c := range []string{"older-client", "newer-client"} {
		p, err := s.GetPermission(ctx, keyPub, c)
		if err != nil {
			t.Fatalf("%s grant after upgrade: %v, want live", c, err)
		}
		if !p.SlidingExpiry || p.ExpiresAt == nil || !near(*p.ExpiresAt, time.Now().Add(SlidingGrantTTL)) {
			t.Fatalf("%s grant = sliding %v expires %v, want sliding ~%v", c, p.SlidingExpiry, p.ExpiresAt, SlidingGrantTTL)
		}
		expiry[c] = *p.ExpiresAt
	}
	s.Close()

	s, err = NewSQLiteStorage(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	for c, want := range expiry {
		if p, err := s.GetPermission(ctx, keyPub, c); err != nil || !p.ExpiresAt.Equal(want) {
			t.Fatalf("%s after restart = %+v, %v; want expiry unchanged at %v", c, p, err, want)
		}
	}
}
