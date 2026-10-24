package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// A key starts unconfirmed and is confirmed once; a login challenge records
// the wallet key that signed it.
func TestLightningKeyConfirm(t *testing.T) {
	backends := []slottedBackend{
		{name: "memory", newFn: func(t *testing.T) Storage { return NewMemoryStorage() }},
		{name: "sqlite", newFn: func(t *testing.T) Storage {
			s, err := NewSQLiteStorage(t.TempDir() + "/confirm.db")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		}},
		{name: "postgres", newFn: func(t *testing.T) Storage {
			ps := getTestPostgresStorage(t)
			t.Cleanup(func() { ps.Close() })
			for _, q := range []string{`DELETE FROM signer_lightning_challenges`, `DELETE FROM signer_lightning_keys WHERE id = 'lk-confirm'`, `DELETE FROM signer_web_accounts WHERE id = 'confirm-owner'`} {
				if _, err := ps.db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			return ps
		}},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			if err := s.CreateUser(ctx, &User{ID: "confirm-owner", Username: "confirm-owner", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := s.CreateLightningKey(ctx, &LightningKey{ID: "lk-confirm", UserID: "confirm-owner", LinkingKey: "02cf", CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if k, _ := s.GetLightningKeyByLinkingKey(ctx, "02cf"); k == nil || k.ConfirmedAt != nil {
				t.Fatalf("new key = %+v, want unconfirmed", k)
			}
			if err := s.ConfirmLightningKey(ctx, "lk-confirm"); err != nil {
				t.Fatal(err)
			}
			first, _ := s.GetLightningKeyByLinkingKey(ctx, "02cf")
			if first == nil || first.ConfirmedAt == nil {
				t.Fatalf("after confirm = %+v", first)
			}
			when := *first.ConfirmedAt
			if err := s.ConfirmLightningKey(ctx, "lk-confirm"); err != nil {
				t.Fatal(err)
			}
			if again, _ := s.GetLightningKeyByLinkingKey(ctx, "02cf"); !again.ConfirmedAt.Equal(when) {
				t.Fatalf("confirming twice moved confirmed_at from %v to %v", when, again.ConfirmedAt)
			}

			now := time.Now()
			if err := s.CreateLightningChallenge(ctx, &LightningChallenge{K1: "k1-conf", SessionID: "sid-conf", ExpiresAt: now.Add(time.Minute), CreatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := s.AuthenticateLightningChallenge(ctx, "k1-conf", "confirm-owner", "02cf"); err != nil {
				t.Fatal(err)
			}
			if c, err := s.GetLightningChallengeBySession(ctx, "sid-conf"); err != nil || c.LinkingKey != "02cf" || c.UserID != "confirm-owner" {
				t.Fatalf("challenge = %+v, %v; want linking key 02cf", c, err)
			}
		})
	}
}

// A SQLite database whose Lightning keys table predates confirmed_at gets the
// column at startup, and its existing keys read as unconfirmed.
func TestSQLiteLightningKeys_ConfirmedAtAddedToOlderTable(t *testing.T) {
	path := t.TempDir() + "/older.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE signer_web_accounts (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
		`CREATE TABLE signer_lightning_keys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES signer_web_accounts(id) ON DELETE CASCADE, linking_key TEXT UNIQUE NOT NULL, name TEXT, created_at TEXT NOT NULL, last_used_at TEXT)`,
		`INSERT INTO signer_web_accounts (id, username, password_hash) VALUES ('old-owner', 'old-owner', 'x')`,
		`INSERT INTO signer_lightning_keys (id, user_id, linking_key, created_at) VALUES ('lk-old', 'old-owner', '02ee', '2026-10-16T00:00:00Z')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	db.Close()

	s, err := NewSQLiteStorage(path)
	if err != nil {
		t.Fatalf("open older database: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	k, err := s.GetLightningKeyByLinkingKey(ctx, "02ee")
	if err != nil || k.ConfirmedAt != nil {
		t.Fatalf("existing key = %+v, %v; want readable and unconfirmed", k, err)
	}
	if err := s.ConfirmLightningKey(ctx, "lk-old"); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.GetLightningKeyByLinkingKey(ctx, "02ee"); k == nil || k.ConfirmedAt == nil {
		t.Fatalf("after confirm = %+v", k)
	}
}
