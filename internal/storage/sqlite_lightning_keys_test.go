package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// Lightning linking keys on every backend, SQLite included: until 2026-10-16
// SQLite refused to store them ("requires postgres storage"), so Lightning
// login could never work on a SQLite install.
func TestLightningKeys_AllBackends(t *testing.T) {
	backends := append(slottedBackends(t), slottedBackend{name: "postgres", newFn: func(t *testing.T) Storage {
		ps := getTestPostgresStorage(t)
		t.Cleanup(func() { ps.Close() })
		return ps
	}})
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			if err := s.CreateUser(ctx, &User{ID: "ln-owner", Username: "ln-owner", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			key := &LightningKey{ID: "lk-1", UserID: "ln-owner", LinkingKey: "02aa", Name: "phone", CreatedAt: time.Now()}
			if err := s.CreateLightningKey(ctx, key); err != nil {
				t.Fatalf("create: %v", err)
			}
			if err := s.CreateLightningKey(ctx, &LightningKey{ID: "lk-2", UserID: "ln-owner", LinkingKey: "02aa", CreatedAt: time.Now()}); !errors.Is(err, ErrLightningKeyExists) {
				t.Fatalf("same linking key twice: %v, want ErrLightningKeyExists", err)
			}
			got, err := s.GetLightningKeyByLinkingKey(ctx, "02aa")
			if err != nil || got.ID != "lk-1" || got.UserID != "ln-owner" || got.Name != "phone" || got.LastUsedAt != nil {
				t.Fatalf("get = %+v, %v", got, err)
			}
			if _, err := s.GetLightningKeyByLinkingKey(ctx, "02bb"); !errors.Is(err, ErrLightningKeyNotFound) {
				t.Fatalf("unknown key: %v, want ErrLightningKeyNotFound", err)
			}
			if err := s.UpdateLightningKeyLastUsed(ctx, "lk-1"); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.GetLightningKeyByLinkingKey(ctx, "02aa"); got == nil || got.LastUsedAt == nil {
				t.Fatalf("last_used_at not set: %+v", got)
			}
			if list, err := s.ListLightningKeys(ctx, "ln-owner"); err != nil || len(list) != 1 {
				t.Fatalf("list = %v, %v", list, err)
			}
			if err := s.DeleteLightningKey(ctx, "lk-1"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetLightningKeyByLinkingKey(ctx, "02aa"); !errors.Is(err, ErrLightningKeyNotFound) {
				t.Fatalf("after delete: %v", err)
			}
		})
	}
}

// Deleting an account removes its Lightning keys, so the key cannot sign in
// to (or be linked by) anyone else's account later.
func TestSQLiteLightningKeys_RemovedWithAccount(t *testing.T) {
	s, err := NewSQLiteStorage(filepath.Join(t.TempDir(), "ln.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &User{ID: "gone", Username: "gone", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateLightningKey(ctx, &LightningKey{ID: "lk-gone", UserID: "gone", LinkingKey: "02cc", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetLightningKeyByLinkingKey(ctx, "02cc"); !errors.Is(err, ErrLightningKeyNotFound) {
		t.Fatalf("key survived its account: %v", err)
	}
}
