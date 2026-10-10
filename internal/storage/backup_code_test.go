package storage

import (
	"context"
	"testing"
	"time"
)

// ConsumeBackupCode removes exactly one stored backup code and touches nothing
// else: a lockout written concurrently must survive, and the same code can be
// consumed only once.
func TestConsumeBackupCode(t *testing.T) {
	backends := map[string]func(t *testing.T) Storage{
		"memory": func(t *testing.T) Storage { return NewMemoryStorage() },
		"sqlite": func(t *testing.T) Storage {
			s, err := NewSQLiteStorage(t.TempDir() + "/test.db")
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
		"postgres": func(t *testing.T) Storage { return getTestPostgresStorage(t) }, // needs TEST_DATABASE_URL
	}
	for name, mk := range backends {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			u := &User{ID: "u1", Username: "bc", PasswordHash: "x", Role: "user",
				BackupCodes: []string{"h1", "h2", "h3"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
			if err := s.CreateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			lockUntil := time.Now().Add(time.Hour)
			_ = s.IncrementFailedLogins(ctx, "u1")
			_ = s.LockUser(ctx, "u1", lockUntil)

			ok, err := s.ConsumeBackupCode(ctx, "u1", "h2")
			if err != nil || !ok {
				t.Fatalf("first consume = %v, %v; want true", ok, err)
			}
			if ok, _ := s.ConsumeBackupCode(ctx, "u1", "h2"); ok {
				t.Fatal("the same backup code was consumed twice")
			}
			if ok, _ := s.ConsumeBackupCode(ctx, "u1", "nope"); ok {
				t.Fatal("an unknown code was reported consumed")
			}

			got, _ := s.GetUser(ctx, "u1")
			if len(got.BackupCodes) != 2 || got.BackupCodes[0] != "h1" || got.BackupCodes[1] != "h3" {
				t.Errorf("remaining codes = %v, want [h1 h3]", got.BackupCodes)
			}
			if got.BackupCodesUsed != 1 {
				t.Errorf("backup codes used = %d, want 1", got.BackupCodesUsed)
			}
			if got.FailedLoginAttempts != 1 || got.LockedUntil == nil || got.LockedUntil.Before(time.Now()) {
				t.Errorf("lockout was disturbed: attempts=%d locked_until=%v", got.FailedLoginAttempts, got.LockedUntil)
			}
		})
	}
}
