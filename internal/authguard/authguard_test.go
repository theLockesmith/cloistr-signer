package authguard

import (
	"context"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// A request reads the user, then another request locks the account, then the
// first consumes a backup code. The lockout must survive: consuming a code
// may only touch the backup-code columns.
func TestCheckMFA_BackupCodeDoesNotOverwriteConcurrentLockout(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()
	plain, hashed, _ := auth.GenerateBackupCodes(2)
	secret, _, _ := auth.GenerateMFASecret("t", "u")
	if err := store.CreateUser(ctx, &storage.User{ID: "u1", Username: "u", PasswordHash: "x", Role: "user",
		MFAEnabled: true, MFASecret: secret, BackupCodes: hashed, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	stale, _ := store.GetUser(ctx, "u1") // read at the start of request 1

	// Request 2 locks the account meanwhile.
	_ = store.IncrementFailedLogins(ctx, "u1")
	_ = store.LockUser(ctx, "u1", time.Now().Add(time.Hour))

	g := &Guard{Store: store, Auth: &auth.Config{MaxFailedAttempts: 5, LockoutDuration: time.Hour}, Cfg: &config.Config{}}
	if !g.CheckMFA(ctx, stale, plain[0]) {
		t.Fatal("valid backup code refused")
	}
	got, _ := store.GetUser(ctx, "u1")
	if got.LockedUntil == nil || got.FailedLoginAttempts != 1 {
		t.Fatalf("consuming a backup code overwrote the concurrent lockout: attempts=%d locked_until=%v",
			got.FailedLoginAttempts, got.LockedUntil)
	}
	// The same code from another stale copy is refused.
	stale2 := *stale
	stale2.BackupCodes = append([]string(nil), hashed...)
	if g.CheckMFA(ctx, &stale2, plain[0]) {
		t.Fatal("a consumed backup code was accepted again")
	}
}
