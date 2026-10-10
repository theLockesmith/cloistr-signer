package authguard

import (
	"context"
	"testing"
	"time"

	"net/http/httptest"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/ratelimit"

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

// Two replicas (two Guards, each with its own hasher built from the shared
// secret, one shared limiter): failed attempts from one address count against
// ONE budget, wherever the edge routes them.
func TestPerIPBudgetSharedAcrossReplicas(t *testing.T) {
	newPod := func(lim ratelimit.Limiter) *Guard {
		cfg := &config.Config{}
		cfg.Auth.AttemptsPerIP = 3
		cfg.Auth.AttemptWindowMinutes = 15
		cfg.Recovery.TrustedProxyHeader = "X-Real-IP"
		return &Guard{Store: storage.NewMemoryStorage(), Auth: &auth.Config{MaxFailedAttempts: 1000, LockoutDuration: time.Hour},
			Cfg: cfg, Limiter: lim, IPHasher: newReplicaHasher()}
	}
	lim := ratelimit.NewMemory()
	pods := []*Guard{newPod(lim), newPod(lim)}
	attempt := func(i int) bool {
		r := httptest.NewRequest("POST", "/api/v1/users/login", nil)
		r.Header.Set("X-Real-IP", "198.51.100.7")
		a, ok := pods[i%2].Begin(r, "someone")
		if ok {
			a.Fail(context.Background(), nil, "password")
			a.End(context.Background())
		}
		return ok
	}
	for i := 0; i < 3; i++ {
		if !attempt(i) {
			t.Fatalf("attempt %d refused within the shared budget", i+1)
		}
	}
	if attempt(3) || attempt(4) {
		t.Fatal("4th/5th failed attempt from the same IP allowed: replicas count separately")
	}
}

// newReplicaHasher builds a pod's hasher the way production does: from the
// replica-shared secret.
func newReplicaHasher() *ratelimit.IPHasher {
	return ratelimit.NewSharedIPHasher([]byte("0123456789abcdef0123456789abcdef"), time.Hour, nil)
}
