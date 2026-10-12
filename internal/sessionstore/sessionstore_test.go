package sessionstore

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	st, err := New(storage.NewMemoryStorage(), "redis://"+mr.Addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return st.(*Store), mr
}

func sampleSession() *storage.UserSession {
	la := time.Now().Add(-time.Minute)
	return &storage.UserSession{
		ID:                   "sess-1",
		UserID:               "user-1",
		Token:                "tok-prefix",
		VaultToken:           "",
		CosignListenerPubkey: "cosignpk",
		UserAgent:            "test-agent",
		RememberDevice:       true,
		LastActivity:         &la,
		ExpiresAt:            time.Now().Add(time.Hour),
		CreatedAt:            time.Now().Add(-time.Hour),
	}
}

func TestCreateGet_RoundTripAllFields(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	in := sampleSession()
	if err := s.CreateUserSession(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetUserSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// The fields tagged json:"-" on the storage struct must survive.
	if got.Token != "tok-prefix" || got.CosignListenerPubkey != "cosignpk" || got.UserID != "user-1" {
		t.Errorf("fields not preserved: %+v", got)
	}
	if !got.RememberDevice || got.UserAgent != "test-agent" {
		t.Errorf("fields not preserved: %+v", got)
	}
}

func TestGet_MissingReturnsNotFound(t *testing.T) {
	s, _ := newTestStore(t)
	_, err := s.GetUserSession(context.Background(), "nope")
	if err != storage.ErrSessionNotFound {
		t.Errorf("want ErrSessionNotFound, got %v", err)
	}
}

func TestGet_ExpiredViaTTL(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	in := sampleSession()
	in.ExpiresAt = time.Now().Add(30 * time.Second)
	if err := s.CreateUserSession(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	mr.FastForward(31 * time.Second) // key TTL elapses
	if _, err := s.GetUserSession(ctx, in.ID); err != storage.ErrSessionNotFound {
		t.Errorf("expired session should be NotFound, got %v", err)
	}
}

func TestUpdateVaultToken_PreservesTTLAndSets(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	in := sampleSession()
	if err := s.CreateUserSession(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	ttlBefore := mr.TTL(s.sessKey(in.ID))
	if err := s.UpdateUserSessionVaultToken(ctx, in.ID, "vault-xyz"); err != nil {
		t.Fatalf("update vault token: %v", err)
	}
	got, _ := s.GetUserSession(ctx, in.ID)
	if got.VaultToken != "vault-xyz" {
		t.Errorf("vault token not set: %q", got.VaultToken)
	}
	if ttlAfter := mr.TTL(s.sessKey(in.ID)); ttlAfter <= 0 || ttlAfter > ttlBefore {
		t.Errorf("TTL not preserved: before=%v after=%v", ttlBefore, ttlAfter)
	}
}

func TestListUserSessions_PrunesStale(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	a := sampleSession()
	a.ID = "a"
	b := sampleSession()
	b.ID = "b"
	if err := s.CreateUserSession(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUserSession(ctx, b); err != nil {
		t.Fatal(err)
	}
	// Kill one session key directly, leaving a dangling index entry.
	if err := s.DeleteUserSession(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListUserSessions(ctx, "user-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != "a" {
		t.Errorf("want [a], got %d sessions", len(list))
	}
}

func TestDeleteUserSessions_All(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"x", "y", "z"} {
		ss := sampleSession()
		ss.ID = id
		if err := s.CreateUserSession(ctx, ss); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteUserSessions(ctx, "user-1"); err != nil {
		t.Fatalf("delete all: %v", err)
	}
	list, _ := s.ListUserSessions(ctx, "user-1")
	if len(list) != 0 {
		t.Errorf("expected no sessions after delete-all, got %d", len(list))
	}
	if _, err := s.GetUserSession(ctx, "x"); err != storage.ErrSessionNotFound {
		t.Errorf("session x should be gone, got %v", err)
	}
}

func TestNew_EmptyURLReturnsUnderlying(t *testing.T) {
	base := storage.NewMemoryStorage()
	got, err := New(base, "")
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if _, isWrapped := got.(*Store); isWrapped {
		t.Error("empty URL must return the underlying store, not a Dragonfly wrapper")
	}
}

// Non-session methods must delegate to the embedded store.
func TestDelegation_NonSessionMethod(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	// EnsurePlatformUser is a MemoryStorage no-op; it should not error, proving
	// the call reached the embedded store rather than the Dragonfly override.
	if err := s.EnsurePlatformUser(ctx, "0000000000000000000000000000000000000000000000000000000000000001"); err != nil {
		t.Errorf("delegated method errored: %v", err)
	}
}

// Sliding sessions ("stay signed in" until sign-out): extending moves both the
// stored expiry and the key's TTL forward.
func TestExtendUserSession_MovesExpiryAndTTL(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	in := sampleSession()
	if err := s.CreateUserSession(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	newExp := time.Now().Add(90 * 24 * time.Hour)
	if err := s.ExtendUserSession(ctx, in.ID, newExp); err != nil {
		t.Fatalf("extend: %v", err)
	}
	got, err := s.GetUserSession(ctx, in.ID)
	if err != nil || !got.ExpiresAt.Equal(newExp.Truncate(0)) && got.ExpiresAt.Sub(newExp).Abs() > time.Second {
		t.Fatalf("expiry = %v (err %v), want %v", got.ExpiresAt, err, newExp)
	}
	if ttl := mr.TTL(s.sessKey(in.ID)); ttl < 89*24*time.Hour {
		t.Fatalf("TTL = %v, want ~90 days", ttl)
	}
	if got.VaultToken != in.VaultToken || got.CosignListenerPubkey != in.CosignListenerPubkey {
		t.Fatal("extend dropped other fields")
	}
	if err := s.ExtendUserSession(ctx, "missing", newExp); err == nil {
		t.Fatal("extended a missing session")
	}
}

// The per-user index must outlive every session in it, or sign-out everywhere
// (DeleteUserSessions) can't find a long sliding session. A later short sign-in
// must not shorten it.
func TestUserIndexOutlivesSlidingSession(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	long := sampleSession()
	long.ID = "long"
	if err := s.CreateUserSession(ctx, long); err != nil {
		t.Fatal(err)
	}
	if err := s.ExtendUserSession(ctx, "long", time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	short := sampleSession()
	short.ID = "short"
	if err := s.CreateUserSession(ctx, short); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL(s.userKey(long.UserID)); ttl < 90*24*time.Hour {
		t.Fatalf("user index TTL = %v, shorter than the 90-day session in it", ttl)
	}
	// 60 days on, the long session is still there and sign-out finds it.
	mr.FastForward(60 * 24 * time.Hour)
	if err := s.DeleteUserSessions(ctx, long.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUserSession(ctx, "long"); err == nil {
		t.Fatal("sign-out everywhere missed the sliding session")
	}
}
