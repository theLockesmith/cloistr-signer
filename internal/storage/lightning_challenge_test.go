package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func lightningBackends(t *testing.T) []slottedBackend {
	return append(slottedBackends(t), slottedBackend{
		name: "postgres",
		newFn: func(t *testing.T) Storage {
			ps := getTestPostgresStorage(t)
			t.Cleanup(func() { ps.Close() })
			if _, err := ps.db.Exec(`DELETE FROM signer_lightning_challenges`); err != nil {
				t.Fatal(err)
			}
			return ps
		},
	})
}

func newChallenge(k1, sid string, ttl time.Duration) *LightningChallenge {
	now := time.Now()
	return &LightningChallenge{K1: k1, SessionID: sid, ExpiresAt: now.Add(ttl), CreatedAt: now}
}

// pending -> authenticated (once) -> consumed (once), on every backend.
func TestLightningChallenge_Lifecycle(t *testing.T) {
	for _, b := range lightningBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			c := newChallenge("k1-life", "sid-life", time.Minute)
			c.IsLink, c.BoundUserID = true, "bound-user"
			if err := s.CreateLightningChallenge(ctx, c); err != nil {
				t.Fatal(err)
			}
			got, err := s.GetLightningChallengeBySession(ctx, "sid-life")
			if err != nil || got.K1 != "k1-life" || got.Status != "pending" || !got.IsLink || got.BoundUserID != "bound-user" {
				t.Fatalf("by session = %+v, %v", got, err)
			}
			if _, err := s.ConsumeLightningChallenge(ctx, "sid-life"); !errors.Is(err, ErrLightningChallengeNotFound) {
				t.Fatalf("consume while pending: %v, want not found", err)
			}
			if err := s.AuthenticateLightningChallenge(ctx, "k1-life", "user-1"); err != nil {
				t.Fatal(err)
			}
			if err := s.AuthenticateLightningChallenge(ctx, "k1-life", "user-2"); !errors.Is(err, ErrLightningChallengeNotFound) {
				t.Fatalf("second authenticate: %v, want not found", err)
			}
			if got, _ := s.GetLightningChallenge(ctx, "k1-life"); got == nil || got.Status != "authenticated" || got.UserID != "user-1" {
				t.Fatalf("after authenticate = %+v", got)
			}
			if uid, err := s.ConsumeLightningChallenge(ctx, "sid-life"); err != nil || uid != "user-1" {
				t.Fatalf("consume = %q, %v", uid, err)
			}
			if _, err := s.ConsumeLightningChallenge(ctx, "sid-life"); !errors.Is(err, ErrLightningChallengeNotFound) {
				t.Fatalf("second consume: %v, want not found", err)
			}
			if _, err := s.GetLightningChallenge(ctx, "k1-life"); !errors.Is(err, ErrLightningChallengeNotFound) {
				t.Fatalf("consumed challenge still readable: %v", err)
			}
		})
	}
}

// An expired challenge cannot be read, authenticated or consumed, and the
// cleanup removes it.
func TestLightningChallenge_Expiry(t *testing.T) {
	for _, b := range lightningBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			if err := s.CreateLightningChallenge(ctx, newChallenge("k1-old", "sid-old", -time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetLightningChallenge(ctx, "k1-old"); !errors.Is(err, ErrLightningChallengeNotFound) {
				t.Fatalf("get expired: %v", err)
			}
			if _, err := s.GetLightningChallengeBySession(ctx, "sid-old"); !errors.Is(err, ErrLightningChallengeNotFound) {
				t.Fatalf("get expired by session: %v", err)
			}
			if err := s.AuthenticateLightningChallenge(ctx, "k1-old", "u"); !errors.Is(err, ErrLightningChallengeNotFound) {
				t.Fatalf("authenticate expired: %v", err)
			}
			if err := s.CleanExpiredLightningChallenges(ctx); err != nil {
				t.Fatal(err)
			}
			// Re-creating the same k1 succeeds only if the cleanup removed the row.
			if err := s.CreateLightningChallenge(ctx, newChallenge("k1-old", "sid-old", time.Minute)); err != nil {
				t.Fatalf("expired row not cleaned: %v", err)
			}
		})
	}
}

// Many concurrent callbacks and polls for one challenge: exactly one of each wins.
func TestLightningChallenge_ConcurrentSingleUse(t *testing.T) {
	for _, b := range lightningBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			if err := s.CreateLightningChallenge(ctx, newChallenge("k1-race", "sid-race", time.Minute)); err != nil {
				t.Fatal(err)
			}
			race := func(fn func() error) int {
				var wg sync.WaitGroup
				var mu sync.Mutex
				won := 0
				start := make(chan struct{})
				for i := 0; i < 12; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						err := fn()
						if err != nil && !errors.Is(err, ErrLightningChallengeNotFound) {
							t.Errorf("unexpected error: %v", err)
						}
						if err == nil {
							mu.Lock()
							won++
							mu.Unlock()
						}
					}()
				}
				close(start)
				wg.Wait()
				return won
			}
			if n := race(func() error { return s.AuthenticateLightningChallenge(ctx, "k1-race", "u") }); n != 1 {
				t.Fatalf("%d callbacks authenticated the challenge, want 1", n)
			}
			if n := race(func() error { _, err := s.ConsumeLightningChallenge(ctx, "sid-race"); return err }); n != 1 {
				t.Fatalf("%d polls signed in, want 1", n)
			}
		})
	}
}
