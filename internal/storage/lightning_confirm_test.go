package storage

import (
	"context"
	"testing"
	"time"
)

// A key starts unconfirmed and is confirmed once; a login challenge records
// the wallet key that signed it.
func TestLightningKeyConfirm(t *testing.T) {
	backends := []slottedBackend{
		{name: "memory", newFn: func(t *testing.T) Storage { return NewMemoryStorage() }},
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
