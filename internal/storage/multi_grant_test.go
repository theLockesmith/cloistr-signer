package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// Grants per key: a user key (SingleGrant false) holds one live grant per
// signed-in app, side by side. Only a key flagged SingleGrant (the fleet's role
// keys) keeps one live grant per slot, a new client displacing the old one.

const (
	userGrantKey   = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	singleGrantKey = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func createGrantTestKey(t *testing.T, s Storage, pubkey string, singleGrant bool) {
	t.Helper()
	if err := s.CreateKey(context.Background(), &Key{
		ID: pubkey[:16], Name: "test-" + pubkey, Pubkey: pubkey, CreatedAt: time.Now(), SingleGrant: singleGrant,
	}); err != nil {
		t.Fatalf("CreateKey(%s): %v", pubkey, err)
	}
}

func signIn(t *testing.T, s Storage, key, client string) {
	t.Helper()
	if err := s.SetPermission(context.Background(), &Permission{KeyID: key, UserPubkey: client, Methods: []string{"connect", "sign_event"}}); err != nil {
		t.Fatalf("SetPermission(%s): %v", client, err)
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestUserKey_SecondAppDoesNotDisplaceFirst(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			createGrantTestKey(t, s, userGrantKey, false)
			signIn(t, s, userGrantKey, "mail")
			signIn(t, s, userGrantKey, "docs")
			for _, c := range []string{"mail", "docs"} {
				if _, err := s.GetPermission(ctx, userGrantKey, c); err != nil {
					t.Errorf("%s grant: %v, want live", c, err)
				}
			}
			if got := sorted(liveIn(t, s, userGrantKey, SlotDefault)); fmt.Sprint(got) != "[docs mail]" {
				t.Fatalf("live grants = %v, want [docs mail]", got)
			}
		})
	}
}

func TestSingleGrantKey_SecondClientDisplacesFirst(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			createGrantTestKey(t, s, singleGrantKey, true)
			signIn(t, s, singleGrantKey, "mail")
			signIn(t, s, singleGrantKey, "docs")
			if _, err := s.GetPermission(ctx, singleGrantKey, "mail"); err == nil {
				t.Error("mail grant still live on a single-grant key")
			}
			if got := liveIn(t, s, singleGrantKey, SlotDefault); fmt.Sprint(got) != "[docs]" {
				t.Fatalf("live grants = %v, want [docs]", got)
			}
		})
	}
}

// On a user key there is no slot to be occupied: a new client is always added.
func TestUserKey_SetPermissionIfSlotFreeAddsNewClient(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			createGrantTestKey(t, s, userGrantKey, false)
			signIn(t, s, userGrantKey, "mail")
			if err := s.SetPermissionIfSlotFree(ctx, &Permission{KeyID: userGrantKey, UserPubkey: "docs", Methods: []string{"sign_event"}}); err != nil {
				t.Fatalf("SetPermissionIfSlotFree on a user key: %v, want nil", err)
			}
			if got := sorted(liveIn(t, s, userGrantKey, SlotDefault)); fmt.Sprint(got) != "[docs mail]" {
				t.Fatalf("live grants = %v, want [docs mail]", got)
			}
		})
	}
}

func concurrentSignIns(t *testing.T, s Storage, key string, n int) {
	t.Helper()
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = s.SetPermission(context.Background(), &Permission{KeyID: key, UserPubkey: fmt.Sprintf("app-%02d", i), Methods: []string{"connect", "sign_event"}})
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("sign-in %d: %v", i, err)
		}
	}
}

func TestUserKey_ConcurrentSignInsAllStayLive(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s := b.newFn(t)
			createGrantTestKey(t, s, userGrantKey, false)
			concurrentSignIns(t, s, userGrantKey, 8)
			if got := liveIn(t, s, userGrantKey, SlotDefault); len(got) != 8 {
				t.Fatalf("live grants = %v, want all 8", got)
			}
		})
	}
}

func TestSingleGrantKey_ConcurrentSignInsLeaveExactlyOne(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s := b.newFn(t)
			createGrantTestKey(t, s, singleGrantKey, true)
			concurrentSignIns(t, s, singleGrantKey, 8)
			if got := liveIn(t, s, singleGrantKey, SlotDefault); len(got) != 1 {
				t.Fatalf("live grants = %v, want exactly one", got)
			}
		})
	}
}

// The flag is stored, read back by every lookup, and not changed by UpdateKey
// (it is set when the key is created).
func TestSingleGrant_StoredAndImmutable(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			createGrantTestKey(t, s, singleGrantKey, true)
			createGrantTestKey(t, s, userGrantKey, false)
			k, err := s.GetKey(ctx, singleGrantKey[:16])
			if err != nil || !k.SingleGrant {
				t.Fatalf("GetKey = %+v, %v; want SingleGrant", k, err)
			}
			if k, err := s.GetKeyByPubkey(ctx, singleGrantKey); err != nil || !k.SingleGrant {
				t.Fatalf("GetKeyByPubkey = %+v, %v; want SingleGrant", k, err)
			}
			all, err := s.ListAllKeys(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, k := range all {
				if want := k.Pubkey == singleGrantKey; k.SingleGrant != want {
					t.Errorf("ListAllKeys %s SingleGrant = %v, want %v", k.Pubkey[:8], k.SingleGrant, want)
				}
			}
			upd := *k
			upd.SingleGrant = false
			upd.Name = "renamed"
			if err := s.UpdateKey(ctx, &upd); err != nil {
				t.Fatal(err)
			}
			if k, _ := s.GetKey(ctx, singleGrantKey[:16]); !k.SingleGrant {
				t.Fatal("UpdateKey cleared SingleGrant")
			}
		})
	}
}

func TestExpiredGrantIsRefused(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			createGrantTestKey(t, s, userGrantKey, false)
			past := time.Now().Add(-time.Minute)
			if err := s.SetPermission(ctx, &Permission{KeyID: userGrantKey, UserPubkey: "mail", Methods: []string{"sign_event"}, ExpiresAt: &past, SlidingExpiry: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetPermission(ctx, userGrantKey, "mail"); !errors.Is(err, ErrPermissionExpired) {
				t.Fatalf("GetPermission on an expired grant = %v, want ErrPermissionExpired", err)
			}
			// A use (which cannot happen, but the write is unconditional) never revives it.
			if err := s.UpdatePermissionLastUsed(ctx, userGrantKey, "mail"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetPermission(ctx, userGrantKey, "mail"); !errors.Is(err, ErrPermissionExpired) {
				t.Fatalf("after a use, GetPermission = %v, want still ErrPermissionExpired", err)
			}
		})
	}
}

func setSliding(t *testing.T, s Storage, client string, expires time.Time, sliding bool) {
	t.Helper()
	if err := s.SetPermission(context.Background(), &Permission{KeyID: userGrantKey, UserPubkey: client, Methods: []string{"sign_event"}, ExpiresAt: &expires, SlidingExpiry: sliding}); err != nil {
		t.Fatal(err)
	}
}

func expiryOf(t *testing.T, s Storage, client string) time.Time {
	t.Helper()
	p, err := s.GetPermission(context.Background(), userGrantKey, client)
	if err != nil || p.ExpiresAt == nil {
		t.Fatalf("GetPermission(%s) = %+v, %v", client, p, err)
	}
	return *p.ExpiresAt
}

func near(a, b time.Time) bool { d := a.Sub(b); return d > -time.Minute && d < time.Minute }

// A use of a sliding grant moves its expiry to SlidingGrantTTL from now; a
// grant slid within the last day is not rewritten; a non-sliding grant keeps
// the expiry it was given.
func TestSlidingGrant_UseSlidesExpiryAtMostDaily(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			createGrantTestKey(t, s, userGrantKey, false)
			now := time.Now()
			stale := now.Add(10 * 24 * time.Hour)
			fresh := now.Add(SlidingGrantTTL - 12*time.Hour).Truncate(time.Second)
			setSliding(t, s, "stale", stale, true)
			setSliding(t, s, "fresh", fresh, true)
			setSliding(t, s, "fixed", stale, false)

			p, err := s.GetPermission(ctx, userGrantKey, "stale")
			if err != nil || !p.SlidingExpiry {
				t.Fatalf("GetPermission = %+v, %v; want SlidingExpiry round-tripped", p, err)
			}
			for _, c := range []string{"stale", "fresh", "fixed"} {
				if err := s.UpdatePermissionLastUsed(ctx, userGrantKey, c); err != nil {
					t.Fatal(err)
				}
			}
			if got := expiryOf(t, s, "stale"); !near(got, now.Add(SlidingGrantTTL)) {
				t.Errorf("used sliding grant expires %v, want ~%v", got, now.Add(SlidingGrantTTL))
			}
			if got := expiryOf(t, s, "fresh"); !got.Equal(fresh) {
				t.Errorf("grant slid within the last day was rewritten: %v, want %v", got, fresh)
			}
			if got := expiryOf(t, s, "fixed"); !near(got, stale) {
				t.Errorf("non-sliding grant expiry moved to %v, want %v", got, stale)
			}
		})
	}
}

// A user-key grant stored with no expiry gets a sliding SlidingGrantTTL; a
// single-grant key's grant keeps the no-expiry it was given.
func TestUserKey_GrantWithNoExpiryGetsSlidingExpiry(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			createGrantTestKey(t, s, userGrantKey, false)
			createGrantTestKey(t, s, singleGrantKey, true)
			signIn(t, s, userGrantKey, "mail")
			signIn(t, s, singleGrantKey, "agent")
			p, err := s.GetPermission(ctx, userGrantKey, "mail")
			if err != nil || !p.SlidingExpiry || p.ExpiresAt == nil || !near(*p.ExpiresAt, time.Now().Add(SlidingGrantTTL)) {
				t.Fatalf("user grant = %+v, %v; want sliding, expiring in ~%v", p, err, SlidingGrantTTL)
			}
			if p, err := s.GetPermission(ctx, singleGrantKey, "agent"); err != nil || p.ExpiresAt != nil || p.SlidingExpiry {
				t.Fatalf("single-grant key's grant = %+v, %v; want no expiry, not sliding", p, err)
			}
		})
	}
}
