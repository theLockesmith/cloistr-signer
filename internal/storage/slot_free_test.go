package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
)

var slotFreeKeys = []string{
	"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

// Every backend, Postgres too when TEST_DATABASE_URL is set.
func slotFreeBackends(t *testing.T) []slottedBackend {
	return append(slottedBackends(t), slottedBackend{
		name: "postgres",
		newFn: func(t *testing.T) Storage {
			ps := getTestPostgresStorage(t)
			t.Cleanup(func() { ps.Close() })
			// cleanupTestDatabase names tables without their signer_ prefix,
			// so clear this file's keys directly.
			for _, table := range []string{"signer_permissions", "signer_keys"} {
				col := "key_id"
				if table == "signer_keys" {
					col = "pubkey"
				}
				if _, err := ps.db.Exec("DELETE FROM "+table+" WHERE "+col+" = ANY($1)", pq.Array(slotFreeKeys)); err != nil {
					t.Fatalf("clear %s: %v", table, err)
				}
			}
			return ps
		},
	})
}

func liveIn(t *testing.T, s Storage, key, slot string) []string {
	t.Helper()
	perms, err := s.ListPermissions(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range perms {
		if p.Slot == slot && (p.ExpiresAt == nil || p.ExpiresAt.After(time.Now())) {
			out = append(out, p.UserPubkey)
		}
	}
	return out
}

// A live grant from another client blocks the write and is left untouched.
func TestSetPermissionIfSlotFree_OccupiedIsRefused(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			key := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			createTestKey(t, s, key)
			exp := time.Now().Add(time.Hour)
			if err := s.SetPermission(ctx, &Permission{KeyID: key, UserPubkey: "holder", Slot: SlotPublisher, Methods: []string{"sign_event"}, ExpiresAt: &exp}); err != nil {
				t.Fatal(err)
			}
			err := s.SetPermissionIfSlotFree(ctx, &Permission{KeyID: key, UserPubkey: "newcomer", Slot: SlotPublisher, Methods: []string{"sign_event"}})
			if !errors.Is(err, ErrSlotOccupied) {
				t.Fatalf("err = %v, want ErrSlotOccupied", err)
			}
			if got := liveIn(t, s, key, SlotPublisher); len(got) != 1 || got[0] != "holder" {
				t.Fatalf("live publisher grants = %v, want [holder]", got)
			}
			if _, err := s.GetPermission(ctx, key, "newcomer"); err == nil {
				t.Fatal("refused grant was stored")
			}
			// The other slot is free, and the holder may amend its own grant.
			if err := s.SetPermissionIfSlotFree(ctx, &Permission{KeyID: key, UserPubkey: "newcomer", Slot: SlotDefault, Methods: []string{"sign_event"}}); err != nil {
				t.Fatalf("free default slot: %v", err)
			}
			if err := s.SetPermissionIfSlotFree(ctx, &Permission{KeyID: key, UserPubkey: "holder", Slot: SlotPublisher, Methods: []string{"sign_event", "nip44_encrypt"}, ExpiresAt: &exp}); err != nil {
				t.Fatalf("holder amending its own grant: %v", err)
			}
		})
	}
}

// A lapsed grant from another client does not hold the slot: it is displaced.
func TestSetPermissionIfSlotFree_LapsedHolderIsDisplaced(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			key := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			createTestKey(t, s, key)
			past := time.Now().Add(-time.Hour)
			if err := s.SetPermission(ctx, &Permission{KeyID: key, UserPubkey: "lapsed", Slot: SlotDefault, Methods: []string{"sign_event"}, ExpiresAt: &past}); err != nil {
				t.Fatal(err)
			}
			if err := s.SetPermissionIfSlotFree(ctx, &Permission{KeyID: key, UserPubkey: "next", Slot: SlotDefault, Methods: []string{"sign_event"}}); err != nil {
				t.Fatalf("lapsed holder blocked the slot: %v", err)
			}
			if got := liveIn(t, s, key, SlotDefault); len(got) != 1 || got[0] != "next" {
				t.Fatalf("live default grants = %v, want [next]", got)
			}
		})
	}
}

// Many clients race for one empty slot: exactly one wins, every other caller
// gets ErrSlotOccupied, and one live grant remains. A check-then-write would
// let several pass the check, with each later write revoking the one before.
func TestSetPermissionIfSlotFree_ConcurrentRaceHasOneWinner(t *testing.T) {
	for _, b := range slotFreeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			s, ctx := b.newFn(t), context.Background()
			key := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			createTestKey(t, s, key)
			const n = 12
			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make([]error, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					errs[i] = s.SetPermissionIfSlotFree(ctx, &Permission{KeyID: key, UserPubkey: fmt.Sprintf("racer-%02d", i), Slot: SlotPublisher, Methods: []string{"sign_event"}})
				}(i)
			}
			close(start)
			wg.Wait()
			won := 0
			for i, err := range errs {
				switch {
				case err == nil:
					won++
				case errors.Is(err, ErrSlotOccupied):
				default:
					t.Errorf("racer %d: unexpected error %v", i, err)
				}
			}
			if won != 1 {
				t.Fatalf("%d racers won the slot, want exactly 1", won)
			}
			if got := liveIn(t, s, key, SlotPublisher); len(got) != 1 {
				t.Fatalf("live publisher grants = %v, want exactly one", got)
			}
		})
	}
}
