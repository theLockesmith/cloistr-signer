package storage

import (
	"context"
	"testing"
	"time"
)

func TestSlottedGrants_TwoActiveDifferentSlots(t *testing.T) {
	for _, b := range slottedBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			s := b.newFn(t)
			createTestKey(t, s, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

			defaultPerm := &Permission{
				KeyID:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				UserPubkey: "client_default",
				Slot:       SlotDefault,
				Methods:    []string{"sign_event", "connect"},
			}
			publisherPerm := &Permission{
				KeyID:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				UserPubkey: "client_publisher",
				Slot:       SlotPublisher,
				Methods:    []string{"sign_event", "nip44_encrypt", "nip44_decrypt", "connect"},
				AllowedKinds: []int{24242, 30080, 33301},
			}

			if err := s.SetPermission(ctx, defaultPerm); err != nil {
				t.Fatalf("set default: %v", err)
			}
			if err := s.SetPermission(ctx, publisherPerm); err != nil {
				t.Fatalf("set publisher: %v", err)
			}

			gotDefault, err := s.GetPermission(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "client_default")
			if err != nil {
				t.Fatalf("get default: %v", err)
			}
			if gotDefault.Slot != SlotDefault {
				t.Errorf("default slot = %q, want %q", gotDefault.Slot, SlotDefault)
			}

			gotPublisher, err := s.GetPermission(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "client_publisher")
			if err != nil {
				t.Fatalf("get publisher: %v", err)
			}
			if gotPublisher.Slot != SlotPublisher {
				t.Errorf("publisher slot = %q, want %q", gotPublisher.Slot, SlotPublisher)
			}

			perms, err := s.ListPermissions(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(perms) != 2 {
				t.Fatalf("expected 2 active grants, got %d", len(perms))
			}
		})
	}
}

func TestSlottedGrants_DisplacementWithinSlotOnly(t *testing.T) {
	for _, b := range slottedBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			s := b.newFn(t)
			createTestKey(t, s, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

			permA := &Permission{
				KeyID:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				UserPubkey: "clientA",
				Slot:       SlotDefault,
				Methods:    []string{"sign_event", "connect"},
			}
			if err := s.SetPermission(ctx, permA); err != nil {
				t.Fatalf("set A: %v", err)
			}

			permB := &Permission{
				KeyID:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				UserPubkey: "clientB",
				Slot:       SlotPublisher,
				Methods:    []string{"sign_event", "connect"},
			}
			if err := s.SetPermission(ctx, permB); err != nil {
				t.Fatalf("set B: %v", err)
			}

			permC := &Permission{
				KeyID:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				UserPubkey: "clientC",
				Slot:       SlotDefault,
				Methods:    []string{"sign_event", "connect"},
			}
			if err := s.SetPermission(ctx, permC); err != nil {
				t.Fatalf("set C: %v", err)
			}

			_, err := s.GetPermission(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "clientA")
			if err == nil {
				t.Error("clientA should be displaced, but GetPermission succeeded")
			}

			gotB, err := s.GetPermission(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "clientB")
			if err != nil {
				t.Fatalf("clientB displaced when it should not have been: %v", err)
			}
			if gotB.Slot != SlotPublisher {
				t.Errorf("clientB slot = %q, want %q", gotB.Slot, SlotPublisher)
			}

			gotC, err := s.GetPermission(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "clientC")
			if err != nil {
				t.Fatalf("clientC not found: %v", err)
			}
			if gotC.Slot != SlotDefault {
				t.Errorf("clientC slot = %q, want %q", gotC.Slot, SlotDefault)
			}
		})
	}
}

func TestSlottedGrants_InvalidSlotRejected(t *testing.T) {
	for _, b := range slottedBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			s := b.newFn(t)
			createTestKey(t, s, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")

			perm := &Permission{
				KeyID:      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				UserPubkey: "clientX",
				Slot:       "nonsense",
				Methods:    []string{"sign_event"},
			}
			err := s.SetPermission(ctx, perm)
			if err == nil {
				t.Fatal("expected error for invalid slot, got nil")
			}
		})
	}
}

func TestSlottedGrants_EmptySlotDefaultsToDefault(t *testing.T) {
	for _, b := range slottedBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			s := b.newFn(t)
			createTestKey(t, s, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")

			perm := &Permission{
				KeyID:      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				UserPubkey: "clientY",
				Methods:    []string{"sign_event", "connect"},
			}
			if err := s.SetPermission(ctx, perm); err != nil {
				t.Fatalf("set: %v", err)
			}

			got, err := s.GetPermission(ctx, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "clientY")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.Slot != SlotDefault {
				t.Errorf("empty slot should default to %q, got %q", SlotDefault, got.Slot)
			}
		})
	}
}

func TestSlottedGrants_SlotExposedInList(t *testing.T) {
	for _, b := range slottedBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			s := b.newFn(t)
			createTestKey(t, s, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

			for _, slot := range []string{SlotDefault, SlotPublisher} {
				perm := &Permission{
					KeyID:      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					UserPubkey: "client_" + slot,
					Slot:       slot,
					Methods:    []string{"sign_event", "connect"},
				}
				if err := s.SetPermission(ctx, perm); err != nil {
					t.Fatalf("set %s: %v", slot, err)
				}
			}

			perms, err := s.ListPermissions(ctx, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
			if err != nil {
				t.Fatalf("list: %v", err)
			}

			slots := map[string]bool{}
			for _, p := range perms {
				slots[p.Slot] = true
			}
			if !slots[SlotDefault] || !slots[SlotPublisher] {
				t.Errorf("listed slots = %v, want both default and publisher", slots)
			}
		})
	}
}

type slottedBackend struct {
	name  string
	newFn func(t *testing.T) Storage
}

func slottedBackends(t *testing.T) []slottedBackend {
	return []slottedBackend{
		{
			name: "memory",
			newFn: func(t *testing.T) Storage {
				return NewMemoryStorage()
			},
		},
		{
			name: "sqlite",
			newFn: func(t *testing.T) Storage {
				s, err := NewSQLiteStorage(t.TempDir() + "/test.db")
				if err != nil {
					t.Fatalf("NewSQLiteStorage: %v", err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			},
		},
	}
}

func createTestKey(t *testing.T, s Storage, pubkey string) {
	t.Helper()
	err := s.CreateKey(context.Background(), &Key{
		ID:        pubkey[:16],
		Name:      "test-" + pubkey,
		Pubkey:    pubkey,
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("createTestKey(%s): %v", pubkey, err)
	}
}
