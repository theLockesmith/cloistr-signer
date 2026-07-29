package storage

import (
	"context"
	"testing"
)

// The primary key is an attribute, not a name. These tests exist because it
// used to be `Name == "Primary"`, which meant renaming a key silently moved the
// account identity and the nsec-recovery anchor.

func mkKey(t *testing.T, s *MemoryStorage, id, name, owner string) *Key {
	t.Helper()
	k := &Key{ID: id, Name: name, Pubkey: "pk-" + id, OwnerID: owner, KeyType: KeyTypeLocal}
	if err := s.CreateKey(context.Background(), k); err != nil {
		t.Fatalf("CreateKey(%s): %v", id, err)
	}
	return k
}

func primaryOf(t *testing.T, s *MemoryStorage, owner string) []string {
	t.Helper()
	keys, err := s.ListKeys(context.Background(), owner)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	var out []string
	for _, k := range keys {
		if k.IsPrimary {
			out = append(out, k.ID)
		}
	}
	return out
}

func TestSetPrimaryKey_IsExclusive(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	mkKey(t, s, "a", "Work", "user1")
	mkKey(t, s, "b", "Personal", "user1")

	if err := s.SetPrimaryKey(ctx, "user1", "a"); err != nil {
		t.Fatalf("SetPrimaryKey(a): %v", err)
	}
	if got := primaryOf(t, s, "user1"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("after promoting a, primary = %v, want [a]", got)
	}

	// Promoting another key must demote the first, never leave two.
	if err := s.SetPrimaryKey(ctx, "user1", "b"); err != nil {
		t.Fatalf("SetPrimaryKey(b): %v", err)
	}
	if got := primaryOf(t, s, "user1"); len(got) != 1 || got[0] != "b" {
		t.Fatalf("after promoting b, primary = %v, want [b]", got)
	}
}

// The whole point of the change: what the key is CALLED must not decide which
// key is primary.
func TestPrimaryIsIndependentOfName(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	decoy := mkKey(t, s, "decoy", "Primary", "user1") // named it, but never set it
	real := mkKey(t, s, "real", "Burner #3", "user1")

	if err := s.SetPrimaryKey(ctx, "user1", real.ID); err != nil {
		t.Fatalf("SetPrimaryKey: %v", err)
	}

	got := primaryOf(t, s, "user1")
	if len(got) != 1 || got[0] != real.ID {
		t.Fatalf("primary = %v, want [%s] — a key named %q must not win", got, real.ID, decoy.Name)
	}

	// And renaming the primary must not demote it.
	real.Name = "Something Else Entirely"
	if err := s.UpdateKey(ctx, real); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}
	if got := primaryOf(t, s, "user1"); len(got) != 1 || got[0] != real.ID {
		t.Fatalf("after rename, primary = %v, want [%s]", got, real.ID)
	}
}

func TestSetPrimaryKey_RejectsForeignKey(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	mkKey(t, s, "mine", "Mine", "user1")
	mkKey(t, s, "theirs", "Theirs", "user2")

	// user1 must not be able to promote a key they do not own, even knowing its id.
	if err := s.SetPrimaryKey(ctx, "user1", "theirs"); err != ErrKeyNotFound {
		t.Fatalf("SetPrimaryKey across owners = %v, want ErrKeyNotFound", err)
	}
	if got := primaryOf(t, s, "user2"); len(got) != 0 {
		t.Fatalf("user2 keys were modified: %v", got)
	}
}

func TestSetPrimaryKey_UnknownKey(t *testing.T) {
	s := NewMemoryStorage()
	if err := s.SetPrimaryKey(context.Background(), "user1", "nope"); err != ErrKeyNotFound {
		t.Fatalf("SetPrimaryKey(unknown) = %v, want ErrKeyNotFound", err)
	}
}
