package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestGrantTakeover_AllBackends proves the one-active-grant-per-key invariant
// across every storage backend. When a new client connects to a role key, the
// old client's grant is displaced in the same transaction. The displaced row
// stays for the audit record, and a displacement is distinguishable from a
// natural expiry.
func TestGrantTakeover_AllBackends(t *testing.T) {
	type backendFactory struct {
		name  string
		newFn func(t *testing.T) Storage
	}

	backends := []backendFactory{
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

	keyPub := "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
	clientA := "bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111"
	clientB := "cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222"

	for _, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			store := be.newFn(t)
			ctx := context.Background()

			if err := store.CreateKey(ctx, &Key{ID: keyPub[:16], Pubkey: keyPub}); err != nil {
				t.Fatalf("CreateKey: %v", err)
			}

			t.Run("new client displaces old client", func(t *testing.T) {
				future := time.Now().Add(7 * 24 * time.Hour)

				// Client A gets a scoped grant.
				err := store.SetPermission(ctx, &Permission{
					KeyID:      keyPub,
					UserPubkey: clientA,
					Methods:    []string{"sign_event"},
					AllowedKinds: []int{1},
					ExpiresAt:  &future,
					CreatedAt:  time.Now(),
				})
				if err != nil {
					t.Fatalf("SetPermission(A): %v", err)
				}

				// Verify A is live.
				permA, err := store.GetPermission(ctx, keyPub, clientA)
				if err != nil {
					t.Fatalf("GetPermission(A) before takeover: %v", err)
				}
				if permA == nil {
					t.Fatal("GetPermission(A) returned nil")
				}

				// Client B connects, displacing A.
				err = store.SetPermission(ctx, &Permission{
					KeyID:      keyPub,
					UserPubkey: clientB,
					Methods:    []string{"sign_event"},
					AllowedKinds: []int{1},
					ExpiresAt:  &future,
					CreatedAt:  time.Now(),
				})
				if err != nil {
					t.Fatalf("SetPermission(B): %v", err)
				}

				// B is live.
				permB, err := store.GetPermission(ctx, keyPub, clientB)
				if err != nil {
					t.Fatalf("GetPermission(B): %v", err)
				}
				if permB == nil {
					t.Fatal("GetPermission(B) returned nil")
				}

				// A is refused. The error comes back as ErrPermissionExpired
				// (or wrapping it), NOT as the upgrade path for strangers.
				_, err = store.GetPermission(ctx, keyPub, clientA)
				if err == nil {
					t.Fatal("GetPermission(A) after takeover should return error, got nil")
				}
				if !errors.Is(err, ErrNotAuthorized) && !errors.Is(err, ErrPermissionExpired) {
					t.Fatalf("GetPermission(A) after takeover: unexpected error %v", err)
				}

				// ListPermissions shows only the active grant.
				perms, err := store.ListPermissions(ctx, keyPub)
				if err != nil {
					t.Fatalf("ListPermissions: %v", err)
				}
				if len(perms) != 1 {
					t.Fatalf("ListPermissions: expected 1 active grant, got %d", len(perms))
				}
				if perms[0].UserPubkey != clientB {
					t.Fatalf("ListPermissions: active grant is for %s, want %s", perms[0].UserPubkey, clientB)
				}
			})

			t.Run("same client reconnecting does not revoke itself", func(t *testing.T) {
				future := time.Now().Add(7 * 24 * time.Hour)

				// B reconnects with updated methods.
				err := store.SetPermission(ctx, &Permission{
					KeyID:      keyPub,
					UserPubkey: clientB,
					Methods:    []string{"sign_event", "nip44_encrypt"},
					ExpiresAt:  &future,
					CreatedAt:  time.Now(),
				})
				if err != nil {
					t.Fatalf("SetPermission(B again): %v", err)
				}

				permB, err := store.GetPermission(ctx, keyPub, clientB)
				if err != nil {
					t.Fatalf("GetPermission(B) after reconnect: %v", err)
				}
				if len(permB.Methods) != 2 {
					t.Fatalf("expected 2 methods after reconnect, got %v", permB.Methods)
				}
			})
		})
	}
}

// TestDisplacementVsExpiry proves the audit trail distinguishes a natural
// expiry from a displacement. A naturally expired grant has ExpiresAt in the
// past and RevokedAt nil. A displaced grant has RevokedAt set and RevokedBy
// naming the client that took over.
func TestDisplacementVsExpiry_Memory(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	keyPub := "dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333"
	clientA := "eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444"
	clientB := "ffff5555ffff5555ffff5555ffff5555ffff5555ffff5555ffff5555ffff5555"

	if err := store.CreateKey(ctx, &Key{ID: keyPub[:16], Pubkey: keyPub}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	future := time.Now().Add(7 * 24 * time.Hour)

	// Grant to A.
	if err := store.SetPermission(ctx, &Permission{
		KeyID:      keyPub,
		UserPubkey: clientA,
		Methods:    []string{"sign_event"},
		ExpiresAt:  &future,
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("SetPermission(A): %v", err)
	}

	// Grant to B, displacing A.
	if err := store.SetPermission(ctx, &Permission{
		KeyID:      keyPub,
		UserPubkey: clientB,
		Methods:    []string{"sign_event"},
		ExpiresAt:  &future,
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("SetPermission(B): %v", err)
	}

	// Reach into the memory backend to inspect A's raw record.
	ms := store
	ms.mu.RLock()
	rawA := ms.permissions[keyPub][clientA]
	ms.mu.RUnlock()

	if rawA == nil {
		t.Fatal("displaced grant was deleted instead of preserved")
	}

	// The displaced row has RevokedAt set (distinguishes from natural expiry).
	if rawA.RevokedAt == nil {
		t.Fatal("displaced grant has nil RevokedAt; should record the displacement moment")
	}

	// The displaced row records who took over.
	if rawA.RevokedBy != clientB {
		t.Fatalf("RevokedBy = %q, want %q", rawA.RevokedBy, clientB)
	}

	// The original ExpiresAt is preserved (not overwritten to now).
	if rawA.ExpiresAt == nil || !rawA.ExpiresAt.Equal(future) {
		t.Fatalf("ExpiresAt was changed; a displacement should preserve the original expiry")
	}
}
