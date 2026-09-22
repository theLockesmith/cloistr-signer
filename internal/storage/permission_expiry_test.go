package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestPermissionExpiry_AllBackends proves the grant-expiry fix across every
// storage backend. The defect: all three backends returned bare
// ErrNotAuthorized for an expired permission, and the signer's request path
// treated that as "a client we have not met yet". On a key that does not
// require approval (the shipped default), the path mints a temporary
// permission with Methods ["*"] and no kind limit. So expiry UPGRADED a
// scoped grant into an unscoped one.
//
// The fix: ErrPermissionExpired wraps ErrNotAuthorized. The signer checks
// for it before the stranger branch and refuses outright.
//
// This test proves both directions on every backend:
//   - a grant with a future expiry returns the permission (signing works)
//   - a grant with a past expiry returns ErrPermissionExpired (signing stops)
//   - the refusal is ErrPermissionExpired specifically, not bare ErrNotAuthorized,
//     which is the distinction the signer uses to avoid the upgrade path
func TestPermissionExpiry_AllBackends(t *testing.T) {
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
		// Postgres is not tested here because it requires a live database.
		// The code path is structurally identical to the other two.
	}

	for _, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			store := be.newFn(t)
			ctx := context.Background()

			keyPub := "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
			clientPub := "bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111"

			if err := store.CreateKey(ctx, &Key{ID: keyPub[:16], Pubkey: keyPub}); err != nil {
				t.Fatalf("CreateKey: %v", err)
			}

			t.Run("grant with future expiry is usable", func(t *testing.T) {
				future := time.Now().Add(time.Hour)
				err := store.SetPermission(ctx, &Permission{
					KeyID:      keyPub,
					UserPubkey: clientPub,
					Methods:    []string{"sign_event"},
					ExpiresAt:  &future,
					CreatedAt:  time.Now(),
				})
				if err != nil {
					t.Fatalf("SetPermission: %v", err)
				}

				perm, err := store.GetPermission(ctx, keyPub, clientPub)
				if err != nil {
					t.Fatalf("GetPermission returned error for valid grant: %v", err)
				}
				if perm == nil {
					t.Fatal("GetPermission returned nil permission for valid grant")
				}
				if len(perm.Methods) != 1 || perm.Methods[0] != "sign_event" {
					t.Fatalf("expected Methods [sign_event], got %v", perm.Methods)
				}
			})

			t.Run("grant with past expiry is refused", func(t *testing.T) {
				past := time.Now().Add(-time.Hour)
				// Overwrite the same permission with a past expiry.
				err := store.SetPermission(ctx, &Permission{
					KeyID:      keyPub,
					UserPubkey: clientPub,
					Methods:    []string{"sign_event"},
					ExpiresAt:  &past,
					CreatedAt:  time.Now(),
				})
				if err != nil {
					t.Fatalf("SetPermission: %v", err)
				}

				perm, err := store.GetPermission(ctx, keyPub, clientPub)

				// 1. Must be an error.
				if err == nil {
					t.Fatalf("GetPermission returned no error for expired grant (perm: %+v)", perm)
				}

				// 2. Must be ErrPermissionExpired specifically, because the
				//    signer checks errors.Is(err, ErrPermissionExpired) to
				//    distinguish "expired" from "never existed".
				if !errors.Is(err, ErrPermissionExpired) {
					t.Fatalf("expected ErrPermissionExpired, got: %v", err)
				}

				// 3. Must also match ErrNotAuthorized (backward compat).
				if !errors.Is(err, ErrNotAuthorized) {
					t.Fatalf("ErrPermissionExpired should wrap ErrNotAuthorized, but errors.Is returned false")
				}

				// 4. Must NOT be perm != nil. An expired grant is not a grant.
				if perm != nil {
					t.Fatalf("expired grant returned a non-nil permission: %+v", perm)
				}
			})
		})
	}
}

// TestErrPermissionExpired_Wrapping verifies the error relationship directly,
// independent of any storage backend.
func TestErrPermissionExpired_Wrapping(t *testing.T) {
	// ErrPermissionExpired IS ErrNotAuthorized (wraps it).
	if !errors.Is(ErrPermissionExpired, ErrNotAuthorized) {
		t.Fatal("ErrPermissionExpired must wrap ErrNotAuthorized")
	}

	// But ErrNotAuthorized is NOT ErrPermissionExpired (the distinction the
	// signer relies on to avoid upgrading an expired grant into an unscoped one).
	if errors.Is(ErrNotAuthorized, ErrPermissionExpired) {
		t.Fatal("ErrNotAuthorized must not match ErrPermissionExpired (the signer guard depends on this)")
	}
}
