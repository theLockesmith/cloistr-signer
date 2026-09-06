package storage

import (
	"context"
	"testing"
	"time"
)

// A scoped, expiring NIP-46 grant is only worth minting if every backend
// honours the expiry. This one did not: it read expires_at, stored it on the
// struct, and handed the permission back regardless. Postgres and the
// in-memory backend both enforce it, so the gap was invisible in production
// (which runs Postgres) and in every test that used MemoryStorage.
func TestSQLiteStorage_GetPermission_ExpiryIsEnforced(t *testing.T) {
	cases := []struct {
		name      string
		expiresAt *time.Time
		wantErr   error
	}{
		{"expired an hour ago", ptrTime(time.Now().Add(-time.Hour)), ErrNotAuthorized},
		{"expires in an hour", ptrTime(time.Now().Add(time.Hour)), nil},
		{"no expiry at all", nil, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSQLiteStorage(t.TempDir() + "/test.db")
			if err != nil {
				t.Fatalf("NewSQLiteStorage() error = %v", err)
			}
			defer s.Close()
			ctx := context.Background()

			if err := s.CreateKey(ctx, &Key{ID: "key1", Pubkey: "keypub123"}); err != nil {
				t.Fatalf("CreateKey() error = %v", err)
			}
			if err := s.SetPermission(ctx, &Permission{
				KeyID:      "keypub123",
				UserPubkey: "userpub456",
				Methods:    []string{"nip44_decrypt"},
				ExpiresAt:  tc.expiresAt,
				CreatedAt:  time.Now(),
			}); err != nil {
				t.Fatalf("SetPermission() error = %v", err)
			}

			perm, err := s.GetPermission(ctx, "keypub123", "userpub456")
			if err != tc.wantErr {
				t.Fatalf("GetPermission() error = %v, want %v (perm %+v)", err, tc.wantErr, perm)
			}
			if tc.wantErr == nil && perm == nil {
				t.Fatal("GetPermission() returned no permission and no error")
			}
		})
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
