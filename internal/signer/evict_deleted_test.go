package signer

import (
	"context"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// A replica can still hold a key in memory after the account was deleted on
// another replica. On use, the key's absence from storage evicts it.
func TestEvictIfKeyDeleted(t *testing.T) {
	store := storage.NewMemoryStorage()
	s := New(&config.Config{}, store, nil, nil, nil, nil, nil)
	ctx := context.Background()
	kept := "1111111111111111111111111111111111111111111111111111111111111111"
	gone := "2222222222222222222222222222222222222222222222222222222222222222"
	if err := store.CreateKey(ctx, &storage.Key{ID: kept[:16], Pubkey: kept, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s.RegisterKey(kept, "0000000000000000000000000000000000000000000000000000000000000001")
	s.RegisterKey(gone, "0000000000000000000000000000000000000000000000000000000000000002")

	if s.evictIfKeyDeleted(ctx, kept) {
		t.Error("evicted a key that still exists")
	}
	if !s.IsKeyLoaded(kept) {
		t.Error("existing key no longer loaded")
	}
	if !s.evictIfKeyDeleted(ctx, gone) {
		t.Error("did not report eviction of a deleted key")
	}
	if s.IsKeyLoaded(gone) {
		t.Error("deleted key still loaded")
	}
}
