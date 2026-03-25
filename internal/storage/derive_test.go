package storage

import (
	"context"
	"testing"
)

func TestMemoryStorage_DeriveUserPubkey(t *testing.T) {
	mem := NewMemoryStorage()
	ctx := context.Background()

	// Test determinism
	pubkey1, err := mem.DeriveUserPubkey(ctx, "user-123")
	if err != nil {
		t.Fatalf("DeriveUserPubkey() error = %v", err)
	}

	pubkey2, err := mem.DeriveUserPubkey(ctx, "user-123")
	if err != nil {
		t.Fatalf("DeriveUserPubkey() error = %v", err)
	}

	if pubkey1 != pubkey2 {
		t.Errorf("DeriveUserPubkey() not deterministic: %s != %s", pubkey1, pubkey2)
	}

	// Test different users get different pubkeys
	pubkey3, err := mem.DeriveUserPubkey(ctx, "user-456")
	if err != nil {
		t.Fatalf("DeriveUserPubkey() error = %v", err)
	}

	if pubkey1 == pubkey3 {
		t.Error("DeriveUserPubkey() same pubkey for different users")
	}

	// Verify pubkey format (64 hex chars)
	if len(pubkey1) != 64 {
		t.Errorf("pubkey length = %d, want 64", len(pubkey1))
	}

	t.Logf("✓ Memory storage DeriveUserPubkey deterministic, pubkey: %s...", pubkey1[:16])
}
