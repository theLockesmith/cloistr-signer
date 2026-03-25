package crypto

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestDeriveNostrKey_ProducesValidNostrKey(t *testing.T) {
	seed := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	userID := "test-user-123"

	// Derive key
	privateKey, err := DeriveNostrKey(seed, userID, "cloistr-platform-identity")
	if err != nil {
		t.Fatalf("DeriveNostrKey() error = %v", err)
	}

	// Verify it's a valid Nostr private key (can derive pubkey)
	pubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v, derived key is not valid for Nostr", err)
	}

	// Pubkey should be 64 hex chars
	if len(pubkey) != 64 {
		t.Errorf("pubkey length = %d, want 64", len(pubkey))
	}

	t.Logf("Derived valid Nostr key, pubkey: %s...", pubkey[:16])
}

func TestDeriveNostrKey_EndToEndDeterminism(t *testing.T) {
	seed := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	// Simulate multiple users
	users := []string{"user-001", "user-002", "user-003"}
	pubkeys := make(map[string]string)

	// First pass: derive pubkeys
	for _, userID := range users {
		privateKey, err := DeriveNostrKey(seed, userID, "cloistr-platform-identity")
		if err != nil {
			t.Fatalf("DeriveNostrKey(%s) error = %v", userID, err)
		}
		pubkey, err := nostr.GetPublicKey(privateKey)
		if err != nil {
			t.Fatalf("GetPublicKey() error = %v", err)
		}
		pubkeys[userID] = pubkey
	}

	// Second pass: verify same pubkeys
	for _, userID := range users {
		privateKey, _ := DeriveNostrKey(seed, userID, "cloistr-platform-identity")
		pubkey, _ := nostr.GetPublicKey(privateKey)

		if pubkey != pubkeys[userID] {
			t.Errorf("Pubkey for %s changed: %s != %s", userID, pubkey, pubkeys[userID])
		}
	}

	// Verify all pubkeys are unique
	seen := make(map[string]string)
	for userID, pubkey := range pubkeys {
		if existingUser, exists := seen[pubkey]; exists {
			t.Errorf("Duplicate pubkey for %s and %s", userID, existingUser)
		}
		seen[pubkey] = userID
	}

	t.Logf("All %d users have unique, deterministic pubkeys", len(users))
}
