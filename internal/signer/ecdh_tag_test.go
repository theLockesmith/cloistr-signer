package signer

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// Known-answer vectors from the kit's own code (thread_wrap.py _ecdh_hex + handoff_bucket).
// sk1 = 1111...1111, pk1 = 4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
// sk2 = 2222...2222, pk2 = 466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27
func TestHandleECDHTag_KnownVectors(t *testing.T) {
	sk1 := "1111111111111111111111111111111111111111111111111111111111111111"
	pk2 := "466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"

	tests := []struct {
		window   string
		expected string
	}{
		{"20000", "38"},
		{"20357", "9f"},
	}

	for _, tt := range tests {
		result, err := testECDHTag(sk1, pk2, tt.window)
		if err != nil {
			t.Fatalf("window %s: %v", tt.window, err)
		}
		if result != tt.expected {
			t.Errorf("window %s: got %q, want %q", tt.window, result, tt.expected)
		}
	}
}

func TestHandleECDHTag_KnownVectors_Reverse(t *testing.T) {
	sk2 := "2222222222222222222222222222222222222222222222222222222222222222"
	pk1 := "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"

	tests := []struct {
		window   string
		expected string
	}{
		{"20000", "38"},
		{"20357", "9f"},
	}

	for _, tt := range tests {
		result, err := testECDHTag(sk2, pk1, tt.window)
		if err != nil {
			t.Fatalf("window %s: %v", tt.window, err)
		}
		if result != tt.expected {
			t.Errorf("window %s (reverse): got %q, want %q", tt.window, result, tt.expected)
		}
	}
}

func TestHandleECDHTag_SymmetricProperty(t *testing.T) {
	skA := nostr.GeneratePrivateKey()
	pkA, _ := nostr.GetPublicKey(skA)
	skB := nostr.GeneratePrivateKey()
	pkB, _ := nostr.GetPublicKey(skB)

	windowID := "19999"

	tagA, err := testECDHTag(skA, pkB, windowID)
	if err != nil {
		t.Fatalf("A->B: %v", err)
	}

	tagB, err := testECDHTag(skB, pkA, windowID)
	if err != nil {
		t.Fatalf("B->A: %v", err)
	}

	if tagA != tagB {
		t.Errorf("ECDH tag not symmetric: A->B=%q, B->A=%q", tagA, tagB)
	}
}

func TestHandleECDHTag_DifferentWindowsDifferentTags(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	peerSk := nostr.GeneratePrivateKey()
	peerPk, _ := nostr.GetPublicKey(peerSk)

	tag1, err := testECDHTag(sk, peerPk, "20000")
	if err != nil {
		t.Fatalf("window 20000: %v", err)
	}

	tag2, err := testECDHTag(sk, peerPk, "20001")
	if err != nil {
		t.Fatalf("window 20001: %v", err)
	}

	if tag1 == tag2 {
		t.Logf("tags collided (possible but unlikely): %s", tag1)
	}
}

func TestHandleECDHTag_MissingParams(t *testing.T) {
	sk := nostr.GeneratePrivateKey()

	if _, err := testECDHTag(sk); err == nil {
		t.Error("expected error with no params")
	}
	if _, err := testECDHTag(sk, "aabb"); err == nil {
		t.Error("expected error with only 1 param")
	}
}

func TestHandleECDHTag_BadPubkey(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	_, err := testECDHTag(sk, "not-a-pubkey", "20000")
	if err == nil {
		t.Error("expected error with invalid pubkey")
	}
}

func testECDHTag(privateKey string, params ...string) (string, error) {
	s := &Signer{}
	return s.handleECDHTag(privateKey, params)
}
