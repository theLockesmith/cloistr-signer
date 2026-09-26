package signer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// TestHandleECDHTag verifies that cloistr_ecdh_tag computes the same bucket
// tag that Space's bucketCrypto.ts computeHandoffBucket produces:
//
//	tag = hex(SHA-256(ECDH_shared || "handoff" || BE32(window_id))[0])
func TestHandleECDHTag(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	peerSk := nostr.GeneratePrivateKey()
	peerPk, _ := nostr.GetPublicKey(peerSk)

	windowID := "20000" // arbitrary window id

	result, err := testECDHTag(sk, peerPk, windowID)
	if err != nil {
		t.Fatalf("handleECDHTag: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2-char hex tag, got %q", result)
	}

	// Cross-validate: compute the expected bucket the same way Space does
	convKey, err := nip44.GenerateConversationKey(peerPk, sk)
	if err != nil {
		t.Fatalf("GenerateConversationKey: %v", err)
	}

	wid := uint32(20000)
	wBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(wBytes, wid)
	label := []byte("handoff")
	input := make([]byte, 0, 32+len(label)+4)
	input = append(input, convKey[:]...)
	input = append(input, label...)
	input = append(input, wBytes...)
	expected := sha256.Sum256(input)
	expectedHex := hex.EncodeToString(expected[:1])

	if result != expectedHex {
		t.Errorf("tag mismatch: got %q, want %q", result, expectedHex)
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

	// Tags CAN collide (1/256 chance), but should almost never for different windows
	// This is a smoke test, not a statistical guarantee
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

// testECDHTag calls handleECDHTag with the given private key and params.
func testECDHTag(privateKey string, params ...string) (string, error) {
	s := &Signer{}
	return s.handleECDHTag(privateKey, params)
}
