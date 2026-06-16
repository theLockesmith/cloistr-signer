package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// FROST 2-of-N user-cosigner share CRUD tests against the in-memory backend.
// docs/frost-2-of-n-design.md §3.1 defines the storage shape; these tests
// pin the contract that all backends (memory, sqlite, postgres) implement.

func newTestFrostUserShare(id, keyID, ownerID string) *FrostUserShare {
	return &FrostUserShare{
		ID:                 id,
		KeyID:              keyID,
		OwnerID:            ownerID,
		ShareIndex:         2,
		EncryptedShare:     []byte("vault:v1:fake-signer-share-ciphertext"),
		VerificationShare:  []byte{0x02, 0xab, 0xcd, 0xef},
		Threshold:          2,
		TotalShares:        2,
		RotationGeneration: 0,
	}
}

func TestMemoryStorage_FrostUserShare_CreateAndGet(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()

	share := newTestFrostUserShare("share-1", "key-1", "owner-1")
	if err := s.CreateFrostUserShare(ctx, share); err != nil {
		t.Fatalf("CreateFrostUserShare: %v", err)
	}
	if share.CreatedAt.IsZero() {
		t.Errorf("CreateFrostUserShare did not set CreatedAt")
	}
	if share.UpdatedAt.IsZero() {
		t.Errorf("CreateFrostUserShare did not set UpdatedAt")
	}

	got, err := s.GetFrostUserShare(ctx, "share-1")
	if err != nil {
		t.Fatalf("GetFrostUserShare: %v", err)
	}
	if got.KeyID != "key-1" {
		t.Errorf("KeyID = %q, want key-1", got.KeyID)
	}
	if !bytes.Equal(got.EncryptedShare, share.EncryptedShare) {
		t.Errorf("EncryptedShare round-trip mismatch")
	}
	if !bytes.Equal(got.VerificationShare, share.VerificationShare) {
		t.Errorf("VerificationShare round-trip mismatch")
	}
	if got.Threshold != 2 || got.TotalShares != 2 {
		t.Errorf("threshold/total = %d/%d, want 2/2", got.Threshold, got.TotalShares)
	}
}

func TestMemoryStorage_FrostUserShare_GetByKeyID(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()

	share := newTestFrostUserShare("share-1", "key-abc", "owner-1")
	if err := s.CreateFrostUserShare(ctx, share); err != nil {
		t.Fatalf("CreateFrostUserShare: %v", err)
	}

	got, err := s.GetFrostUserShareByKeyID(ctx, "key-abc")
	if err != nil {
		t.Fatalf("GetFrostUserShareByKeyID: %v", err)
	}
	if got.ID != "share-1" {
		t.Errorf("got share ID = %q, want share-1", got.ID)
	}

	if _, err := s.GetFrostUserShareByKeyID(ctx, "no-such-key"); !errors.Is(err, ErrFrostUserShareNotFound) {
		t.Errorf("missing key should return ErrFrostUserShareNotFound, got %v", err)
	}
}

func TestMemoryStorage_FrostUserShare_OneSharePerKey(t *testing.T) {
	// Design invariant: exactly one signer-held share per FROST-user Key.
	// Creating a second share for the same key_id must fail.
	s := NewMemoryStorage()
	ctx := context.Background()

	first := newTestFrostUserShare("share-1", "key-1", "owner-1")
	if err := s.CreateFrostUserShare(ctx, first); err != nil {
		t.Fatalf("first CreateFrostUserShare: %v", err)
	}

	second := newTestFrostUserShare("share-2", "key-1", "owner-1")
	err := s.CreateFrostUserShare(ctx, second)
	if !errors.Is(err, ErrFrostUserShareExists) {
		t.Errorf("second create with same key_id should return ErrFrostUserShareExists, got %v", err)
	}
}

func TestMemoryStorage_FrostUserShare_DuplicateID(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()

	first := newTestFrostUserShare("share-1", "key-1", "owner-1")
	if err := s.CreateFrostUserShare(ctx, first); err != nil {
		t.Fatalf("first CreateFrostUserShare: %v", err)
	}

	dup := newTestFrostUserShare("share-1", "key-2", "owner-1")
	err := s.CreateFrostUserShare(ctx, dup)
	if !errors.Is(err, ErrFrostUserShareExists) {
		t.Errorf("duplicate ID should return ErrFrostUserShareExists, got %v", err)
	}
}

func TestMemoryStorage_FrostUserShare_ListByOwner(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()

	mustCreate := func(id, keyID, ownerID string) {
		if err := s.CreateFrostUserShare(ctx, newTestFrostUserShare(id, keyID, ownerID)); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}

	mustCreate("share-a1", "key-a1", "owner-a")
	mustCreate("share-a2", "key-a2", "owner-a")
	mustCreate("share-b1", "key-b1", "owner-b")

	got, err := s.ListFrostUserSharesByOwner(ctx, "owner-a")
	if err != nil {
		t.Fatalf("ListFrostUserSharesByOwner: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("owner-a share count = %d, want 2", len(got))
	}

	got, err = s.ListFrostUserSharesByOwner(ctx, "owner-b")
	if err != nil {
		t.Fatalf("ListFrostUserSharesByOwner: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("owner-b share count = %d, want 1", len(got))
	}

	got, err = s.ListFrostUserSharesByOwner(ctx, "owner-none")
	if err != nil {
		t.Fatalf("ListFrostUserSharesByOwner: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("owner-none share count = %d, want 0", len(got))
	}
}

func TestMemoryStorage_FrostUserShare_UpdateRotation(t *testing.T) {
	// Share refresh / rotation: RotationGeneration increments, EncryptedShare
	// and VerificationShare change, but the same row remains identified by
	// ID + KeyID. CreatedAt is preserved; UpdatedAt advances.
	s := NewMemoryStorage()
	ctx := context.Background()

	share := newTestFrostUserShare("share-1", "key-1", "owner-1")
	if err := s.CreateFrostUserShare(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}
	originalCreated := share.CreatedAt

	share.RotationGeneration = 1
	share.EncryptedShare = []byte("vault:v2:fresh-ciphertext-after-refresh")
	share.VerificationShare = []byte{0x03, 0xfe, 0xdc, 0xba}
	share.TotalShares = 3 // user added a device
	if err := s.UpdateFrostUserShare(ctx, share); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.GetFrostUserShare(ctx, "share-1")
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.RotationGeneration != 1 {
		t.Errorf("RotationGeneration = %d, want 1", got.RotationGeneration)
	}
	if !bytes.Equal(got.EncryptedShare, share.EncryptedShare) {
		t.Errorf("EncryptedShare did not update")
	}
	if got.TotalShares != 3 {
		t.Errorf("TotalShares = %d, want 3 after device add", got.TotalShares)
	}
	if !got.CreatedAt.Equal(originalCreated) {
		t.Errorf("CreatedAt changed across update: %v -> %v", originalCreated, got.CreatedAt)
	}
	if !got.UpdatedAt.After(originalCreated) {
		t.Errorf("UpdatedAt should advance past original CreatedAt")
	}
}

func TestMemoryStorage_FrostUserShare_Delete(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()

	share := newTestFrostUserShare("share-1", "key-1", "owner-1")
	if err := s.CreateFrostUserShare(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.DeleteFrostUserShare(ctx, "share-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.GetFrostUserShare(ctx, "share-1"); !errors.Is(err, ErrFrostUserShareNotFound) {
		t.Errorf("Get after delete should return NotFound, got %v", err)
	}
	if _, err := s.GetFrostUserShareByKeyID(ctx, "key-1"); !errors.Is(err, ErrFrostUserShareNotFound) {
		t.Errorf("GetByKeyID after delete should return NotFound, got %v", err)
	}

	if err := s.DeleteFrostUserShare(ctx, "missing"); !errors.Is(err, ErrFrostUserShareNotFound) {
		t.Errorf("Delete on missing ID should return NotFound, got %v", err)
	}
}
