package storage

import (
	"context"
	"testing"
)

// TestMemoryStorage_AppConsent exercises the full consent lifecycle on the
// in-memory backend.
func TestMemoryStorage_AppConsent(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	const (
		userID  = "user-abc"
		appID   = "0000000000000000000000000000000000000000000000000000000000000001"
		appName = "TestApp"
		appID2  = "0000000000000000000000000000000000000000000000000000000000000002"
	)

	// HasAppConsent returns false before any consent is recorded.
	got, err := s.HasAppConsent(ctx, userID, appID)
	if err != nil {
		t.Fatalf("HasAppConsent before record: unexpected error: %v", err)
	}
	if got {
		t.Error("HasAppConsent before record = true, want false")
	}

	// RecordAppConsent stores the consent.
	if err := s.RecordAppConsent(ctx, userID, appID, appName); err != nil {
		t.Fatalf("RecordAppConsent: %v", err)
	}

	// HasAppConsent returns true after recording.
	got, err = s.HasAppConsent(ctx, userID, appID)
	if err != nil {
		t.Fatalf("HasAppConsent after record: %v", err)
	}
	if !got {
		t.Error("HasAppConsent after record = false, want true")
	}

	// ListAppConsents returns the recorded consent.
	list, err := s.ListAppConsents(ctx, userID)
	if err != nil {
		t.Fatalf("ListAppConsents: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListAppConsents len = %d, want 1", len(list))
	}
	if list[0].AppID != appID {
		t.Errorf("ListAppConsents[0].AppID = %q, want %q", list[0].AppID, appID)
	}
	if list[0].AppName != appName {
		t.Errorf("ListAppConsents[0].AppName = %q, want %q", list[0].AppName, appName)
	}
	if list[0].ApprovedAt.IsZero() {
		t.Error("ListAppConsents[0].ApprovedAt is zero")
	}

	// Record a second app for the same user.
	if err := s.RecordAppConsent(ctx, userID, appID2, "AnotherApp"); err != nil {
		t.Fatalf("RecordAppConsent (second): %v", err)
	}
	list2, _ := s.ListAppConsents(ctx, userID)
	if len(list2) != 2 {
		t.Errorf("ListAppConsents after second record len = %d, want 2", len(list2))
	}

	// RevokeAppConsent removes the specific consent.
	if err := s.RevokeAppConsent(ctx, userID, appID); err != nil {
		t.Fatalf("RevokeAppConsent: %v", err)
	}
	got, _ = s.HasAppConsent(ctx, userID, appID)
	if got {
		t.Error("HasAppConsent after revoke = true, want false")
	}
	// Second app is still present.
	got, _ = s.HasAppConsent(ctx, userID, appID2)
	if !got {
		t.Error("HasAppConsent second app after first revoke = false, want true")
	}

	// RevokeAppConsent on a non-existent consent returns ErrConsentNotFound.
	if err := s.RevokeAppConsent(ctx, userID, appID); err != ErrConsentNotFound {
		t.Errorf("RevokeAppConsent non-existent = %v, want %v", err, ErrConsentNotFound)
	}

	// RevokeAllAppConsents clears remaining consents.
	if err := s.RevokeAllAppConsents(ctx, userID); err != nil {
		t.Fatalf("RevokeAllAppConsents: %v", err)
	}
	list3, _ := s.ListAppConsents(ctx, userID)
	if len(list3) != 0 {
		t.Errorf("ListAppConsents after RevokeAll len = %d, want 0", len(list3))
	}

	// A different user's consents are isolated.
	s.RecordAppConsent(ctx, "other-user", appID, "OtherApp")
	has, _ := s.HasAppConsent(ctx, userID, appID)
	if has {
		t.Error("consent bled from other-user into userID")
	}
	has, _ = s.HasAppConsent(ctx, "other-user", appID)
	if !has {
		t.Error("other-user consent not found after userID RevokeAll")
	}
}

// TestMemoryStorage_RecordAppConsent_Idempotent verifies that re-recording an
// existing consent (e.g. app name change) does not create a duplicate row.
func TestMemoryStorage_RecordAppConsent_Idempotent(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	s.RecordAppConsent(ctx, "u1", "app1", "Old Name")
	s.RecordAppConsent(ctx, "u1", "app1", "New Name")

	list, _ := s.ListAppConsents(ctx, "u1")
	if len(list) != 1 {
		t.Errorf("re-recording consent created duplicates: len = %d, want 1", len(list))
	}
	if list[0].AppName != "New Name" {
		t.Errorf("re-recording did not update AppName: got %q, want %q", list[0].AppName, "New Name")
	}
}
