package storage

// Table-driven unit tests for the WebAuthn passkey storage layer.
// These exercise the in-memory backend only (no live DB required).

import (
	"context"
	"testing"
	"time"
)

func TestPasskeyCredentialCRUD(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStorage()

	// Seed a user so the storage has context.
	user := &User{
		ID:           "user-abc",
		Username:     "alice",
		PasswordHash: "x",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := m.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cred := &PasskeyCredential{
		ID:           "cred-1",
		UserID:       "user-abc",
		CredentialID: []byte{0x01, 0x02, 0x03},
		PublicKey:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
		AAGUID:       make([]byte, 16),
		SignCount:    0,
		Transport:    []string{"internal"},
		Name:         "Test Key",
		CreatedAt:    time.Now(),
	}

	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "create and retrieve by credentialID",
			fn: func(t *testing.T) {
				if err := m.CreatePasskeyCredential(ctx, cred); err != nil {
					t.Fatalf("create: %v", err)
				}
				got, err := m.GetPasskeyCredentialByCredentialID(ctx, cred.CredentialID)
				if err != nil {
					t.Fatalf("get by credentialID: %v", err)
				}
				if got.ID != cred.ID {
					t.Errorf("got ID %q, want %q", got.ID, cred.ID)
				}
				if got.UserID != cred.UserID {
					t.Errorf("got UserID %q, want %q", got.UserID, cred.UserID)
				}
			},
		},
		{
			name: "list by user",
			fn: func(t *testing.T) {
				list, err := m.ListPasskeyCredentials(ctx, "user-abc")
				if err != nil {
					t.Fatalf("list: %v", err)
				}
				if len(list) != 1 {
					t.Errorf("expected 1 credential, got %d", len(list))
				}
			},
		},
		{
			name: "update sign count",
			fn: func(t *testing.T) {
				if err := m.UpdatePasskeyCredentialUsage(ctx, cred.CredentialID, 42); err != nil {
					t.Fatalf("update usage: %v", err)
				}
				got, err := m.GetPasskeyCredentialByCredentialID(ctx, cred.CredentialID)
				if err != nil {
					t.Fatalf("get after update: %v", err)
				}
				if got.SignCount != 42 {
					t.Errorf("got SignCount %d, want 42", got.SignCount)
				}
				if got.LastUsedAt == nil {
					t.Error("LastUsedAt should be set after update")
				}
			},
		},
		{
			name: "delete credential",
			fn: func(t *testing.T) {
				if err := m.DeletePasskeyCredential(ctx, cred.ID); err != nil {
					t.Fatalf("delete: %v", err)
				}
				if _, err := m.GetPasskeyCredentialByCredentialID(ctx, cred.CredentialID); err == nil {
					t.Error("expected error after delete, got nil")
				}
				list, _ := m.ListPasskeyCredentials(ctx, "user-abc")
				if len(list) != 0 {
					t.Errorf("expected 0 credentials after delete, got %d", len(list))
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.fn)
	}
}

func TestWebAuthnSessionCRUD(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStorage()

	session := &WebAuthnSession{
		ID:        "sess-xyz",
		UserID:    "user-abc",
		Data:      []byte("gobdata"),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}

	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "create and retrieve",
			fn: func(t *testing.T) {
				if err := m.CreateWebAuthnSession(ctx, session); err != nil {
					t.Fatalf("create: %v", err)
				}
				got, err := m.GetWebAuthnSession(ctx, session.ID)
				if err != nil {
					t.Fatalf("get: %v", err)
				}
				if got.UserID != session.UserID {
					t.Errorf("got UserID %q, want %q", got.UserID, session.UserID)
				}
				if string(got.Data) != string(session.Data) {
					t.Errorf("got Data %q, want %q", got.Data, session.Data)
				}
			},
		},
		{
			name: "missing session returns error",
			fn: func(t *testing.T) {
				if _, err := m.GetWebAuthnSession(ctx, "does-not-exist"); err == nil {
					t.Error("expected error for missing session, got nil")
				}
			},
		},
		{
			name: "delete session",
			fn: func(t *testing.T) {
				if err := m.DeleteWebAuthnSession(ctx, session.ID); err != nil {
					t.Fatalf("delete: %v", err)
				}
				if _, err := m.GetWebAuthnSession(ctx, session.ID); err == nil {
					t.Error("expected error after delete, got nil")
				}
			},
		},
		{
			name: "discoverable session with empty user_id",
			fn: func(t *testing.T) {
				disc := &WebAuthnSession{
					ID:        "disc-sess",
					UserID:    "",
					Data:      []byte("discoverable"),
					ExpiresAt: time.Now().Add(5 * time.Minute),
					CreatedAt: time.Now(),
				}
				if err := m.CreateWebAuthnSession(ctx, disc); err != nil {
					t.Fatalf("create discoverable: %v", err)
				}
				got, err := m.GetWebAuthnSession(ctx, disc.ID)
				if err != nil {
					t.Fatalf("get discoverable: %v", err)
				}
				if got.UserID != "" {
					t.Errorf("expected empty UserID, got %q", got.UserID)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.fn)
	}
}
