package nostr

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	relayURLs := []string{
		"wss://relay1.example.com",
		"wss://relay2.example.com",
		"wss://relay3.example.com",
	}

	client := NewClient(relayURLs)

	if client == nil {
		t.Fatal("NewClient() returned nil")
	}

	if len(client.relayURLs) != 3 {
		t.Errorf("relayURLs length = %d, want 3", len(client.relayURLs))
	}

	if client.relays == nil {
		t.Error("relays map should be initialized")
	}

	if len(client.relays) != 0 {
		t.Errorf("relays should be empty before Connect, got %d", len(client.relays))
	}
}

func TestNewClient_Empty(t *testing.T) {
	client := NewClient([]string{})

	if client == nil {
		t.Fatal("NewClient() returned nil")
	}

	if len(client.relayURLs) != 0 {
		t.Errorf("relayURLs length = %d, want 0", len(client.relayURLs))
	}
}

func TestClient_SetAuthKey(t *testing.T) {
	client := NewClient([]string{"wss://relay.example.com"})

	// Initially empty
	if client.authKey != "" {
		t.Errorf("authKey should be empty initially, got %q", client.authKey)
	}

	// Set auth key
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	client.SetAuthKey(testKey)

	if client.authKey != testKey {
		t.Errorf("authKey = %q, want %q", client.authKey, testKey)
	}

	// Update auth key
	newKey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	client.SetAuthKey(newKey)

	if client.authKey != newKey {
		t.Errorf("authKey = %q, want %q", client.authKey, newKey)
	}
}

func TestClient_GetConnectedRelays_Empty(t *testing.T) {
	client := NewClient([]string{"wss://relay.example.com"})

	relays := client.GetConnectedRelays()

	if len(relays) != 0 {
		t.Errorf("GetConnectedRelays() = %v, want empty slice", relays)
	}
}

func TestClient_GetConnectedRelays_ThreadSafe(t *testing.T) {
	client := NewClient([]string{"wss://relay.example.com"})

	// Test concurrent access doesn't panic
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = client.GetConnectedRelays()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestClient_Disconnect_Empty(t *testing.T) {
	client := NewClient([]string{"wss://relay.example.com"})

	// Should not panic on empty relays
	client.Disconnect()

	if len(client.relays) != 0 {
		t.Errorf("relays should be empty after Disconnect, got %d", len(client.relays))
	}
}

func TestClient_Disconnect_ClearsMap(t *testing.T) {
	client := NewClient([]string{"wss://relay.example.com"})

	// Disconnect should reset the map
	client.Disconnect()

	if client.relays == nil {
		t.Error("relays map should not be nil after Disconnect")
	}

	if len(client.relays) != 0 {
		t.Errorf("relays should be empty after Disconnect, got %d", len(client.relays))
	}
}

func TestIsAuthRequired(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "auth-required lowercase",
			err:  errors.New("auth-required: please authenticate"),
			want: true,
		},
		{
			name: "auth-required uppercase",
			err:  errors.New("AUTH-REQUIRED: please authenticate"),
			want: true,
		},
		{
			name: "authentication required",
			err:  errors.New("authentication required"),
			want: true,
		},
		{
			name: "Authentication Required mixed case",
			err:  errors.New("Authentication Required for this action"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("connection refused"),
			want: false,
		},
		{
			name: "timeout error",
			err:  errors.New("context deadline exceeded"),
			want: false,
		},
		{
			name: "permission denied (not auth)",
			err:  errors.New("permission denied"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAuthRequired(tt.err)
			if got != tt.want {
				t.Errorf("isAuthRequired(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestClient_Connect_InvalidRelay(t *testing.T) {
	// Use an invalid URL that will fail to connect
	client := NewClient([]string{"wss://invalid.nonexistent.relay.example.com:12345"})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Connect should not return an error even if all relays fail
	// It just logs warnings and returns nil
	err := client.Connect(ctx)
	if err != nil {
		t.Errorf("Connect() error = %v, want nil (failures are logged, not returned)", err)
	}

	// No relays should be connected
	relays := client.GetConnectedRelays()
	if len(relays) != 0 {
		t.Errorf("GetConnectedRelays() = %v, want empty (invalid relay)", relays)
	}
}

func TestClient_Connect_ContextCancelled(t *testing.T) {
	client := NewClient([]string{"wss://relay.example.com"})

	// Create an already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Connect with cancelled context should handle gracefully
	err := client.Connect(ctx)
	if err != nil {
		t.Errorf("Connect() error = %v, want nil", err)
	}
}

func TestClient_Publish_NoRelays(t *testing.T) {
	client := NewClient([]string{})

	ctx := context.Background()
	// Publish with no connected relays should return nil (no error, no success)
	err := client.Publish(ctx, nil)
	if err != nil {
		t.Errorf("Publish() with no relays should return nil, got %v", err)
	}
}

func TestClient_SetAuthKey_Concurrent(t *testing.T) {
	client := NewClient([]string{"wss://relay.example.com"})

	// Test concurrent SetAuthKey calls don't cause race conditions
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde" + string(rune('0'+n))
			client.SetAuthKey(key)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Just verify no panic occurred and authKey is set
	if client.authKey == "" {
		t.Error("authKey should be set after concurrent SetAuthKey calls")
	}
}

func TestClient_Fields(t *testing.T) {
	relayURLs := []string{"wss://relay1.example.com", "wss://relay2.example.com"}
	client := NewClient(relayURLs)

	// Verify internal fields are properly initialized
	if client.relayURLs == nil {
		t.Error("relayURLs should not be nil")
	}

	if len(client.relayURLs) != 2 {
		t.Errorf("relayURLs length = %d, want 2", len(client.relayURLs))
	}

	// Verify URLs are stored correctly
	if client.relayURLs[0] != "wss://relay1.example.com" {
		t.Errorf("relayURLs[0] = %q, want %q", client.relayURLs[0], "wss://relay1.example.com")
	}

	if client.relayURLs[1] != "wss://relay2.example.com" {
		t.Errorf("relayURLs[1] = %q, want %q", client.relayURLs[1], "wss://relay2.example.com")
	}
}

// Note: The following methods require actual relay connections and are better
// tested with integration tests:
// - Connect (with valid relays)
// - Publish (with connected relays)
// - PublishToRelay
// - Subscribe
// - SubscribeWithReconnect
// - authenticateRelay
// - reconnectIfNeeded
//
// These would require either:
// 1. A mock Nostr relay server
// 2. Integration tests with a real relay
// 3. Refactoring to accept an interface for the relay connection
