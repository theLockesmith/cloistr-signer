package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient_Disabled(t *testing.T) {
	client := NewClient(Config{URL: ""})
	if client != nil {
		t.Error("expected nil client when URL is empty")
	}
}

func TestNewClient_Enabled(t *testing.T) {
	client := NewClient(Config{URL: "https://discovery.example.com"})
	if client == nil {
		t.Error("expected non-nil client when URL is set")
	}
	if !client.Enabled() {
		t.Error("expected client to be enabled")
	}
}

func TestClient_GetRelaysForUser_NilClient(t *testing.T) {
	var client *Client
	relays := client.GetRelaysForUser(context.Background(), "abc123")
	if relays != nil {
		t.Error("expected nil relays from nil client")
	}
}

func TestClient_GetRelaysForUser_EmptyPubkey(t *testing.T) {
	client := NewClient(Config{URL: "https://discovery.example.com"})
	relays := client.GetRelaysForUser(context.Background(), "")
	if relays != nil {
		t.Error("expected nil relays for empty pubkey")
	}
}

func TestClient_GetRelaysForUser_Success(t *testing.T) {
	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/testpubkey123/relays" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := RelayResponse{
			Pubkey: "testpubkey123",
			Relays: []RelayInfo{
				{URL: "wss://relay1.example.com", Read: true, Write: true},
				{URL: "wss://relay2.example.com", Read: true, Write: true},
				{URL: "wss://relay3.example.com", Read: true, Write: false}, // Read-only
			},
			Source: "nip65",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:       server.URL,
		MaxRelays: 3,
	})

	relays := client.GetRelaysForUser(context.Background(), "testpubkey123")

	// Should only return write-capable relays
	if len(relays) != 2 {
		t.Errorf("expected 2 relays, got %d", len(relays))
	}

	expected := []string{"wss://relay1.example.com", "wss://relay2.example.com"}
	for i, r := range relays {
		if r != expected[i] {
			t.Errorf("relay %d: expected %s, got %s", i, expected[i], r)
		}
	}
}

func TestClient_GetRelaysForUser_MaxRelays(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := RelayResponse{
			Relays: []RelayInfo{
				{URL: "wss://relay1.example.com", Write: true},
				{URL: "wss://relay2.example.com", Write: true},
				{URL: "wss://relay3.example.com", Write: true},
				{URL: "wss://relay4.example.com", Write: true},
				{URL: "wss://relay5.example.com", Write: true},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:       server.URL,
		MaxRelays: 2,
	})

	relays := client.GetRelaysForUser(context.Background(), "testpubkey")

	if len(relays) != 2 {
		t.Errorf("expected 2 relays (max), got %d", len(relays))
	}
}

func TestClient_GetRelaysForUser_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(Config{URL: server.URL})
	relays := client.GetRelaysForUser(context.Background(), "unknownpubkey")

	if relays != nil {
		t.Error("expected nil relays for unknown pubkey")
	}
}

func TestClient_GetRelaysForUser_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(Config{URL: server.URL})
	relays := client.GetRelaysForUser(context.Background(), "testpubkey")

	if relays != nil {
		t.Error("expected nil relays on server error")
	}
}

func TestClient_GetRelaysForUser_Caching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := RelayResponse{
			Relays: []RelayInfo{
				{URL: "wss://relay.example.com", Write: true},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:      server.URL,
		CacheTTL: 1 * time.Hour,
	})

	// First call
	client.GetRelaysForUser(context.Background(), "testpubkey")
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}

	// Second call - should use cache
	client.GetRelaysForUser(context.Background(), "testpubkey")
	if callCount != 1 {
		t.Errorf("expected 1 call (cached), got %d", callCount)
	}

	// Different pubkey - should make new call
	client.GetRelaysForUser(context.Background(), "otherpubkey")
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestClient_ClearCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := RelayResponse{
			Relays: []RelayInfo{
				{URL: "wss://relay.example.com", Write: true},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{URL: server.URL})

	client.GetRelaysForUser(context.Background(), "testpubkey")
	client.ClearCache()
	client.GetRelaysForUser(context.Background(), "testpubkey")

	if callCount != 2 {
		t.Errorf("expected 2 calls after cache clear, got %d", callCount)
	}
}

func TestIsValidRelayURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"wss://relay.example.com", true},
		{"ws://relay.example.com", true},
		{"wss://relay.example.com:443", true},
		{"wss://relay.example.com/path", true},
		{"https://relay.example.com", false},
		{"http://relay.example.com", false},
		{"relay.example.com", false},
		{"", false},
		{"invalid-url", false},
	}

	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			result := isValidRelayURL(tc.url)
			if result != tc.expected {
				t.Errorf("isValidRelayURL(%q) = %v, expected %v", tc.url, result, tc.expected)
			}
		})
	}
}

func TestClient_Enabled(t *testing.T) {
	var nilClient *Client
	if nilClient.Enabled() {
		t.Error("nil client should not be enabled")
	}

	client := NewClient(Config{URL: "https://discovery.example.com"})
	if !client.Enabled() {
		t.Error("configured client should be enabled")
	}
}
