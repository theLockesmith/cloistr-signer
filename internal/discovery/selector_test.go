package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelector_SelectRelays_ManualMode(t *testing.T) {
	selector := NewSelector(SelectorConfig{
		FallbackRelays: []string{"wss://fallback.example.com"},
		MaxRelays:      5,
	})

	relays := selector.SelectRelays(context.Background(), SelectionInput{
		KeyRelays: []string{"wss://key1.example.com", "wss://key2.example.com"},
		Mode:      RelayModeManual,
	})

	// Should include key relays and fallback
	if len(relays) != 3 {
		t.Errorf("expected 3 relays, got %d: %v", len(relays), relays)
	}

	// Key relays should come first
	if relays[0] != "wss://key1.example.com" {
		t.Errorf("expected key1 first, got %s", relays[0])
	}
}

func TestSelector_SelectRelays_DiscoveryMode(t *testing.T) {
	// Setup mock discovery server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := RelayResponse{
			Relays: []RelayInfo{
				{URL: "wss://discovered.example.com", Write: true},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	discovery := NewClient(Config{URL: server.URL})
	selector := NewSelector(SelectorConfig{
		Discovery:      discovery,
		FallbackRelays: []string{"wss://fallback.example.com"},
		MaxRelays:      5,
	})

	relays := selector.SelectRelays(context.Background(), SelectionInput{
		KeyRelays:     []string{"wss://key.example.com"}, // Should be ignored in discovery mode
		Mode:          RelayModeDiscovery,
		DiscoveryHint: "testpubkey",
	})

	// Should NOT include key relays in discovery mode
	hasKeyRelay := false
	hasDiscovered := false
	for _, r := range relays {
		if r == "wss://key.example.com" {
			hasKeyRelay = true
		}
		if r == "wss://discovered.example.com" {
			hasDiscovered = true
		}
	}

	if hasKeyRelay {
		t.Error("discovery mode should not include key relays")
	}
	if !hasDiscovered {
		t.Error("discovery mode should include discovered relays")
	}
}

func TestSelector_SelectRelays_AutoMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := RelayResponse{
			Relays: []RelayInfo{
				{URL: "wss://discovered.example.com", Write: true},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	discovery := NewClient(Config{URL: server.URL})
	selector := NewSelector(SelectorConfig{
		Discovery:      discovery,
		FallbackRelays: []string{"wss://fallback.example.com"},
		MaxRelays:      5,
	})

	relays := selector.SelectRelays(context.Background(), SelectionInput{
		KeyRelays:     []string{"wss://key.example.com"},
		Mode:          RelayModeAuto,
		DiscoveryHint: "testpubkey",
	})

	// Auto mode should include ALL sources
	hasKey := false
	hasDiscovered := false
	hasFallback := false

	for _, r := range relays {
		switch r {
		case "wss://key.example.com":
			hasKey = true
		case "wss://discovered.example.com":
			hasDiscovered = true
		case "wss://fallback.example.com":
			hasFallback = true
		}
	}

	if !hasKey {
		t.Error("auto mode should include key relays")
	}
	if !hasDiscovered {
		t.Error("auto mode should include discovered relays")
	}
	if !hasFallback {
		t.Error("auto mode should include fallback relays")
	}
}

func TestSelector_SelectRelays_NoDiscoveryHint(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(RelayResponse{})
	}))
	defer server.Close()

	discovery := NewClient(Config{URL: server.URL})
	selector := NewSelector(SelectorConfig{
		Discovery:      discovery,
		FallbackRelays: []string{"wss://fallback.example.com"},
	})

	selector.SelectRelays(context.Background(), SelectionInput{
		Mode:          RelayModeAuto,
		DiscoveryHint: "", // Empty hint
	})

	// Should not call discovery with empty hint
	if callCount != 0 {
		t.Errorf("expected 0 discovery calls with empty hint, got %d", callCount)
	}
}

func TestSelector_SelectRelays_Deduplication(t *testing.T) {
	selector := NewSelector(SelectorConfig{
		FallbackRelays: []string{
			"wss://relay.example.com",
			"wss://relay.example.com", // Duplicate
		},
		MaxRelays: 5,
	})

	relays := selector.SelectRelays(context.Background(), SelectionInput{
		KeyRelays: []string{
			"wss://relay.example.com", // Also duplicate
			"wss://other.example.com",
		},
		Mode: RelayModeAuto,
	})

	// Count occurrences of relay.example.com
	count := 0
	for _, r := range relays {
		if r == "wss://relay.example.com" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("expected 1 occurrence of relay.example.com, got %d", count)
	}
}

func TestSelector_SelectRelays_MaxRelays(t *testing.T) {
	selector := NewSelector(SelectorConfig{
		FallbackRelays: []string{
			"wss://fb1.example.com",
			"wss://fb2.example.com",
			"wss://fb3.example.com",
		},
		MaxRelays: 2,
	})

	relays := selector.SelectRelays(context.Background(), SelectionInput{
		KeyRelays: []string{
			"wss://key1.example.com",
			"wss://key2.example.com",
		},
		Mode: RelayModeAuto,
	})

	if len(relays) != 2 {
		t.Errorf("expected 2 relays (max), got %d", len(relays))
	}

	// Key relays should have priority
	if relays[0] != "wss://key1.example.com" || relays[1] != "wss://key2.example.com" {
		t.Error("key relays should have priority over fallbacks")
	}
}

func TestSelector_SelectRelays_DiscoveryDisabled(t *testing.T) {
	selector := NewSelector(SelectorConfig{
		Discovery:      nil, // No discovery
		FallbackRelays: []string{"wss://fallback.example.com"},
	})

	relays := selector.SelectRelays(context.Background(), SelectionInput{
		Mode:          RelayModeDiscovery,
		DiscoveryHint: "testpubkey",
	})

	// Should still return fallback relays
	if len(relays) == 0 {
		t.Error("should return fallback relays even when discovery is disabled")
	}
}

func TestSelector_SelectRelays_DefaultMode(t *testing.T) {
	selector := NewSelector(SelectorConfig{
		FallbackRelays: []string{"wss://fallback.example.com"},
	})

	relays := selector.SelectRelays(context.Background(), SelectionInput{
		KeyRelays: []string{"wss://key.example.com"},
		// Mode not specified - should default to Auto
	})

	// Should include key relays (auto behavior)
	hasKey := false
	for _, r := range relays {
		if r == "wss://key.example.com" {
			hasKey = true
		}
	}

	if !hasKey {
		t.Error("default mode (auto) should include key relays")
	}
}

func TestDeduplicateRelays(t *testing.T) {
	input := []string{
		"wss://relay1.example.com",
		"wss://relay2.example.com",
		"wss://relay1.example.com", // Duplicate
		"wss://relay3.example.com",
		"wss://relay1.example.com/", // Duplicate with trailing slash
	}

	result := deduplicateRelays(input, 10)

	// Should have 3 unique relays
	if len(result) != 3 {
		t.Errorf("expected 3 unique relays, got %d: %v", len(result), result)
	}
}

func TestNormalizeRelayURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"wss://relay.example.com", "wss://relay.example.com"},
		{"wss://relay.example.com/", "wss://relay.example.com"},
		{"wss://relay.example.com//", "wss://relay.example.com"},
		{"invalid", ""},
		{"", ""},
	}

	for _, tc := range tests {
		result := normalizeRelayURL(tc.input)
		if result != tc.expected {
			t.Errorf("normalizeRelayURL(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestSelector_HasDiscovery(t *testing.T) {
	// Without discovery
	selector1 := NewSelector(SelectorConfig{})
	if selector1.HasDiscovery() {
		t.Error("selector without discovery should return false")
	}

	// With discovery
	discovery := NewClient(Config{URL: "https://discovery.example.com"})
	selector2 := NewSelector(SelectorConfig{Discovery: discovery})
	if !selector2.HasDiscovery() {
		t.Error("selector with discovery should return true")
	}
}
