package discovery

import (
	"context"
	"log/slog"
)

// RelayMode determines how relays are selected for a key
type RelayMode string

const (
	// RelayModeAuto uses key relays if set, else discovery, else global
	RelayModeAuto RelayMode = "auto"

	// RelayModeManual only uses explicitly configured relays
	RelayModeManual RelayMode = "manual"

	// RelayModeDiscovery queries discovery, falls back to global relays
	RelayModeDiscovery RelayMode = "discovery"
)

// Selector handles relay selection with optional discovery integration
type Selector struct {
	discovery      *Client
	fallbackRelays []string
	maxRelays      int
}

// SelectorConfig configures the relay selector
type SelectorConfig struct {
	// Discovery client (can be nil)
	Discovery *Client

	// Fallback relays to always include
	FallbackRelays []string

	// Maximum total relays to return (default: 5)
	MaxRelays int
}

// NewSelector creates a new relay selector
func NewSelector(cfg SelectorConfig) *Selector {
	if cfg.MaxRelays == 0 {
		cfg.MaxRelays = 5
	}

	return &Selector{
		discovery:      cfg.Discovery,
		fallbackRelays: cfg.FallbackRelays,
		maxRelays:      cfg.MaxRelays,
	}
}

// SelectionInput contains the inputs for relay selection
type SelectionInput struct {
	// KeyRelays are relays explicitly configured for this key
	KeyRelays []string

	// Mode determines the selection strategy
	Mode RelayMode

	// DiscoveryHint is the pubkey to query for relay discovery
	// If empty and mode includes discovery, uses no discovery query
	DiscoveryHint string
}

// SelectRelays returns the relays to use based on configuration and discovery
// The returned list is deduplicated and limited to MaxRelays
func (s *Selector) SelectRelays(ctx context.Context, input SelectionInput) []string {
	var relays []string

	mode := input.Mode
	if mode == "" {
		mode = RelayModeAuto
	}

	// Step 1: Add key-specific relays (if mode allows)
	if mode != RelayModeDiscovery && len(input.KeyRelays) > 0 {
		relays = append(relays, input.KeyRelays...)
		slog.Debug("added key relays", "count", len(input.KeyRelays))
	}

	// Step 2: Query discovery (if mode allows and discovery is enabled)
	if mode != RelayModeManual && s.discovery != nil && s.discovery.Enabled() {
		if input.DiscoveryHint != "" {
			discovered := s.discovery.GetRelaysForUser(ctx, input.DiscoveryHint)
			if len(discovered) > 0 {
				relays = append(relays, discovered...)
				slog.Debug("added discovered relays", "count", len(discovered))
			}
		}
	}

	// Step 3: Always add fallback relays (if not already at max)
	// Fallbacks ensure the signer is always reachable
	relays = append(relays, s.fallbackRelays...)
	slog.Debug("added fallback relays", "count", len(s.fallbackRelays))

	// Step 4: Deduplicate and limit
	result := deduplicateRelays(relays, s.maxRelays)

	slog.Info("selected relays",
		"mode", mode,
		"discovery_hint", truncatePubkey(input.DiscoveryHint),
		"total", len(result),
	)

	return result
}

// deduplicateRelays removes duplicates and limits the count
func deduplicateRelays(relays []string, max int) []string {
	seen := make(map[string]bool)
	var result []string

	for _, relay := range relays {
		// Normalize URL (lowercase, trim trailing slash)
		normalized := normalizeRelayURL(relay)
		if normalized == "" {
			continue
		}

		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, relay) // Keep original casing
			if len(result) >= max {
				break
			}
		}
	}

	return result
}

// normalizeRelayURL normalizes a relay URL for deduplication
func normalizeRelayURL(url string) string {
	if !isValidRelayURL(url) {
		return ""
	}

	// Convert to lowercase for comparison
	// Keep ws:// vs wss:// distinction
	normalized := url

	// Remove trailing slash
	for len(normalized) > 0 && normalized[len(normalized)-1] == '/' {
		normalized = normalized[:len(normalized)-1]
	}

	return normalized
}

// truncatePubkey truncates a pubkey for logging
func truncatePubkey(pubkey string) string {
	if pubkey == "" {
		return ""
	}
	if len(pubkey) > 16 {
		return pubkey[:16] + "..."
	}
	return pubkey
}

// HasDiscovery returns true if discovery is enabled
func (s *Selector) HasDiscovery() bool {
	return s.discovery != nil && s.discovery.Enabled()
}

// GetFallbackRelays returns the configured fallback relays
func (s *Selector) GetFallbackRelays() []string {
	return s.fallbackRelays
}
