// Package discovery provides optional integration with relay discovery services
// for improved NIP-46 relay selection. The package is designed to be completely
// optional - if no discovery URL is configured, all methods gracefully return
// empty results and the signer falls back to manually configured relays.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RelayInfo represents a relay with read/write capabilities
type RelayInfo struct {
	URL   string `json:"url"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
}

// RelayResponse is the response from the discovery service
type RelayResponse struct {
	Pubkey   string      `json:"pubkey"`
	Relays   []RelayInfo `json:"relays"`
	Source   string      `json:"source"` // "nip65", "profile", "fallback"
	CachedAt time.Time   `json:"cached_at,omitempty"`
}

// cacheEntry holds cached relay data
type cacheEntry struct {
	relays    []string
	fetchedAt time.Time
}

// Client provides relay discovery functionality
type Client struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
	maxRelays  int

	// Cache for relay lookups
	cache    map[string]*cacheEntry
	cacheMu  sync.RWMutex
	cacheTTL time.Duration
}

// Config holds discovery client configuration
type Config struct {
	// URL of the discovery service (empty = disabled)
	URL string

	// Timeout for discovery requests (default: 5s)
	Timeout time.Duration

	// Maximum relays to return from discovery (default: 3)
	MaxRelays int

	// Cache TTL for relay lookups (default: 5m)
	CacheTTL time.Duration
}

// NewClient creates a new discovery client
// Returns nil if URL is empty (discovery disabled)
func NewClient(cfg Config) *Client {
	if cfg.URL == "" {
		slog.Info("discovery service disabled (no URL configured)")
		return nil
	}

	// Apply defaults
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxRelays == 0 {
		cfg.MaxRelays = 3
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}

	client := &Client{
		baseURL: strings.TrimSuffix(cfg.URL, "/"),
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		timeout:   cfg.Timeout,
		maxRelays: cfg.MaxRelays,
		cache:     make(map[string]*cacheEntry),
		cacheTTL:  cfg.CacheTTL,
	}

	slog.Info("discovery client initialized",
		"url", cfg.URL,
		"timeout", cfg.Timeout,
		"max_relays", cfg.MaxRelays,
	)

	return client
}

// GetRelaysForUser queries the discovery service for a user's preferred relays
// Returns only relays that support writing (needed for NIP-46)
// Returns empty slice if discovery fails or is disabled
func (c *Client) GetRelaysForUser(ctx context.Context, pubkey string) []string {
	if c == nil || pubkey == "" {
		return nil
	}

	// Check cache first
	if cached := c.getFromCache(pubkey); cached != nil {
		slog.Debug("using cached relays", "pubkey", truncatePubkeyForLog(pubkey), "count", len(cached))
		return cached
	}

	// Query discovery service
	relays, err := c.fetchRelays(ctx, pubkey)
	if err != nil {
		slog.Warn("discovery query failed",
			"pubkey", truncatePubkeyForLog(pubkey),
			"error", err,
		)
		return nil
	}

	// Cache the result
	c.setCache(pubkey, relays)

	slog.Info("discovered relays",
		"pubkey", truncatePubkeyForLog(pubkey),
		"count", len(relays),
		"relays", relays,
	)

	return relays
}

// fetchRelays queries the discovery service
func (c *Client) fetchRelays(ctx context.Context, pubkey string) ([]string, error) {
	// Build request URL
	reqURL := fmt.Sprintf("%s/api/v1/users/%s/relays", c.baseURL, url.PathEscape(pubkey))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cloistr-signer/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// User not found in discovery - not an error
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var relayResp RelayResponse
	if err := json.NewDecoder(resp.Body).Decode(&relayResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract write-capable relay URLs
	var relays []string
	for _, r := range relayResp.Relays {
		if r.Write && isValidRelayURL(r.URL) {
			relays = append(relays, r.URL)
			if len(relays) >= c.maxRelays {
				break
			}
		}
	}

	return relays, nil
}

// getFromCache returns cached relays if still valid
func (c *Client) getFromCache(pubkey string) []string {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	entry, ok := c.cache[pubkey]
	if !ok {
		return nil
	}

	if time.Since(entry.fetchedAt) > c.cacheTTL {
		return nil
	}

	return entry.relays
}

// setCache stores relays in cache
func (c *Client) setCache(pubkey string, relays []string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache[pubkey] = &cacheEntry{
		relays:    relays,
		fetchedAt: time.Now(),
	}
}

// ClearCache clears the relay cache
func (c *Client) ClearCache() {
	if c == nil {
		return
	}

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = make(map[string]*cacheEntry)
}

// isValidRelayURL validates a relay URL
func isValidRelayURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Must be ws:// or wss://
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return false
	}

	// Must have a host
	if u.Host == "" {
		return false
	}

	return true
}

// Enabled returns true if discovery is configured
func (c *Client) Enabled() bool {
	return c != nil && c.baseURL != ""
}

// truncatePubkeyForLog truncates a pubkey for logging
func truncatePubkeyForLog(pubkey string) string {
	if pubkey == "" {
		return ""
	}
	if len(pubkey) > 16 {
		return pubkey[:16] + "..."
	}
	return pubkey
}

// RelayMetadata represents relay information needed for NIP-46 compatibility check
type RelayMetadata struct {
	URL           string `json:"url"`
	Name          string `json:"name"`
	SupportedNIPs []int  `json:"supported_nips"`
}

// relayMetadataResponse wraps the discovery API response
type relayMetadataResponse struct {
	Relay *RelayMetadata `json:"relay,omitempty"`
	Error string         `json:"error,omitempty"`
}

// GetRelayMetadata queries the discovery service for relay NIP support
// Returns nil if discovery fails, is disabled, or relay not found
func (c *Client) GetRelayMetadata(ctx context.Context, relayURL string) *RelayMetadata {
	if c == nil || relayURL == "" {
		return nil
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/api/v1/relay/?url=%s", c.baseURL, url.QueryEscape(relayURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Debug("relay metadata query failed", "url", relayURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var metaResp relayMetadataResponse
	if err := json.NewDecoder(resp.Body).Decode(&metaResp); err != nil {
		return nil
	}

	return metaResp.Relay
}

// NIP46Compatible returns true if the relay advertises NIP-46 support
func (m *RelayMetadata) NIP46Compatible() bool {
	if m == nil {
		return false
	}
	for _, n := range m.SupportedNIPs {
		if n == 46 {
			return true
		}
	}
	return false
}
