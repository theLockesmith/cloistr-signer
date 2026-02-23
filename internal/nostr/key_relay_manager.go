package nostr

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/metrics"
)

// KeyRelayManager manages per-key relay connections.
// Each signing key gets its own set of relay connections, authenticated as that key.
// This isolates rate limits per key and ensures proper NIP-42 authentication.
type KeyRelayManager struct {
	mu           sync.RWMutex
	clients      map[string]*KeyRelayClient // pubkey -> client
	globalRelays []string                   // fallback relays if key has none configured
}

// KeyRelayClient is a relay client dedicated to a specific signing key
type KeyRelayClient struct {
	pubkey     string
	privateKey string
	relayURLs  []string
	relays     map[string]*nostr.Relay
	mu         sync.RWMutex
}

// NewKeyRelayManager creates a new manager for per-key relay connections
func NewKeyRelayManager(globalRelays []string) *KeyRelayManager {
	return &KeyRelayManager{
		clients:      make(map[string]*KeyRelayClient),
		globalRelays: globalRelays,
	}
}

// GetClient returns a relay client for the given key, creating one if needed.
// relayURLs are the key-specific relays; if empty, global relays are used.
func (m *KeyRelayManager) GetClient(ctx context.Context, pubkey, privateKey string, relayURLs []string) *KeyRelayClient {
	m.mu.RLock()
	client, exists := m.clients[pubkey]
	m.mu.RUnlock()

	if exists {
		return client
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if client, exists = m.clients[pubkey]; exists {
		return client
	}

	// Merge key-specific relays with global relays
	// Global relays (like relay.cloistr.xyz) are ALWAYS included as fallback
	// This ensures messages get through even if user-specified relays rate limit
	urlSet := make(map[string]bool)
	var urls []string

	// Add key-specific relays first (user preference)
	for _, url := range relayURLs {
		if !urlSet[url] {
			urlSet[url] = true
			urls = append(urls, url)
		}
	}

	// Always add global relays as fallback (guaranteed delivery)
	for _, url := range m.globalRelays {
		if !urlSet[url] {
			urlSet[url] = true
			urls = append(urls, url)
		}
	}

	client = &KeyRelayClient{
		pubkey:     pubkey,
		privateKey: privateKey,
		relayURLs:  urls,
		relays:     make(map[string]*nostr.Relay),
	}

	// Connect to relays
	client.Connect(ctx)

	m.clients[pubkey] = client
	slog.Info("created per-key relay client", "pubkey", pubkey[:16]+"...", "relays", len(urls))

	return client
}

// RemoveClient disconnects and removes a client for a key
func (m *KeyRelayManager) RemoveClient(pubkey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if client, exists := m.clients[pubkey]; exists {
		client.Disconnect()
		delete(m.clients, pubkey)
		slog.Info("removed per-key relay client", "pubkey", pubkey[:16]+"...")
	}
}

// Connect establishes connections to all configured relays for this key
func (c *KeyRelayClient) Connect(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, url := range c.relayURLs {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			slog.Warn("failed to connect per-key relay", "pubkey", c.pubkey[:16]+"...", "url", url, "error", err)
			continue
		}
		c.relays[url] = relay
		slog.Debug("per-key relay connected", "pubkey", c.pubkey[:16]+"...", "url", url)

		// Authenticate as the signing key
		if err := c.authenticateRelay(ctx, relay); err != nil {
			slog.Debug("per-key auth failed (may not be required)", "pubkey", c.pubkey[:16]+"...", "url", url, "error", err)
		}
	}

	metrics.SetRelayConnections(len(c.relays))
}

// Disconnect closes all relay connections for this key
func (c *KeyRelayClient) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for url, relay := range c.relays {
		relay.Close()
		slog.Debug("per-key relay disconnected", "pubkey", c.pubkey[:16]+"...", "url", url)
	}
	c.relays = make(map[string]*nostr.Relay)
}

// authenticateRelay performs NIP-42 authentication with this key
func (c *KeyRelayClient) authenticateRelay(ctx context.Context, relay *nostr.Relay) error {
	if c.privateKey == "" {
		return nil
	}

	// Short timeout - if relay doesn't respond to AUTH quickly, continue without it
	// Most relays don't require auth, and we can retry on publish if needed
	authCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return relay.Auth(authCtx, func(event *nostr.Event) error {
		event.PubKey = c.pubkey
		return event.Sign(c.privateKey)
	})
}

// PublishToRelay publishes an event to a specific relay with rate-limit retry
func (c *KeyRelayClient) PublishToRelay(ctx context.Context, relayURL string, event *nostr.Event) error {
	c.mu.RLock()
	relay, exists := c.relays[relayURL]
	c.mu.RUnlock()

	if !exists {
		// Try to connect to this relay on-demand
		c.mu.Lock()
		var err error
		relay, err = nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			c.mu.Unlock()
			return err
		}
		c.relays[relayURL] = relay
		c.mu.Unlock()

		// Authenticate
		if authErr := c.authenticateRelay(ctx, relay); authErr != nil {
			slog.Debug("on-demand relay auth failed", "url", relayURL, "error", authErr)
		}
	}

	// Publish with rate-limit retry and adaptive POW
	return c.publishWithRetry(ctx, relay, event, relayURL)
}

// isConnectionError checks if an error indicates a dead connection that needs reconnect
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "use of closed") ||
		strings.Contains(errStr, "eof")
}

// publishWithRetry handles rate-limiting, POW, auth retry, and connection recovery
func (c *KeyRelayClient) publishWithRetry(ctx context.Context, relay *nostr.Relay, event *nostr.Event, url string) error {
	var err error
	backoff := 1 * time.Second   // Start with 1s backoff (was 500ms)
	maxRetries := 5              // More retries for longer rate windows (was 3)
	currentRelay := relay        // May be replaced on reconnection

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err = currentRelay.Publish(ctx, *event)
		if err == nil {
			return nil
		}

		// Log the actual error for debugging rate limit issues
		slog.Debug("publish failed",
			"url", url,
			"attempt", attempt,
			"error", err.Error(),
			"is_rate_limited", isRateLimited(err),
			"is_auth_required", isAuthRequired(err),
			"is_connection_error", isConnectionError(err),
		)

		// Handle connection errors by reconnecting
		if isConnectionError(err) {
			slog.Info("connection error detected, reconnecting", "url", url)
			c.mu.Lock()
			delete(c.relays, url) // Remove stale relay
			newRelay, connectErr := nostr.RelayConnect(ctx, url)
			if connectErr != nil {
				c.mu.Unlock()
				slog.Warn("failed to reconnect to relay", "url", url, "error", connectErr)
				// Continue with backoff, maybe next attempt will succeed
			} else {
				c.relays[url] = newRelay
				c.mu.Unlock()
				currentRelay = newRelay
				// Try auth on new connection
				if authErr := c.authenticateRelay(ctx, newRelay); authErr != nil {
					slog.Debug("auth failed on reconnected relay", "url", url, "error", authErr)
				}
				// Retry immediately after reconnect (no backoff for first post-reconnect attempt)
				continue
			}
		}

		// Handle auth required
		if isAuthRequired(err) || isRestricted(err) {
			slog.Debug("auth required, authenticating", "url", url)
			if authErr := c.authenticateRelay(ctx, relay); authErr == nil {
				err = relay.Publish(ctx, *event)
				if err == nil {
					return nil
				}
			}
		}

		// Handle POW required
		difficulty := parsePowRequirement(err.Error())
		if difficulty > 0 {
			slog.Info("relay requires POW, mining...", "url", url, "difficulty", difficulty)
			powEvent, powErr := c.mineAndSignPow(ctx, event, difficulty)
			if powErr != nil {
				return powErr
			}
			err = relay.Publish(ctx, *powEvent)
			if err == nil {
				return nil
			}

			// POW event might still need auth
			if isAuthRequired(err) || isRestricted(err) {
				if authErr := c.authenticateRelay(ctx, relay); authErr == nil {
					err = relay.Publish(ctx, *powEvent)
					if err == nil {
						return nil
					}
				}
			}
		}

		// Retry any error that isn't definitively non-retryable
		// This is more permissive - we assume network/rate issues are transient
		if !isRetryableError(err) || attempt == maxRetries {
			return err
		}

		slog.Debug("retryable error, waiting before retry", "url", url, "backoff", backoff, "attempt", attempt+1, "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second  // Allow longer waits for aggressive rate limiters (was 5s)
		}
	}

	return err
}

// mineAndSignPow mines POW and signs the event
func (c *KeyRelayClient) mineAndSignPow(ctx context.Context, event *nostr.Event, difficulty int) (*nostr.Event, error) {
	// Create a fresh unsigned event for POW mining
	unsignedEvent := nostr.Event{
		Kind:      event.Kind,
		Content:   event.Content,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      event.Tags,
		PubKey:    event.PubKey,
	}

	// Mine POW with 60 second timeout
	powCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	start := time.Now()
	nonceTag, err := nip13.DoWork(powCtx, unsignedEvent, difficulty)
	if err != nil {
		return nil, err
	}

	unsignedEvent.Tags = append(unsignedEvent.Tags, nonceTag)
	slog.Info("POW mined", "difficulty", difficulty, "duration", time.Since(start))

	if err := unsignedEvent.Sign(c.privateKey); err != nil {
		return nil, err
	}

	return &unsignedEvent, nil
}

// GetConnectedRelays returns the list of connected relay URLs
func (c *KeyRelayClient) GetConnectedRelays() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	urls := make([]string, 0, len(c.relays))
	for url := range c.relays {
		urls = append(urls, url)
	}
	return urls
}
