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
	mu                sync.RWMutex
	clients           map[string]*KeyRelayClient // pubkey -> client
	globalRelays      []string                   // fallback relays if key has none configured
	publicURLMappings map[string]string          // internal URL -> public URL for NIP-42 auth
}

// KeyRelayClient is a relay client dedicated to a specific signing key
type KeyRelayClient struct {
	pubkey            string
	privateKey        string
	relayURLs         []string
	relays            map[string]*nostr.Relay
	publicURLMappings map[string]string // internal URL -> public URL for NIP-42 auth
	mu                sync.RWMutex
}

// NewKeyRelayManager creates a new manager for per-key relay connections.
// publicURLMappings maps internal relay URLs to public URLs for NIP-42 authentication.
func NewKeyRelayManager(globalRelays []string, publicURLMappings map[string]string) *KeyRelayManager {
	return &KeyRelayManager{
		clients:           make(map[string]*KeyRelayClient),
		globalRelays:      globalRelays,
		publicURLMappings: publicURLMappings,
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

	// Use key-specific relays if configured, otherwise fall back to global relays
	// This respects user intent - if they configure specific relays, use only those
	var urls []string

	if len(relayURLs) > 0 {
		// Key has specific relays configured - use only those
		urlSet := make(map[string]bool)
		for _, url := range relayURLs {
			if !urlSet[url] {
				urlSet[url] = true
				urls = append(urls, url)
			}
		}
		slog.Debug("using key-specific relays", "pubkey", pubkey[:16]+"...", "relays", urls)
	} else {
		// No key-specific relays - use global relays as default
		urls = m.globalRelays
		slog.Debug("using global relays (no key-specific config)", "pubkey", pubkey[:16]+"...", "relays", urls)
	}

	client = &KeyRelayClient{
		pubkey:            pubkey,
		privateKey:        privateKey,
		relayURLs:         urls,
		relays:            make(map[string]*nostr.Relay),
		publicURLMappings: m.publicURLMappings,
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
		// Don't proactively auth - will auth reactively when publish fails with auth-required
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

// getPublicURL returns the public URL for a relay URL.
// This maps internal K8s service URLs to public URLs for NIP-42 authentication.
func (c *KeyRelayClient) getPublicURL(internalURL string) string {
	if c.publicURLMappings != nil {
		if public, ok := c.publicURLMappings[internalURL]; ok {
			return public
		}
	}
	return internalURL
}

// authenticateRelay performs NIP-42 authentication with this key.
// Uses the public URL mapping for the relay tag in the AUTH event.
func (c *KeyRelayClient) authenticateRelay(ctx context.Context, relay *nostr.Relay) error {
	if c.privateKey == "" {
		return nil
	}

	// Get the public URL for this relay (for AUTH event relay tag)
	publicURL := c.getPublicURL(relay.URL)
	slog.Info("auth URL mapping",
		"pubkey", c.pubkey[:16]+"...",
		"relay_url", relay.URL,
		"public_url", publicURL,
		"has_mappings", c.publicURLMappings != nil,
		"mapping_count", len(c.publicURLMappings))

	// Short timeout - if relay doesn't respond to AUTH quickly, continue without it
	authCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return relay.Auth(authCtx, func(event *nostr.Event) error {
		// Log the event before modification for debugging
		var challengeTag, relayTag string
		for _, tag := range event.Tags {
			if len(tag) >= 2 {
				if tag[0] == "challenge" {
					challengeTag = tag[1]
				} else if tag[0] == "relay" {
					relayTag = tag[1]
				}
			}
		}
		slog.Info("AUTH event before signing",
			"pubkey", c.pubkey[:16]+"...",
			"challenge_len", len(challengeTag),
			"challenge_preview", func() string {
				if len(challengeTag) > 8 {
					return challengeTag[:8] + "..."
				}
				return challengeTag
			}(),
			"relay_tag", relayTag)

		event.PubKey = c.pubkey
		// Replace the relay tag with the public URL
		// go-nostr sets this to relay.URL (internal), but we need the public URL
		for i, tag := range event.Tags {
			if len(tag) >= 2 && tag[0] == "relay" {
				slog.Info("replacing relay tag in AUTH event",
					"pubkey", c.pubkey[:16]+"...",
					"original", tag[1],
					"replacement", publicURL)
				event.Tags[i] = nostr.Tag{"relay", publicURL}
				break
			}
		}
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
		// Don't proactively auth - publishWithRetry handles auth-required errors
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
		publishStart := time.Now()
		err = currentRelay.Publish(ctx, *event)
		if err == nil {
			if attempt > 0 {
				slog.Info("publish succeeded after retry",
					"url", url,
					"attempt", attempt+1,
					"publish_ms", time.Since(publishStart).Milliseconds(),
					"event_kind", event.Kind,
				)
			}
			return nil
		}

		// Log the actual error for debugging rate limit issues
		slog.Info("publish attempt failed",
			"url", url,
			"attempt", attempt+1,
			"max_attempts", maxRetries+1,
			"error", err.Error(),
			"is_rate_limited", isRateLimited(err),
			"is_auth_required", isAuthRequired(err),
			"is_connection_error", isConnectionError(err),
			"event_kind", event.Kind,
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
				// Don't proactively auth - if auth is needed, publish will fail
				// with auth-required and we'll handle it below
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

		slog.Info("retrying after backoff", "url", url, "backoff_ms", backoff.Milliseconds(), "next_attempt", attempt+2, "error", err.Error())
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

// SubscribeWithAuth authenticates as this key and subscribes to the given filters.
// This is required for HAVEN-enabled relays where inbox events can only be read
// by the authenticated owner of that inbox.
func (c *KeyRelayClient) SubscribeWithAuth(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event, string)) {
	c.mu.RLock()
	relaysCopy := make(map[string]*nostr.Relay)
	for url, relay := range c.relays {
		relaysCopy[url] = relay
	}
	c.mu.RUnlock()

	for url, relay := range relaysCopy {
		go c.subscribeToRelayWithAuth(ctx, url, relay, filters, handler)
	}

	// Start reconnection loop
	go c.subscribeReconnectLoop(ctx, filters, handler)
}

// subscribeToRelayWithAuth subscribes to a relay, authenticating if required.
// NIP-42 flow: subscribe first, if rejected with restricted/auth, authenticate and retry.
func (c *KeyRelayClient) subscribeToRelayWithAuth(ctx context.Context, url string, relay *nostr.Relay, filters nostr.Filters, handler func(*nostr.Event, string)) {
	// First attempt without auth
	sub, err := relay.Subscribe(ctx, filters)
	if err != nil {
		slog.Warn("initial subscribe failed", "pubkey", c.pubkey[:16]+"...", "url", url, "error", err)
		// Check if it's an auth-related error
		if isAuthRequired(err) || isRestricted(err) {
			sub = c.authAndRetrySubscribe(ctx, url, relay, filters)
		}
		if sub == nil {
			c.mu.Lock()
			delete(c.relays, url)
			c.mu.Unlock()
			return
		}
	}

	slog.Info("subscribed", "pubkey", c.pubkey[:16]+"...", "url", url, "filters", filters)

	// Monitor for immediate CLOSED (auth rejection) vs normal event flow
	for {
		select {
		case <-ctx.Done():
			return
		case reason, ok := <-sub.ClosedReason:
			if !ok {
				// Channel closed without reason
				slog.Warn("subscription closed (no reason)", "pubkey", c.pubkey[:16]+"...", "url", url)
				c.mu.Lock()
				delete(c.relays, url)
				c.mu.Unlock()
				return
			}
			slog.Info("subscription CLOSED received", "pubkey", c.pubkey[:16]+"...", "url", url, "reason", reason)

			// Check if it's an auth-related rejection
			reasonLower := strings.ToLower(reason)
			if strings.Contains(reasonLower, "restricted") ||
				strings.Contains(reasonLower, "auth") ||
				strings.Contains(reasonLower, "owner") {
				// Authenticate and retry
				sub = c.authAndRetrySubscribe(ctx, url, relay, filters)
				if sub == nil {
					c.mu.Lock()
					delete(c.relays, url)
					c.mu.Unlock()
					return
				}
				slog.Info("subscribed after auth", "pubkey", c.pubkey[:16]+"...", "url", url)
				// Continue the loop with new subscription
				continue
			}
			// Closed for other reason - mark for reconnection
			c.mu.Lock()
			delete(c.relays, url)
			c.mu.Unlock()
			return

		case ev, ok := <-sub.Events:
			if !ok {
				// Events channel closed
				slog.Warn("subscription events closed", "pubkey", c.pubkey[:16]+"...", "url", url)
				c.mu.Lock()
				delete(c.relays, url)
				c.mu.Unlock()
				return
			}
			handler(ev, url)
		}
	}
}

// authAndRetrySubscribe authenticates and retries subscription
func (c *KeyRelayClient) authAndRetrySubscribe(ctx context.Context, url string, relay *nostr.Relay, filters nostr.Filters) *nostr.Subscription {
	if err := c.authenticateRelay(ctx, relay); err != nil {
		slog.Warn("auth failed", "pubkey", c.pubkey[:16]+"...", "url", url, "error", err)
		return nil
	}
	slog.Info("authenticated", "pubkey", c.pubkey[:16]+"...", "url", url)

	sub, err := relay.Subscribe(ctx, filters)
	if err != nil {
		slog.Warn("subscribe failed after auth", "pubkey", c.pubkey[:16]+"...", "url", url, "error", err)
		return nil
	}
	return sub
}

// subscribeReconnectLoop periodically reconnects dropped relays and re-subscribes
func (c *KeyRelayClient) subscribeReconnectLoop(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event, string)) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.reconnectAndSubscribe(ctx, filters, handler)
		}
	}
}

// reconnectAndSubscribe reconnects to any disconnected relays and re-subscribes
func (c *KeyRelayClient) reconnectAndSubscribe(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event, string)) {
	c.mu.Lock()
	// Find relays that need reconnection
	connectedURLs := make(map[string]bool)
	for url := range c.relays {
		connectedURLs[url] = true
	}
	c.mu.Unlock()

	for _, url := range c.relayURLs {
		if connectedURLs[url] {
			continue // Already connected
		}

		// Reconnect
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			slog.Debug("reconnect failed", "pubkey", c.pubkey[:16]+"...", "url", url, "error", err)
			continue
		}

		c.mu.Lock()
		c.relays[url] = relay
		c.mu.Unlock()

		slog.Info("reconnected relay", "pubkey", c.pubkey[:16]+"...", "url", url)

		// Authenticate and subscribe in goroutine
		go c.subscribeToRelayWithAuth(ctx, url, relay, filters, handler)
	}
}
