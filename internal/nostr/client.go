package nostr

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/metrics"
)

// subscription holds a filter and handler pair for reconnection
type subscription struct {
	filters nostr.Filters
	handler func(*nostr.Event)
}

// Client manages connections to Nostr relays
type Client struct {
	relayURLs         []string
	relays            map[string]*nostr.Relay
	authKey           string            // Private key for NIP-42 auth (hex)
	publicURLMappings map[string]string // internal URL -> public URL for NIP-42 auth
	mu                sync.RWMutex

	// Subscription state for reconnection - supports multiple subscriptions
	subscriptions []subscription
	subMu         sync.RWMutex
}

// NewClient creates a new relay client
func NewClient(relayURLs []string) *Client {
	return &Client{
		relayURLs: relayURLs,
		relays:    make(map[string]*nostr.Relay),
	}
}

// SetAuthKey sets the private key to use for NIP-42 authentication
func (c *Client) SetAuthKey(privateKeyHex string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authKey = privateKeyHex
}

// SetPublicURLMappings sets the internal-to-public URL mappings for NIP-42 auth
// This maps internal K8s service URLs to public URLs for the AUTH event relay tag
func (c *Client) SetPublicURLMappings(mappings map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.publicURLMappings = mappings
}

// getPublicURL returns the public URL for a relay URL
func (c *Client) getPublicURL(internalURL string) string {
	if c.publicURLMappings != nil {
		if public, ok := c.publicURLMappings[internalURL]; ok {
			return public
		}
	}
	return internalURL
}

// internalURLFor maps a public relay URL back to the internal URL the signer
// holds a persistent connection to (the reverse of publicURLMappings). Clients
// advertise the public relay (e.g. wss://relay.cloistr.xyz) in nostrconnect
// URIs, but the signer should publish over its existing internal connection
// (e.g. ws://cloistr-relay.svc): it's already connected, avoids a fresh
// Tor-routed dial to the external hostname, and the relay's cross-pod pubsub
// delivers the event to the external subscriber regardless of pod/path.
// Returns the input unchanged when it isn't a known public URL.
func (c *Client) internalURLFor(url string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for internal, public := range c.publicURLMappings {
		if public == url {
			return internal
		}
	}
	return url
}

// Connect establishes connections to all configured relays
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, url := range c.relayURLs {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			slog.Warn("failed to connect to relay", "url", url, "error", err)
			continue
		}
		c.relays[url] = relay
		metrics.SetRelayConnections(len(c.relays))
		slog.Info("connected to relay", "url", url)
		// Don't proactively authenticate - NIP-42 requires the relay to send
		// an AUTH challenge first. We'll auth reactively when operations fail
		// with auth-required errors or when the relay sends a challenge.
	}

	if len(c.relays) == 0 {
		slog.Warn("no relays connected")
	}

	return nil
}

// authenticateRelay performs NIP-42 authentication with a relay using the client's auth key
func (c *Client) authenticateRelay(ctx context.Context, relay *nostr.Relay) error {
	return c.authenticateRelayWithKey(ctx, relay, c.authKey)
}

// authenticateRelayWithKey performs NIP-42 authentication with a relay using a specific private key
func (c *Client) authenticateRelayWithKey(ctx context.Context, relay *nostr.Relay, privateKey string) error {
	if privateKey == "" {
		return fmt.Errorf("no private key for authentication")
	}

	// Get the public URL for this relay (for AUTH event relay tag)
	publicURL := c.getPublicURL(relay.URL)

	// Use a dedicated context with sufficient timeout for auth
	// The parent context might have a tight deadline from HTTP handlers
	authCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := relay.Auth(authCtx, func(event *nostr.Event) error {
		pubkey, err := nostr.GetPublicKey(privateKey)
		if err != nil {
			return err
		}
		event.PubKey = pubkey
		// Replace the relay tag with the public URL
		// go-nostr sets this to relay.URL (internal), but we need the public URL
		for i, tag := range event.Tags {
			if len(tag) >= 2 && tag[0] == "relay" {
				event.Tags[i] = nostr.Tag{"relay", publicURL}
				break
			}
		}
		return event.Sign(privateKey)
	})
	if err != nil {
		return err
	}
	slog.Info("authenticated with relay", "url", relay.URL, "publicURL", publicURL)
	return nil
}

// Disconnect closes all relay connections
func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for url, relay := range c.relays {
		relay.Close()
		slog.Info("disconnected from relay", "url", url)
	}
	c.relays = make(map[string]*nostr.Relay)
}

// Publish publishes an event to all connected relays
func (c *Client) Publish(ctx context.Context, event *nostr.Event) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var lastErr error
	successCount := 0

	for url, relay := range c.relays {
		err := relay.Publish(ctx, *event)
		if err != nil {
			// Check if auth is required
			if c.authKey != "" && isAuthRequired(err) {
				slog.Info("auth required, authenticating", "url", url)
				if authErr := c.authenticateRelay(ctx, relay); authErr != nil {
					slog.Warn("auth failed", "url", url, "error", authErr)
				} else {
					// Retry publish after auth
					err = relay.Publish(ctx, *event)
				}
			}
		}

		if err != nil {
			slog.Warn("failed to publish to relay", "url", url, "error", err)
			lastErr = err
			continue
		}
		successCount++
		slog.Debug("published to relay", "url", url, "event_id", event.ID)
	}

	if successCount > 0 {
		return nil
	}
	return lastErr
}

// publishWithRateLimitRetry attempts to publish an event with automatic retry on transient errors
func publishWithRateLimitRetry(ctx context.Context, relay *nostr.Relay, event nostr.Event, maxRetries int) error {
	var err error
	backoff := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err = relay.Publish(ctx, event)
		if err == nil {
			return nil
		}

		// Retry any error that isn't definitively non-retryable
		if !isRetryableError(err) || attempt == maxRetries {
			return err
		}

		// Wait with exponential backoff before retrying
		slog.Debug("retryable error, waiting before retry", "url", relay.URL, "backoff", backoff, "attempt", attempt+1, "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
	return err
}

// PublishWithAdaptivePow publishes an event, automatically mining POW if required by relays.
// The privateKey is needed to re-sign the event after adding the POW nonce tag,
// and also for NIP-42 authentication (so event.pubkey matches authenticated identity).
func (c *Client) PublishWithAdaptivePow(ctx context.Context, event *nostr.Event, privateKey string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var lastErr error
	successCount := 0

	for url, relay := range c.relays {
		err := publishWithRateLimitRetry(ctx, relay, *event, 3)
		if err != nil {
			// Check if auth is required or restricted (must auth as event pubkey)
			if privateKey != "" && (isAuthRequired(err) || isRestricted(err)) {
				slog.Info("auth required, authenticating with event key", "url", url)
				// Authenticate with the signing key (privateKey), not the global authKey
				// This ensures event.pubkey matches authenticated identity
				if authErr := c.authenticateRelayWithKey(ctx, relay, privateKey); authErr != nil {
					slog.Warn("auth failed", "url", url, "error", authErr)
				} else {
					// Retry publish after auth
					err = publishWithRateLimitRetry(ctx, relay, *event, 3)
				}
			}
		}

		// Check if POW is required
		if err != nil {
			difficulty := parsePowRequirement(err.Error())
			if difficulty > 0 && privateKey != "" {
				slog.Info("relay requires POW, mining...", "url", url, "difficulty", difficulty)

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
				start := time.Now()
				nonceTag, powErr := nip13.DoWork(powCtx, unsignedEvent, difficulty)
				cancel()

				if powErr != nil {
					slog.Warn("POW mining failed", "url", url, "error", powErr)
					lastErr = powErr
					continue
				}

				unsignedEvent.Tags = append(unsignedEvent.Tags, nonceTag)
				slog.Info("POW mined", "url", url, "difficulty", difficulty, "duration", time.Since(start))

				if signErr := unsignedEvent.Sign(privateKey); signErr != nil {
					slog.Warn("failed to sign POW event", "url", url, "error", signErr)
					lastErr = signErr
					continue
				}

				// Try publishing the POW event
				err = publishWithRateLimitRetry(ctx, relay, unsignedEvent, 3)

				// POW event might still need auth
				if err != nil && (isAuthRequired(err) || isRestricted(err)) {
					slog.Info("auth required after POW, authenticating with event key", "url", url)
					if authErr := c.authenticateRelayWithKey(ctx, relay, privateKey); authErr != nil {
						slog.Warn("auth failed after POW", "url", url, "error", authErr)
					} else {
						// Retry POW event after auth
						err = publishWithRateLimitRetry(ctx, relay, unsignedEvent, 3)
					}
				}
			}
		}

		if err != nil {
			slog.Warn("failed to publish to relay", "url", url, "error", err)
			lastErr = err
			continue
		}
		successCount++
		slog.Debug("published to relay", "url", url, "event_id", event.ID)
	}

	if successCount > 0 {
		return nil
	}
	return lastErr
}

// parsePowRequirement extracts the required POW difficulty from a relay error message.
// Returns 0 if not a POW error.
func parsePowRequirement(errStr string) int {
	errLower := strings.ToLower(errStr)

	// Check for POW error indicators
	if !strings.Contains(errLower, "pow") {
		return 0
	}

	// Try to extract specific difficulty
	// Common patterns: "pow: 28 bits needed", "requires 20 bits of proof of work"
	for _, pattern := range []string{"pow: ", "pow:", "requires "} {
		if idx := strings.Index(errLower, pattern); idx >= 0 {
			numStart := idx + len(pattern)
			numEnd := numStart
			for numEnd < len(errLower) && errLower[numEnd] >= '0' && errLower[numEnd] <= '9' {
				numEnd++
			}
			if numEnd > numStart {
				if bits, err := strconv.Atoi(errLower[numStart:numEnd]); err == nil && bits > 0 {
					return bits
				}
			}
		}
	}

	// Generic POW error without specific difficulty - use default
	return 16
}

// PublishToRelay publishes an event to a specific relay, connecting if necessary
func (c *Client) PublishToRelay(ctx context.Context, relayURL string, event *nostr.Event) error {
	// A nostrconnect URI advertises the PUBLIC relay URL, but the signer holds a
	// persistent connection to the INTERNAL URL. Resolve to that so we publish
	// over the live internal connection instead of making a fresh (Tor-routed,
	// slow/failing) dial to the external hostname — the relay's cross-pod pubsub
	// still fans the event out to the external subscriber. Without this, the
	// NIP-46 connect response was never delivered and clients hit a 120s timeout.
	relayURL = c.internalURLFor(relayURL)

	c.mu.RLock()
	relay, exists := c.relays[relayURL]
	c.mu.RUnlock()

	// Only reuse the cached persistent connection if it is still live. A relay
	// pod restart (or any server-side close) leaves a dead *nostr.Relay in the
	// map, and the base client has no auto-reconnect for it (only per-key
	// KeyRelayManager connections reconnect). Reusing the dead connection makes
	// relay.Publish return "connection closed" on every attempt, which silently
	// broke all nostrconnect ack publishes (login) until the signer restarted.
	// When the cached connection is dead we fall through to a fresh temporary
	// dial — the same path an uncached relay takes.
	if exists && !relay.IsConnected() {
		exists = false
	}

	fresh := !exists
	if fresh {
		// Dial a fresh temporary connection (cached one absent or dead).
		var err error
		relay, err = nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			return fmt.Errorf("failed to connect to relay %s: %w", relayURL, err)
		}
		defer relay.Close()
	}

	err := relay.Publish(ctx, *event)

	// Guard the race where a cached connection passed the IsConnected() check
	// but died before/during the write: retry once on a fresh dial. Without this
	// the ack would fail with "connection closed" and the login would time out.
	if err != nil && !fresh && isConnectionClosed(err) {
		slog.Info("cached relay connection closed, redialing", "url", relayURL)
		if redial, derr := nostr.RelayConnect(ctx, relayURL); derr == nil {
			defer redial.Close()
			relay = redial
			fresh = true
			err = relay.Publish(ctx, *event)
		}
	}

	if err != nil {
		// Check if auth is required
		if c.authKey != "" && isAuthRequired(err) {
			slog.Info("auth required for target relay, authenticating", "url", relayURL)
			if authErr := c.authenticateRelay(ctx, relay); authErr != nil {
				slog.Warn("auth failed for target relay", "url", relayURL, "error", authErr)
			} else {
				// Retry publish after auth
				err = relay.Publish(ctx, *event)
			}
		}
	}

	if err != nil {
		return fmt.Errorf("failed to publish to %s: %w", relayURL, err)
	}

	slog.Debug("published to specific relay", "url", relayURL, "event_id", event.ID)
	return nil
}

// isConnectionClosed reports whether an error indicates the relay websocket was
// closed (as opposed to an application-level rejection like auth-required or
// rate-limited). Used to trigger a reconnect-and-retry on a stale connection.
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "use of closed") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset")
}

// isAuthRequired checks if an error indicates authentication is required
func isAuthRequired(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "auth-required") ||
		strings.Contains(errStr, "authentication required")
}

// isRestricted checks if an error indicates the relay restricts publishing to authenticated identity
func isRestricted(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "restricted") ||
		strings.Contains(errStr, "only publish events as your authenticated")
}

// isRateLimited checks if an error indicates rate limiting
// Uses NIP-01 standard prefix detection
func isRateLimited(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	// NIP-01 defines standard prefixes for OK messages
	// go-nostr may prefix with "msg: " so we check for both prefix and contains
	return strings.HasPrefix(errStr, "rate-limited:") ||
		strings.HasPrefix(errStr, "rate-limited") ||
		strings.Contains(errStr, "rate-limited:")
}

// isRetryableError checks if an error should trigger a retry
// This is more permissive than isRateLimited - we retry on any error
// that isn't definitively non-retryable (invalid, duplicate, blocked)
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())

	// NIP-01 non-retryable prefixes
	if strings.HasPrefix(errStr, "invalid:") ||
		strings.HasPrefix(errStr, "duplicate:") ||
		strings.HasPrefix(errStr, "blocked:") {
		return false
	}

	// Everything else is potentially retryable:
	// - rate-limited: (yes, retry with backoff)
	// - pow: (yes, retry with POW)
	// - error: (maybe transient, retry)
	// - anything else (unknown, assume retry might help)
	return true
}

// Subscribe creates a subscription on all connected relays
func (c *Client) Subscribe(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event)) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for url, relay := range c.relays {
		go func(url string, relay *nostr.Relay) {
			sub, err := relay.Subscribe(ctx, filters)
			if err != nil {
				slog.Warn("failed to subscribe to relay", "url", url, "error", err)
				return
			}

			slog.Info("subscribed to relay", "url", url, "filters", filters)

			for ev := range sub.Events {
				handler(ev)
			}
		}(url, relay)
	}
}

// SubscribeWithRelayInfo creates a subscription that includes the source relay URL in callbacks.
// This enables responding only to the relay the request came from.
func (c *Client) SubscribeWithRelayInfo(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event, string)) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for url, relay := range c.relays {
		go func(url string, relay *nostr.Relay) {
			sub, err := relay.Subscribe(ctx, filters)
			if err != nil {
				slog.Warn("failed to subscribe to relay", "url", url, "error", err)
				// Remove from map so reconnect logic can kick in
				c.mu.Lock()
				delete(c.relays, url)
				metrics.SetRelayConnections(len(c.relays))
				c.mu.Unlock()
				return
			}

			slog.Info("subscribed to relay", "url", url, "filters", filters)

			for ev := range sub.Events {
				handler(ev, url)
			}

			// Subscription channel closed - connection dropped
			// Remove from map so reconnect logic kicks in
			slog.Warn("relay subscription closed, will reconnect", "url", url)
			c.mu.Lock()
			delete(c.relays, url)
			metrics.SetRelayConnections(len(c.relays))
			c.mu.Unlock()
		}(url, relay)
	}
}

// SubscribeWithRelayInfoReconnect maintains a subscription with relay info and automatic reconnection
func (c *Client) SubscribeWithRelayInfoReconnect(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event, string)) {
	// Store subscription state for reconnection
	c.subMu.Lock()
	// We wrap the handler to convert to the old format for storage
	wrappedHandler := func(ev *nostr.Event) {
		// This won't be called directly - reconnect uses SubscribeWithRelayInfo
	}
	c.subscriptions = append(c.subscriptions, subscription{filters: filters, handler: wrappedHandler})
	subIndex := len(c.subscriptions) - 1
	c.subMu.Unlock()

	// Subscribe with relay info
	c.SubscribeWithRelayInfo(ctx, filters, handler)

	// Only the first subscription starts the reconnect ticker
	if subIndex == 0 {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					c.reconnectWithRelayInfoIfNeeded(ctx, filters, handler)
				}
			}
		}()
	}

	// Block until context is done
	<-ctx.Done()
}

func (c *Client) reconnectWithRelayInfoIfNeeded(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event, string)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, url := range c.relayURLs {
		if _, exists := c.relays[url]; !exists {
			relay, err := nostr.RelayConnect(ctx, url)
			if err != nil {
				slog.Debug("reconnect failed", "url", url, "error", err)
				continue
			}
			c.relays[url] = relay
			metrics.SetRelayConnections(len(c.relays))
			slog.Info("reconnected to relay", "url", url)
			// Don't proactively auth - wait for relay challenge or auth-required errors

			// Re-establish subscription with relay info
			go func(url string, relay *nostr.Relay) {
				sub, err := relay.Subscribe(ctx, filters)
				if err != nil {
					slog.Warn("failed to subscribe on reconnected relay", "url", url, "error", err)
					// Remove from map so next reconnect cycle tries again
					c.mu.Lock()
					delete(c.relays, url)
					metrics.SetRelayConnections(len(c.relays))
					c.mu.Unlock()
					return
				}
				slog.Info("subscribed on reconnected relay", "url", url, "filters", filters)
				for ev := range sub.Events {
					handler(ev, url)
				}
				// Subscription channel closed - connection dropped
				slog.Warn("reconnected relay subscription closed, will reconnect", "url", url)
				c.mu.Lock()
				delete(c.relays, url)
				metrics.SetRelayConnections(len(c.relays))
				c.mu.Unlock()
			}(url, relay)
		}
	}
}

// SubscribeWithReconnect maintains a subscription with automatic reconnection
func (c *Client) SubscribeWithReconnect(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event)) {
	// Store subscription state for reconnection (append, don't overwrite)
	c.subMu.Lock()
	c.subscriptions = append(c.subscriptions, subscription{filters: filters, handler: handler})
	subIndex := len(c.subscriptions) - 1
	c.subMu.Unlock()

	// Subscribe to currently connected relays
	c.Subscribe(ctx, filters, handler)

	// Only the first subscription starts the reconnect ticker
	if subIndex == 0 {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					c.reconnectIfNeeded(ctx)
				}
			}
		}()
	}

	// Block until context is done
	<-ctx.Done()
}

func (c *Client) reconnectIfNeeded(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get current subscriptions
	c.subMu.RLock()
	subs := make([]subscription, len(c.subscriptions))
	copy(subs, c.subscriptions)
	c.subMu.RUnlock()

	for _, url := range c.relayURLs {
		if _, exists := c.relays[url]; !exists {
			relay, err := nostr.RelayConnect(ctx, url)
			if err != nil {
				slog.Debug("reconnect failed", "url", url, "error", err)
				continue
			}
			c.relays[url] = relay
			metrics.SetRelayConnections(len(c.relays))
			slog.Info("reconnected to relay", "url", url)

			// Re-establish ALL subscriptions on the reconnected relay
			for _, sub := range subs {
				go func(url string, relay *nostr.Relay, filters nostr.Filters, handler func(*nostr.Event)) {
					subscription, err := relay.Subscribe(ctx, filters)
					if err != nil {
						slog.Warn("failed to subscribe on reconnected relay", "url", url, "error", err)
						return
					}
					slog.Info("subscribed on reconnected relay", "url", url, "filters", filters)
					for ev := range subscription.Events {
						handler(ev)
					}
				}(url, relay, sub.filters, sub.handler)
			}
		}
	}
}

// GetConnectedRelays returns the list of currently connected relay URLs
func (c *Client) GetConnectedRelays() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	urls := make([]string, 0, len(c.relays))
	for url := range c.relays {
		urls = append(urls, url)
	}
	return urls
}
