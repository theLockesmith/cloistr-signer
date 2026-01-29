package nostr

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Client manages connections to Nostr relays
type Client struct {
	relayURLs []string
	relays    map[string]*nostr.Relay
	authKey   string // Private key for NIP-42 auth (hex)
	mu        sync.RWMutex
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
		slog.Info("connected to relay", "url", url)

		// Try to authenticate if we have an auth key
		if c.authKey != "" {
			if err := c.authenticateRelay(ctx, relay); err != nil {
				slog.Warn("initial auth failed", "url", url, "error", err)
				// Continue anyway - auth might not be required for reading
			}
		}
	}

	if len(c.relays) == 0 {
		slog.Warn("no relays connected")
	}

	return nil
}

// authenticateRelay performs NIP-42 authentication with a relay
func (c *Client) authenticateRelay(ctx context.Context, relay *nostr.Relay) error {
	err := relay.Auth(ctx, func(event *nostr.Event) error {
		pubkey, err := nostr.GetPublicKey(c.authKey)
		if err != nil {
			return err
		}
		event.PubKey = pubkey
		return event.Sign(c.authKey)
	})
	if err != nil {
		return err
	}
	slog.Info("authenticated with relay", "url", relay.URL)
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

// PublishToRelay publishes an event to a specific relay, connecting if necessary
func (c *Client) PublishToRelay(ctx context.Context, relayURL string, event *nostr.Event) error {
	c.mu.RLock()
	relay, exists := c.relays[relayURL]
	c.mu.RUnlock()

	if !exists {
		// Try to connect to the relay temporarily
		var err error
		relay, err = nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			return fmt.Errorf("failed to connect to relay %s: %w", relayURL, err)
		}
		defer relay.Close()
	}

	err := relay.Publish(ctx, *event)
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

// isAuthRequired checks if an error indicates authentication is required
func isAuthRequired(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "auth-required") ||
		strings.Contains(errStr, "authentication required")
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

// SubscribeWithReconnect maintains a subscription with automatic reconnection
func (c *Client) SubscribeWithReconnect(ctx context.Context, filters nostr.Filters, handler func(*nostr.Event)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c.Subscribe(ctx, filters, handler)

			// Check connections periodically and reconnect if needed
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
		}
	}
}

func (c *Client) reconnectIfNeeded(ctx context.Context) {
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
			slog.Info("reconnected to relay", "url", url)
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
