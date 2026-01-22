package nostr

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Client manages connections to Nostr relays
type Client struct {
	relayURLs []string
	relays    map[string]*nostr.Relay
	mu        sync.RWMutex
}

// NewClient creates a new relay client
func NewClient(relayURLs []string) *Client {
	return &Client{
		relayURLs: relayURLs,
		relays:    make(map[string]*nostr.Relay),
	}
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
	}

	if len(c.relays) == 0 {
		slog.Warn("no relays connected")
	}

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
		if err := relay.Publish(ctx, *event); err != nil {
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
