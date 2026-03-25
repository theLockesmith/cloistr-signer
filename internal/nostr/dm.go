// Package nostr provides Nostr relay client functionality including DM support.
package nostr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
)

// DMMessage represents a structured direct message
type DMMessage struct {
	Type    string          `json:"type"`    // Message type (e.g., "dkg_commit", "dkg_share")
	Payload json.RawMessage `json:"payload"` // Type-specific payload
}

// SendDM sends an encrypted direct message to a recipient
// Uses NIP-04 encryption (deprecated but widely supported)
func (c *Client) SendDM(ctx context.Context, privateKey, recipientPubkey string, message *DMMessage) error {
	// Serialize the message
	content, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal DM: %w", err)
	}

	// Encrypt using NIP-04
	shared, err := nip04.ComputeSharedSecret(recipientPubkey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encrypted, err := nip04.Encrypt(string(content), shared)
	if err != nil {
		return fmt.Errorf("failed to encrypt DM: %w", err)
	}

	// Get our pubkey
	senderPubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to get sender pubkey: %w", err)
	}

	// Create NIP-04 DM event (kind 4)
	event := &nostr.Event{
		Kind:      nostr.KindEncryptedDirectMessage,
		PubKey:    senderPubkey,
		Content:   encrypted,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"p", recipientPubkey},
		},
	}

	if err := event.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign DM event: %w", err)
	}

	// Publish to all connected relays with adaptive POW
	return c.PublishWithAdaptivePow(ctx, event, privateKey)
}

// SendEphemeralDM sends an ephemeral direct message (kind 24133 for NIP-46 style communication)
// Used for FROST DKG coordination where messages don't need to be stored
func (c *Client) SendEphemeralDM(ctx context.Context, privateKey, recipientPubkey string, message *DMMessage) error {
	// Serialize the message
	content, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal DM: %w", err)
	}

	// Encrypt using NIP-04
	shared, err := nip04.ComputeSharedSecret(recipientPubkey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encrypted, err := nip04.Encrypt(string(content), shared)
	if err != nil {
		return fmt.Errorf("failed to encrypt DM: %w", err)
	}

	// Get our pubkey
	senderPubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to get sender pubkey: %w", err)
	}

	// Create ephemeral DM event (kind 24133 - NIP-46 style)
	event := &nostr.Event{
		Kind:      24133,
		PubKey:    senderPubkey,
		Content:   encrypted,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"p", recipientPubkey},
		},
	}

	if err := event.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign ephemeral DM event: %w", err)
	}

	// Publish to all connected relays with adaptive POW
	return c.PublishWithAdaptivePow(ctx, event, privateKey)
}

// DMHandler is called when a DM is received
type DMHandler func(senderPubkey string, message *DMMessage)

// SubscribeDMs subscribes to direct messages for a specific pubkey
// Uses NIP-42 authentication when required by the relay
func (c *Client) SubscribeDMs(ctx context.Context, privateKey string, handler DMHandler) error {
	pubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to get pubkey: %w", err)
	}

	// Set since to now to avoid processing old messages
	now := nostr.Timestamp(time.Now().Unix())

	filters := nostr.Filters{
		{
			Kinds: []int{nostr.KindEncryptedDirectMessage, 24133}, // Both NIP-04 DMs and ephemeral
			Tags:  nostr.TagMap{"p": []string{pubkey}},
			Since: &now,
		},
	}

	// Event handler for DMs
	eventHandler := func(event *nostr.Event, relayURL string) {
		// Skip our own messages
		if event.PubKey == pubkey {
			return
		}

		// Decrypt the message
		shared, err := nip04.ComputeSharedSecret(event.PubKey, privateKey)
		if err != nil {
			slog.Warn("failed to compute shared secret for DM", "from", event.PubKey, "error", err)
			return
		}

		decrypted, err := nip04.Decrypt(event.Content, shared)
		if err != nil {
			slog.Warn("failed to decrypt DM", "from", event.PubKey, "error", err)
			return
		}

		// Parse the message
		var msg DMMessage
		if err := json.Unmarshal([]byte(decrypted), &msg); err != nil {
			slog.Debug("received non-structured DM", "from", event.PubKey)
			// Not a structured message, ignore
			return
		}

		slog.Debug("received DM", "type", msg.Type, "from", event.PubKey, "relay", relayURL)
		handler(event.PubKey, &msg)
	}

	// Subscribe to each relay with NIP-42 auth support
	c.subscribeDMsWithAuth(ctx, privateKey, filters, eventHandler)

	return nil
}

// subscribeDMsWithAuth subscribes with NIP-42 authentication support
func (c *Client) subscribeDMsWithAuth(ctx context.Context, privateKey string, filters nostr.Filters, handler func(*nostr.Event, string)) {
	c.mu.Lock()
	relays := make(map[string]*nostr.Relay, len(c.relays))
	for url, relay := range c.relays {
		relays[url] = relay
	}
	c.mu.Unlock()

	for url, relay := range relays {
		go c.subscribeDMToRelayWithAuth(ctx, privateKey, url, relay, filters, handler)
	}

	// Reconnection loop
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.reconnectDMsWithAuth(ctx, privateKey, filters, handler)
			}
		}
	}()

	// Block until context is done
	<-ctx.Done()
}

// subscribeDMToRelayWithAuth subscribes to a single relay with NIP-42 auth
func (c *Client) subscribeDMToRelayWithAuth(ctx context.Context, privateKey, url string, relay *nostr.Relay, filters nostr.Filters, handler func(*nostr.Event, string)) {
	sub, err := relay.Subscribe(ctx, filters)
	if err != nil {
		slog.Warn("DM subscription failed", "url", url, "error", err)
		return
	}
	slog.Info("DM subscription started", "url", url)

	for {
		select {
		case <-ctx.Done():
			return
		case reason, ok := <-sub.ClosedReason:
			if !ok {
				slog.Warn("DM subscription closed", "url", url)
				return
			}
			// Check if auth is required
			if isAuthRequiredReason(reason) {
				slog.Info("DM subscription requires auth, authenticating", "url", url, "reason", reason)
				if authErr := c.authenticateRelayWithKey(ctx, relay, privateKey); authErr != nil {
					slog.Warn("DM auth failed", "url", url, "error", authErr)
					return
				}
				slog.Info("DM auth successful, resubscribing", "url", url)
				// Resubscribe after auth
				sub, err = relay.Subscribe(ctx, filters)
				if err != nil {
					slog.Warn("DM resubscription failed", "url", url, "error", err)
					return
				}
				slog.Info("DM resubscription successful", "url", url)
			} else {
				slog.Warn("DM subscription closed", "url", url, "reason", reason)
				return
			}
		case ev, ok := <-sub.Events:
			if !ok {
				slog.Warn("DM subscription events closed", "url", url)
				return
			}
			handler(ev, url)
		}
	}
}

// reconnectDMsWithAuth reconnects disconnected relays for DM subscriptions
func (c *Client) reconnectDMsWithAuth(ctx context.Context, privateKey string, filters nostr.Filters, handler func(*nostr.Event, string)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, url := range c.relayURLs {
		if _, exists := c.relays[url]; !exists {
			relay, err := nostr.RelayConnect(ctx, url)
			if err != nil {
				slog.Debug("DM reconnect failed", "url", url, "error", err)
				continue
			}
			c.relays[url] = relay
			slog.Info("DM reconnected to relay", "url", url)
			go c.subscribeDMToRelayWithAuth(ctx, privateKey, url, relay, filters, handler)
		}
	}
}

// isAuthRequiredReason checks if the subscription close reason indicates auth is needed
func isAuthRequiredReason(reason string) bool {
	reasonLower := strings.ToLower(reason)
	return strings.Contains(reasonLower, "auth-required") ||
		strings.Contains(reasonLower, "restricted") ||
		strings.Contains(reasonLower, "authentication")
}

// QueryDMs queries for DMs within a time range
func (c *Client) QueryDMs(ctx context.Context, privateKey string, since, until time.Time) ([]*DMMessage, []string, error) {
	pubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get pubkey: %w", err)
	}

	sinceTs := nostr.Timestamp(since.Unix())
	untilTs := nostr.Timestamp(until.Unix())

	filters := nostr.Filters{
		{
			Kinds: []int{nostr.KindEncryptedDirectMessage, 24133},
			Tags:  nostr.TagMap{"p": []string{pubkey}},
			Since: &sinceTs,
			Until: &untilTs,
		},
	}

	var messages []*DMMessage
	var senders []string

	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, relay := range c.relays {
		events, err := relay.QuerySync(ctx, nostr.Filter(filters[0]))
		if err != nil {
			slog.Warn("failed to query relay for DMs", "url", relay.URL, "error", err)
			continue
		}

		for _, event := range events {
			if event.PubKey == pubkey {
				continue // Skip our own messages
			}

			shared, err := nip04.ComputeSharedSecret(event.PubKey, privateKey)
			if err != nil {
				continue
			}

			decrypted, err := nip04.Decrypt(event.Content, shared)
			if err != nil {
				continue
			}

			var msg DMMessage
			if err := json.Unmarshal([]byte(decrypted), &msg); err != nil {
				continue
			}

			messages = append(messages, &msg)
			senders = append(senders, event.PubKey)
		}
	}

	return messages, senders, nil
}
