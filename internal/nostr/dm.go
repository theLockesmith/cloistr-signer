// Package nostr provides Nostr relay client functionality including DM support.
package nostr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

	c.SubscribeWithRelayInfoReconnect(ctx, filters, func(event *nostr.Event, relayURL string) {
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
	})

	return nil
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
