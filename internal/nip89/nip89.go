package nip89

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

const (
	// KindAppHandler is the event kind for application handler announcements (NIP-89)
	KindAppHandler = 31990

	// KindAppRecommendation is the event kind for app recommendations
	KindAppRecommendation = 31989
)

// AppHandlerInfo contains information about the signer service
type AppHandlerInfo struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name,omitempty"`
	Description string   `json:"about,omitempty"`
	Picture     string   `json:"picture,omitempty"`
	Website     string   `json:"website,omitempty"`
	Nip05       string   `json:"nip05,omitempty"`
	LUD16       string   `json:"lud16,omitempty"`
	Kinds       []int    `json:"kinds,omitempty"` // Kinds this handler supports
}

// Publisher publishes NIP-89 service announcements
type Publisher struct {
	relays     []string
	signerKey  string // Private key for signing
	signerPub  string // Public key
}

// NewPublisher creates a new NIP-89 publisher
func NewPublisher(relays []string) *Publisher {
	return &Publisher{
		relays: relays,
	}
}

// SetSignerKey sets the key to use for signing announcements
func (p *Publisher) SetSignerKey(pubkey, privateKey string) {
	p.signerPub = pubkey
	p.signerKey = privateKey
}

// CreateHandlerEvent creates a kind:31990 event for the signer service
func (p *Publisher) CreateHandlerEvent(info *AppHandlerInfo) (*nostr.Event, error) {
	if p.signerKey == "" {
		return nil, fmt.Errorf("no signer key set")
	}

	// Create content JSON
	content, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal info: %w", err)
	}

	// Build tags
	tags := nostr.Tags{
		// d tag for replaceable event identifier
		{"d", "coldforge-signer"},
		// k tags for supported kinds (NIP-46)
		{"k", "24133"},
	}

	// Add relay hints
	for _, relay := range p.relays {
		tags = append(tags, nostr.Tag{"relay", relay})
	}

	// Add web URL if available
	if info.Website != "" {
		tags = append(tags, nostr.Tag{"web", info.Website})
	}

	event := &nostr.Event{
		Kind:      KindAppHandler,
		PubKey:    p.signerPub,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      tags,
		Content:   string(content),
	}

	if err := event.Sign(p.signerKey); err != nil {
		return nil, fmt.Errorf("failed to sign event: %w", err)
	}

	return event, nil
}

// PublishHandler publishes the handler announcement to all relays
func (p *Publisher) PublishHandler(ctx context.Context, info *AppHandlerInfo) error {
	event, err := p.CreateHandlerEvent(info)
	if err != nil {
		return err
	}

	// Publish to each relay
	for _, relayURL := range p.relays {
		go func(url string) {
			relay, err := nostr.RelayConnect(ctx, url)
			if err != nil {
				slog.Warn("failed to connect to relay for NIP-89", "relay", url, "error", err)
				return
			}
			defer relay.Close()

			if err := relay.Publish(ctx, *event); err != nil {
				slog.Warn("failed to publish NIP-89 event", "relay", url, "error", err)
				return
			}

			slog.Info("published NIP-89 handler announcement", "relay", url, "event_id", event.ID[:16]+"...")
		}(relayURL)
	}

	return nil
}

// DefaultHandlerInfo returns default info for coldforge-signer
func DefaultHandlerInfo(website string) *AppHandlerInfo {
	return &AppHandlerInfo{
		Name:        "coldforge-signer",
		DisplayName: "Coldforge Signer",
		Description: "NIP-46 Remote Signing Service - Securely sign Nostr events without exposing your private keys",
		Website:     website,
		Kinds:       []int{24133}, // NIP-46 request/response kind
	}
}
