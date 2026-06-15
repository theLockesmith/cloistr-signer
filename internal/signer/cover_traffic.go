package signer

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// CoverTrafficEmitter periodically publishes ephemeral NIP-17-shaped gift-wrap
// decoys to relays of keys with CoverTraffic enabled. Implements the paid-tier
// behavior described in privacy-architecture §3.11: constant-rate dummy events
// that make on/off-line presence indistinguishable from background.
//
// Decoys use ephemeral one-time keys (NIP-17 convention: the outer kind:1059
// wrapper is always signed by a fresh pubkey), so the user's signing key is
// not involved. The recipient p-tag is also a random pubkey; the payload is
// NIP-44 ciphertext encrypting random bytes. To a relay observer the event is
// indistinguishable from a real NIP-17 gift-wrap.
type CoverTrafficEmitter struct {
	storage     storage.Storage
	relayClient RelayPublisher
	minInterval time.Duration
	jitter      time.Duration
}

// RelayPublisher is the subset of relay-client behavior CoverTrafficEmitter
// depends on. Satisfied by *nostr.Client.
type RelayPublisher interface {
	PublishToRelay(ctx context.Context, relayURL string, event *nostr.Event) error
}

// NewCoverTrafficEmitter wires up an emitter with default cadence (15-30 min
// between cycles, jittered).
func NewCoverTrafficEmitter(store storage.Storage, relayClient RelayPublisher) *CoverTrafficEmitter {
	return &CoverTrafficEmitter{
		storage:     store,
		relayClient: relayClient,
		minInterval: 15 * time.Minute,
		jitter:      15 * time.Minute,
	}
}

// Run blocks until ctx is cancelled. Each cycle picks a random next-interval
// in [minInterval, minInterval+jitter), then iterates cover-traffic-enabled
// keys and publishes one decoy each to one of that key's relays.
func (e *CoverTrafficEmitter) Run(ctx context.Context) {
	slog.Info("cover-traffic emitter started",
		"min_interval", e.minInterval,
		"jitter", e.jitter,
	)
	for {
		wait := e.nextInterval()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := e.emitOnce(ctx); err != nil {
			slog.Warn("cover-traffic cycle failed", "error", err)
		}
	}
}

func (e *CoverTrafficEmitter) nextInterval() time.Duration {
	if e.jitter <= 0 {
		return e.minInterval
	}
	extra := time.Duration(randUint32() % uint32(e.jitter.Nanoseconds()))
	return e.minInterval + extra
}

// emitOnce enumerates keys with CoverTraffic enabled and publishes one decoy
// per key to a randomly chosen relay from that key's relay set. Errors from
// individual publishes are logged at debug level; we don't want a flaky relay
// to spam warn-level noise.
func (e *CoverTrafficEmitter) emitOnce(ctx context.Context) error {
	keys, err := e.storage.ListAllKeys(ctx)
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	emitted := 0
	for _, key := range keys {
		if !key.CoverTraffic {
			continue
		}
		if len(key.Relays) == 0 {
			// No relays configured for this key; nothing to publish to.
			continue
		}

		decoy, err := buildDecoyEvent()
		if err != nil {
			slog.Warn("cover-traffic: build decoy failed",
				"error", err,
				"key_id", key.ID,
			)
			continue
		}

		// Pick one random relay rather than fanning out to all. Spreading
		// decoys per-cycle keeps the traffic pattern less obviously a
		// "signer beacon" event burst.
		relayURL := key.Relays[randIntn(len(key.Relays))]
		pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := e.relayClient.PublishToRelay(pubCtx, relayURL, decoy); err != nil {
			slog.Debug("cover-traffic publish failed",
				"relay", relayURL,
				"key_id", key.ID,
				"error", err,
			)
		} else {
			emitted++
		}
		cancel()
	}
	if emitted > 0 {
		slog.Debug("cover-traffic cycle complete", "decoys_emitted", emitted)
	}
	return nil
}

// buildDecoyEvent constructs a kind:1059 (NIP-17 gift-wrap) event signed by a
// one-time ephemeral pubkey, with a random recipient and NIP-44 ciphertext
// payload. The event is structurally indistinguishable from a real NIP-17
// gift-wrap, but nobody can decrypt the payload (the recipient's nsec is
// thrown away immediately).
func buildDecoyEvent() (*nostr.Event, error) {
	ephPriv := nostr.GeneratePrivateKey()
	ephPub, err := nostr.GetPublicKey(ephPriv)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral pubkey: %w", err)
	}
	recipientPriv := nostr.GeneratePrivateKey()
	recipientPub, err := nostr.GetPublicKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("derive recipient pubkey: %w", err)
	}

	var payload [256]byte
	if _, err := cryptorand.Read(payload[:]); err != nil {
		return nil, fmt.Errorf("read payload entropy: %w", err)
	}

	convKey, err := nip44.GenerateConversationKey(recipientPub, ephPriv)
	if err != nil {
		return nil, fmt.Errorf("nip44 conversation key: %w", err)
	}
	ciphertext, err := nip44.Encrypt(hex.EncodeToString(payload[:]), convKey)
	if err != nil {
		return nil, fmt.Errorf("nip44 encrypt: %w", err)
	}

	// NIP-17 convention: outer gift-wrap CreatedAt is randomized into the
	// recent past (up to ~2 days back) so the timestamp doesn't immediately
	// reveal when the message was actually constructed.
	pastOffset := time.Duration(randIntn(2*24*60*60)) * time.Second
	createdAt := nostr.Timestamp(time.Now().Add(-pastOffset).Unix())

	ev := &nostr.Event{
		Kind:      1059,
		PubKey:    ephPub,
		Content:   ciphertext,
		CreatedAt: createdAt,
		Tags:      nostr.Tags{{"p", recipientPub}},
	}
	if err := ev.Sign(ephPriv); err != nil {
		return nil, fmt.Errorf("sign decoy: %w", err)
	}
	return ev, nil
}

// randUint32 returns a uniformly random uint32 via crypto/rand. Falls back to
// 0 on read failure (degrades to zero jitter, never panics).
func randUint32() uint32 {
	var b [4]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint32(b[:])
}

// randIntn returns a uniformly random int in [0, n). Returns 0 if n <= 0.
func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(randUint32() % uint32(n))
}
