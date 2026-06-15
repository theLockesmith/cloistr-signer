package signer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// fakeRelayPublisher records every Publish call so tests can assert behavior
// without standing up a real WebSocket relay.
type fakeRelayPublisher struct {
	mu       sync.Mutex
	events   []*nostr.Event
	relays   []string
	failNext bool
}

func (f *fakeRelayPublisher) PublishToRelay(ctx context.Context, relayURL string, event *nostr.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return context.Canceled
	}
	f.events = append(f.events, event)
	f.relays = append(f.relays, relayURL)
	return nil
}

func (f *fakeRelayPublisher) calls() ([]*nostr.Event, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	evs := append([]*nostr.Event(nil), f.events...)
	rs := append([]string(nil), f.relays...)
	return evs, rs
}

func TestBuildDecoyEvent_Shape(t *testing.T) {
	ev, err := buildDecoyEvent()
	if err != nil {
		t.Fatalf("buildDecoyEvent() error = %v", err)
	}
	if ev.Kind != 1059 {
		t.Errorf("decoy kind = %d, want 1059 (NIP-17 gift-wrap)", ev.Kind)
	}
	if ev.PubKey == "" {
		t.Errorf("decoy pubkey is empty")
	}
	if ev.Sig == "" {
		t.Errorf("decoy is not signed")
	}
	if ev.Content == "" {
		t.Errorf("decoy content is empty")
	}
	if ok, err := ev.CheckSignature(); !ok || err != nil {
		t.Errorf("decoy signature does not verify: ok=%v err=%v", ok, err)
	}
	hasP := false
	for _, tag := range ev.Tags {
		if len(tag) > 0 && tag[0] == "p" {
			hasP = true
			break
		}
	}
	if !hasP {
		t.Errorf("decoy missing p-tag (NIP-17 wrap requires recipient pointer)")
	}
}

func TestBuildDecoyEvent_EachUnique(t *testing.T) {
	// Each emission must use a fresh ephemeral key + fresh randomness, so
	// two decoys built back-to-back must have distinct pubkeys, recipients,
	// and content. Otherwise an observer can fingerprint cover traffic.
	a, err := buildDecoyEvent()
	if err != nil {
		t.Fatalf("buildDecoyEvent() error = %v", err)
	}
	b, err := buildDecoyEvent()
	if err != nil {
		t.Fatalf("buildDecoyEvent() error = %v", err)
	}
	if a.PubKey == b.PubKey {
		t.Errorf("ephemeral pubkey reused across decoys: %s", a.PubKey)
	}
	if a.Content == b.Content {
		t.Errorf("decoy content identical across decoys")
	}
	if a.ID == b.ID {
		t.Errorf("decoy event ID identical across decoys")
	}
}

func TestCoverTrafficEmitter_EmitOnlyEnabledKeys(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()

	if err := store.CreateKey(ctx, &storage.Key{
		ID:           "key-enabled",
		Pubkey:       "1111111111111111111111111111111111111111111111111111111111111111",
		KeyType:      storage.KeyTypeLocal,
		CoverTraffic: true,
		Relays:       []string{"wss://relay.test/one"},
	}); err != nil {
		t.Fatalf("CreateKey enabled: %v", err)
	}
	if err := store.CreateKey(ctx, &storage.Key{
		ID:           "key-disabled",
		Pubkey:       "2222222222222222222222222222222222222222222222222222222222222222",
		KeyType:      storage.KeyTypeLocal,
		CoverTraffic: false,
		Relays:       []string{"wss://relay.test/two"},
	}); err != nil {
		t.Fatalf("CreateKey disabled: %v", err)
	}
	if err := store.CreateKey(ctx, &storage.Key{
		ID:           "key-enabled-no-relays",
		Pubkey:       "3333333333333333333333333333333333333333333333333333333333333333",
		KeyType:      storage.KeyTypeLocal,
		CoverTraffic: true,
		// No Relays - should be skipped because there's nowhere to publish.
	}); err != nil {
		t.Fatalf("CreateKey no-relays: %v", err)
	}

	pub := &fakeRelayPublisher{}
	em := NewCoverTrafficEmitter(store, pub)

	if err := em.emitOnce(ctx); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}

	events, relays := pub.calls()
	if len(events) != 1 {
		t.Fatalf("expected 1 decoy emitted (only key-enabled qualifies), got %d", len(events))
	}
	if relays[0] != "wss://relay.test/one" {
		t.Errorf("decoy went to wrong relay: %s", relays[0])
	}
	if events[0].Kind != 1059 {
		t.Errorf("emitted event kind = %d, want 1059", events[0].Kind)
	}
}

func TestCoverTrafficEmitter_PublishErrorIsTolerated(t *testing.T) {
	// A flaky relay should not stop the emitter from continuing to other
	// keys in the same cycle.
	store := storage.NewMemoryStorage()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		pubkey := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		pubkey[0] = byte('a' + i)
		if err := store.CreateKey(ctx, &storage.Key{
			ID:           "k" + string(rune('1'+i)),
			Pubkey:       string(pubkey),
			KeyType:      storage.KeyTypeLocal,
			CoverTraffic: true,
			Relays:       []string{"wss://relay.test/" + string(rune('a'+i))},
		}); err != nil {
			t.Fatalf("CreateKey %d: %v", i, err)
		}
	}

	pub := &fakeRelayPublisher{failNext: true}
	em := NewCoverTrafficEmitter(store, pub)

	if err := em.emitOnce(ctx); err != nil {
		t.Fatalf("emitOnce should not propagate per-publish errors, got %v", err)
	}
	events, _ := pub.calls()
	if len(events) != 2 {
		t.Errorf("expected 2 successful publishes (1 failure + 2 successes), got %d", len(events))
	}
}

func TestCoverTrafficEmitter_NextIntervalInRange(t *testing.T) {
	em := &CoverTrafficEmitter{
		minInterval: 10 * time.Minute,
		jitter:      5 * time.Minute,
	}
	for i := 0; i < 32; i++ {
		d := em.nextInterval()
		if d < 10*time.Minute || d >= 15*time.Minute {
			t.Errorf("nextInterval() = %v, want in [10m, 15m)", d)
		}
	}
}
